//Copyright (C) 2013 Potix Corporation. All Rights Reserved.
//History: Mon, Apr 22, 2013  6:22:24 PM
// Author: tomyeh

part of rikulo_security;

///Session attribute for storing the current user
const String _attrUser = "stream.user";

typedef FutureOr _LoginCallback<User>(HttpConnect connect, User user, bool? rememberMe);
typedef FutureOr _LogoutCallback<User>(HttpConnect connect, User user);

/** The implementation of the security module.
 */
class _Security<User> implements Security<User> {
  _LoginCallback<User>? _onLogin;
  _LogoutCallback<User>? _onLogout;

  _Security(this.authenticator, this.accessControl, this.redirector,
      this.rememberMe, this.rememberUri, this._onLogin, this._onLogout);

  @override
  Future filter(HttpConnect connect, Future chain(HttpConnect conn)) async {
    User? user = currentUser(connect.request.session);
    if (user != null) {
      if (await authenticator.isSessionExpired(connect, user)) {
        final session = connect.request.session;
        _setCurrentUser(session, user = null);
        session.destroy();
      }
    } else {
      final reme = rememberMe;
      if (reme != null) { //1. remember me
        user = await reme.recall(connect);
        if (user != null)
          await setLogin(connect, user);
      }
    }

    //2-3: authorize and chain
    return _authorize(connect, user, chain);
  }

  @override
  Future login(HttpConnect connect, {String? username, String? password,
      bool? rememberMe, bool redirect = true,
      bool handleAuthenticationException = true}) async {
    String? uri;
    Map<String, String> params;
    redirect = redirect != false; //including null

    try {
      //1. logout first
      await logout(connect, redirect: false);

      if (username == null) {
        //2. get login information
        //FORM-based login  (note: we ignore query parameters)
        params = await HttpUtil.decodePostedParameters(connect.request,
            maxLength: 3000); //avoid DoS
        username = params["s_username"];
        if (username == null)
          username = "";
        password = params["s_password"];
        if (rememberMe == null)
          rememberMe = params["s_rememberMe"] == "true";
      } else {
        rememberMe = rememberMe == true; //excluding null
        params = HashMap<String, String>();
      }

      //3. retrieve the URI for redirecting
      //we have to do it before login since login will re-create a session
      if (redirect)
        uri = rememberUri.recall(connect, params);

      //4. login
      final user = await authenticator.login(connect, username, password ?? "");

      //5 session/cookie handling
      await setLogin(connect, user, rememberMe: rememberMe);

      //6. redirect
      if (redirect)
        connect.redirect(redirector.getLoginTarget(connect, uri));

    } on AuthenticationException catch (_) {
      if (handleAuthenticationException && redirect) {
        uri = redirector.getLoginFailed(connect, username ?? "", rememberMe ?? false);
        return redirector.isRedirectOnFail ?
          connect.redirect(uri): connect.forward(uri);
      }
      rethrow;
    }
  }

  @override
  Future logout(HttpConnect connect, {bool redirect = true}) async {
    final req = connect.request;
    var user = currentUser<User>(req.session);
    if (user == null) {
      if (redirect)
        connect.redirect(redirector.getLogoutTarget(connect));
      return;
    }

    final data = await authenticator.logout(connect, user),
      session = req.session..clear();
      //SPEC: we don't destroy session when logout
    if (data != null) {
      data.forEach((key, value) {
        session[key] = value;
      });
      _setCurrentUser(session, null); //be safe in case data contains it
    }

    await _onLogout?.call(connect, user);

    if (redirect)
      connect.redirect(redirector.getLogoutTarget(connect));
  }

  //called by _filter to authorize and chain
  Future _authorize(HttpConnect connect, User? user, Future chain(HttpConnect conn)) async {
    //1. check accessibility
    if (!await accessControl.canAccess(connect, user)) {
      if (user == null) {
        rememberUri.save(connect);
        connect.redirect(redirector.getLogin(connect));
        return null; //redirect for login
      }
      throw Http404.fromConnect(connect); //404 (not 403) to minimize attack
    }

    //2. granted and chain
    return chain(connect);
  }

  @override
  Future setLogin(HttpConnect connect, User user, {bool? rememberMe,
      bool resetSession = true, bool onLogin = true}) async {
    //5. session fixation attack protection
    final req = connect.request;
    var session = req.session;
    if (resetSession) {
      final backup = HashMap<String, dynamic>.from(
          session..remove(_attrRememberUri));
      session.destroy();
      session = req.session; //re-create
      session.addAll(backup);
    }

    //5a. store the user
    _setCurrentUser(session, user);

    //6. remember me
    final reme = this.rememberMe;
    if (reme != null && rememberMe != null) //null => ignored
      await reme.save(connect, user, rememberMe);

    if (onLogin)
      return _onLogin?.call(connect, user, rememberMe);
  }

  @override
  Future<Map<String, dynamic>> switchLogin(HttpConnect connect, User user,
      {bool onLogin = true, bool? resetSession}) async {
    final req = connect.request;
    var session = req.session;
    final backup = HashMap<String, dynamic>.from(session);
    if (resetSession ?? !session.isNew) {
      session.destroy();
      session = req.session;
    } else {
      session.clear();
    }

    _setCurrentUser(session, user);

    if (onLogin)
      await _onLogin?.call(connect, user, null);
    return backup;
  }
  @override
  void switchBack(HttpConnect connect, Map<String, dynamic> data) {
    final session = connect.request.session;
    session..clear()..addAll(data);
  }

  @override
  final Authenticator<User> authenticator;
  @override
  final AccessControl<User> accessControl;
  @override
  final Redirector redirector;
  @override
  final RememberMe<User>? rememberMe;
  @override
  final RememberUri rememberUri;
}
