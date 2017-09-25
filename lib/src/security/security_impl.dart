//Copyright (C) 2013 Potix Corporation. All Rights Reserved.
//History: Mon, Apr 22, 2013  6:22:24 PM
// Author: tomyeh

part of rikulo_security;

///Session attribute for storing the current user
const String _ATTR_USER = "stream.user";

typedef FutureOr _LoginCallback<User>(HttpConnect connect, User user, bool rememberMe);
typedef FutureOr _LogoutCallback<User>(HttpConnect connect, User user);

/** The implementation of the security module.
 */
class _Security<User> implements Security<User> {
  RequestFilter _filter;
  LoginHandler _login;
  LogoutHandler _logout; //we add a named parameter so we can't use RequestHandler
  _LoginCallback _onLogin;
  _LogoutCallback _onLogout;

  _Security(this.authenticator, this.accessControl, this.redirector,
      this.rememberMe, this.rememberUri, this._onLogin, this._onLogout) {
    _init();
  }
  void _init() {
    _filter = (HttpConnect connect, Future chain(HttpConnect conn)) async {
      var user = currentUser(connect.request.session);
      if (user != null) {
        if (await authenticator.isSessionExpired(connect, user))
          user = null;
      } else if (rememberMe != null) { //1. remember me
        user = await rememberMe.recall(connect);
        if (user != null)
          await setLogin(connect, user);
      }

      //2-3: authorize and chain
      return _authorize(connect, user, chain);
    };

    _login = (HttpConnect connect, {String username, String password,
        bool rememberMe, bool redirect: true,
        bool handleAuthenticationException: true}) async {
      String uri;
      Map<String, String> params;
      redirect = redirect != false; //including null

      try {
        //1. logout first
        await _logout(connect, redirect: false);

        if (username == null) {
          //2. get login information
          //FORM-based login  (note: we ignore query parameters)
          final params = await HttpUtil.decodePostedParameters(connect.request);
          username = params["s_username"];
          if (username == null)
            username = "";
          password = params["s_password"];
          if (password == null)
            password = "";
          if (rememberMe == null)
            rememberMe = params["s_rememberMe"] == "true";
        } else {
          rememberMe = rememberMe == true; //excluding null
          params = new HashMap<String, String>();
        }

        //3. retrieve the URI for redirecting
        //we have to do it before login since login will re-create a session
        if (redirect)
          uri = rememberUri.recall(connect, params);

        //4. login
        final user = await authenticator.login(connect, username, password);

        //5 session/cookie handling
        await setLogin(connect, user, rememberMe: rememberMe);

        //6. redirect
        if (redirect)
          connect.redirect(redirector.getLoginTarget(connect, uri));

      } on AuthenticationException catch (_) {
        if (handleAuthenticationException && redirect) {
          uri = redirector.getLoginFailed(connect, username, rememberMe);
          return redirector.isRedirectOnFail ?
            connect.redirect(uri): connect.forward(uri);
        }
        rethrow;
      }
    };

    _logout = (HttpConnect connect, {bool redirect: true}) async {
      var user = currentUser(connect.request.session);
      if (user == null) {
        if (redirect)
          connect.redirect(redirector.getLogoutTarget(connect));
        return;
      }

      final data = await authenticator.logout(connect, user);
      final session = connect.request.session..clear();
      if (data != null) {
        data.forEach((key, value) {
          session[key] = value;
        });
        _setCurrentUser(session, null); //be safe in case data contains it
      }

      if (_onLogout != null)
        await _onLogout(connect, user);

      if (redirect)
        connect.redirect(redirector.getLogoutTarget(connect));
    };
  }

  //called by _filter to authorize and chain
  Future _authorize(HttpConnect connect, User user, Future chain(HttpConnect conn)) async {
    //1. check accessibility
    if (!await accessControl.canAccess(connect, user)) {
      if (user == null) {
        rememberUri.save(connect);
        connect.redirect(redirector.getLogin(connect));
        return null; //redirect for login
      }
      throw new Http404.fromConnect(connect); //404 (not 403) to minimize attack
    }

    //2. granted and chain
    return chain(connect);
  }

  @override
  Future setLogin(HttpConnect connect, User user, {bool rememberMe,
      bool resetSession: true, bool onLogin: true}) async {
    //5. session fixation attack protection
    var session = connect.request.session;
    if (resetSession) {
      final data = new Map.from(session..remove(_ATTR_REMEMBER_URI));
      session.destroy();
      session = connect.request.session; //re-create
      data.forEach((key, value) {
        session[key] = value;
      });
    }

    //5a. store the user
    _setCurrentUser(session, user);

    //6. remember me
    if (this.rememberMe != null && rememberMe != null) //null => ignored
      await this.rememberMe.save(connect, user, rememberMe);

    if (onLogin && _onLogin != null)
      return _onLogin(connect, user, rememberMe);
  }

  @override
  RequestFilter get filter => _filter;
  @override
  LoginHandler get login => _login;
  @override
  LogoutHandler get logout => _logout;

  @override
  final Authenticator authenticator;
  @override
  final AccessControl accessControl;
  @override
  final Redirector redirector;
  @override
  final RememberMe rememberMe;
  @override
  final RememberUri rememberUri;
}
