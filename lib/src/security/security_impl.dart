//Copyright (C) 2013 Potix Corporation. All Rights Reserved.
//History: Mon, Apr 22, 2013  6:22:24 PM
// Author: tomyeh

part of rikulo_security;

///Session attribute for storing the current user
const _ATTR_USER = "stream.user";

/** The implementation of the security module.
 */
class _Security implements Security {
  RequestFilter _filter;
  RequestHandler _login;
  Function _logout; //we add a named parameter so we can't use RequestHandler

  _Security(this.authenticator, this.accessControl, this.redirector,
      this.rememberMe, this.rememberUri) {
    _init();
  }
  void _init() {
    _filter = (HttpConnect connect, Future chain(HttpConnect conn)) {
      //1. remember me
      var user = currentUser(connect.request.session);
      if (user == null && rememberMe != null) {
        Future result = rememberMe.recall(connect);
        if (result != null)
          return result.then((user) => _authorize(connect, user, chain));
          //2-3: authorize and chain
      }

      //2-3: authorize and chain
      return _authorize(connect, user, chain);
    };
    _login = (HttpConnect connect) {
      bool rememberMe;
      //1. logout first
      return _logout(connect, redirect:false).then((_) {
        //2. get login information
        return HttpUtil.decodePostedParameters(connect.request,
          new HashMap.from(connect.request.uri.queryParameters));
      }).then((Map<String, String> params) {
        final username = params["s_username"];
        final password = params["s_password"];
        rememberMe = params["s_rememberMe"] == "true";

        //3. login
        return authenticator.login(connect, username, password);
      }).then((user) {
        //4-5 session/cookie handling
        return setLogin(connect, user, rememberMe);

      }).then((_) {
        //6. retrieve the URI for redirecting
        String uri = rememberUri.recall(connect);

        //7. redirect
        connect.redirect(redirector.getLoginTarget(connect, uri));

      }).catchError((ex) {
        return connect.forward(redirector.getLoginFailed(connect));
      }, test: (ex) => ex is AuthenticationException);
    };
    _logout = (HttpConnect connect, {bool redirect: true}) {
      var user = currentUser(connect.request.session);
      if (user == null) {
        if (redirect)
          connect.redirect(redirector.getLogoutTarget(connect));
        return new Future.value();
      }

      return authenticator.logout(connect, user)
      .then((Map data) => setLogout(connect, data))
      .then((_) {
        if (redirect)
          connect.redirect(redirector.getLogoutTarget(connect));
      });
    };
  }
  //called by _filter to authorize and chain
  Future _authorize(HttpConnect connect, user, Future chain(HttpConnect conn)) {
    //2. authorize
    if (!accessControl.canAccess(connect, user)) {
      if (user == null) {
        rememberUri.save(connect);
        connect.redirect(redirector.getLogin(connect));
        return new Future.value();
      }
      throw new Http404(); //404 (not 401) to minimize attack
    }

    //3. granted and chain
    return chain(connect);
  }

  @override
  Future setLogin(HttpConnect connect, user, [bool rememberMe]) {
    //5. session fixation attack protection
    var session = connect.request.session;
    final data = new Map.from(session..remove(_ATTR_REMEMBER_URI));
    session.destroy();
    session = connect.request.session; //re-create
    data.forEach((key, value) {
      session[key] = value;
    });
    _setCurrentUser(session, user);

    //6. remember me
    Future result;
    if (this.rememberMe != null && rememberMe != null) //null => ignored
      result = this.rememberMe.save(connect, user, rememberMe);
    return result !=null ? result: new Future.value();
  }
  @override
  Future setLogout(HttpConnect connect, [Map<String, dynamic> data]) {
    final session = connect.request.session..clear();
    if (data != null) {
      data.forEach((key, value) {
        session[key] = value;
      });
      _setCurrentUser(session, null); //safe if data contains it
    }
    return new Future.value(); //not used but reserved for future modification
  }

  @override
  RequestFilter get filter => _filter;
  @override
  RequestHandler get login => _login;
  @override
  RequestHandler get logout => _logout;

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
