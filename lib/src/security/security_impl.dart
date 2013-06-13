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
        user = rememberMe.recall(connect);
      }

      //2. authorize
      if (!accessControl.canAccess(connect, user)) {
        if (user == null) {
          rememberUri.save(connect);
          connect.redirect(redirector.getLogin(connect));
          return new Future.value();
        }
        throw new Http404(); //404 (not 401) to minimize attack
      }

      //3. granted
      return chain(connect);
    };
    _login = (HttpConnect connect) {
      //1. logout first
      return _logout(connect, redirect:false).then((_) {
        //2. get login information
        return HttpUtil.decodePostedParameters(connect.request,
          new HashMap.from(connect.request.uri.queryParameters));
      }).then((Map<String, String> params) {
        final username = params["s_username"];
        final password = params["s_password"];

        //3. login
        return authenticator.login(connect, username, password);
      }).then((user) {
        //4. retrieve the URI for redirecting
        String uri = rememberUri.recall(connect);

        //5-6 session/cookie handling
        setLogin(connect, user);

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

      return authenticator.logout(connect, user).then((Map data) {
        setLogout(connect, data);
        if (redirect)
          connect.redirect(redirector.getLogoutTarget(connect));
      });
    };
  }

  @override
  void setLogin(HttpConnect connect, user) {
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
    if (rememberMe != null)
      rememberMe.save(connect, user);
  }
  void setLogout(HttpConnect connect, [Map<String, dynamic> data]) {
    final session = connect.request.session..clear();
    if (data != null) {
      data.forEach((key, value) {
        session[key] = value;
      });
      _setCurrentUser(session, null); //safe if data contains it
    }
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
