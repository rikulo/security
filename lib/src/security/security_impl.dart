//Copyright (C) 2013 Potix Corporation. All Rights Reserved.
//History: Mon, Apr 22, 2013  6:22:24 PM
// Author: tomyeh

part of rikulo_security;

///Session attribute for storing the current user
const _ATTR_USER = "stream.user";

typedef Future _LoginCallback(HttpConnect connect, user, bool rememberMe);
typedef Future _LogoutCallback(HttpConnect connect, user);

/** The implementation of the security module.
 */
class _Security implements Security {
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
    _filter = (HttpConnect connect, Future chain(HttpConnect conn)) {
      //1. remember me
      var user = currentUser(connect.request.session);
      if (user == null && rememberMe != null) {
        Future result = rememberMe.recall(connect);
        if (result != null)
          return result.then((user) {
              if (user != null) //failed to recall
              setLogin(connect, user);
            return _authorize(connect, user, chain);
              //2-3: authorize and chain
          });
      }

      //2-3: authorize and chain
      return _authorize(connect, user, chain);
    };
    _login = (HttpConnect connect, {String username, String password,
        bool rememberMe, bool redirect: true}) {
      String uri;
      redirect = redirect != false; //including null

      //1. logout first
      return _logout(connect, redirect: false).then((_) {
        if (username == null) {
          //2. get login information
          //FORM-based login  (note: we ignore query parameters)
          return HttpUtil.decodePostedParameters(connect.request)
            .then((Map<String, String> params) {
              username = params["s_username"];
              if (username == null)
                username = "";
              password = params["s_password"];
              if (password == null)
                password = "";
              if (rememberMe == null)
                rememberMe = params["s_rememberMe"] == "true";
            });
        } else {
          rememberMe = rememberMe == true; //excluding null
        }
      }).then((_) {
        //3. retrieve the URI for redirecting
        //we have to do it before login since login will re-create a session
        if (redirect)
          uri = rememberUri.recall(connect);

        //4. login
        return authenticator.login(connect, username, password);
      }).then((user) {
        //5 session/cookie handling
        return setLogin(connect, user, rememberMe: rememberMe);

      }).then((_) {
        //6. redirect
        if (redirect)
          connect.redirect(redirector.getLoginTarget(connect, uri));

      }).catchError((ex) {
        uri = redirector.getLoginFailed(connect, username, rememberMe);
        return redirector.isRedirectOnFail ?
          connect.redirect(uri): connect.forward(uri);
      }, test: (ex) => redirect && ex is AuthenticationException);
    };
    _logout = (HttpConnect connect, {bool redirect: true}) {
      var user = currentUser(connect.request.session);
      if (user == null) {
        if (redirect)
          connect.redirect(redirector.getLogoutTarget(connect));
        return new Future.value();
      }

      return authenticator.logout(connect, user)
      .then((Map data) {
        final session = connect.request.session..clear();
        if (data != null) {
          data.forEach((key, value) {
            session[key] = value;
          });
          _setCurrentUser(session, null); //safe if data contains it
        }
      }).then((_) {
        if (_onLogout != null)
          return _onLogout(connect, user);
      }).then((_) {
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
  Future setLogin(HttpConnect connect, user, {bool rememberMe}) {
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
    return (result !=null ? result: new Future.value()).then((_) {
      if (_onLogin != null)
        return _onLogin(connect, user, rememberMe);
    });
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
