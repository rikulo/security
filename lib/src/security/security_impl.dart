//Copyright (C) 2013 Potix Corporation. All Rights Reserved.
//History: Mon, Apr 22, 2013  6:22:24 PM
// Author: tomyeh

part of rikulo_security;

///Session attribute for storing the current user
const _ATTR_USER = "stream.user";

/** The implementation of the security module.
 */
class _Security implements Security {
  final Authenticator _authenticator;
  final AccessControl _accessControl;
  final Redirector _redirector;
  final RememberMe _rememberMe;
  final RememberUri _rememberUri;
  RequestFilter _filter;
  RequestHandler _login, _logout;

  _Security(this._authenticator, this._accessControl, this._redirector,
      this._rememberMe, this._rememberUri) {
    _init();
  }
  void _init() {
    _filter = (HttpConnect connect, Future chain(HttpConnect conn)) {
      //1. remember me
      var user = currentUser(connect.request.session);
      if (user == null && _rememberMe != null) {
        user = _rememberMe.recall(connect);
      }

      //2. authorize
      if (!_accessControl.canAccess(connect, user)) {
        if (user == null) {
          _rememberUri.save(connect);
          connect.redirect(_redirector.getLogin(connect));
          return new Future.value();
        }
        throw new Http404(); //404 (not 401) to minimize attack
      }

      //3. granted
      return chain(connect);
    };
    _login = (HttpConnect connect) {
      final request = connect.request;

      //1. logout first
      return _logout(connect).then((_) {
        //2. get login information
        return HttpUtil.decodePostedParameters(request, request.queryParameters);
      }).then((Map<String, String> params) {
        final username = params["s_username"];
        final password = params["s_password"];

        //3. login
        return _authenticator.login(connect, username, password);
      }).then((user) {
        //4. retrieve the URI for redirecting
        String uri = _rememberUri.recall(connect);

        //5. session fixation attack protection
        var session = request.session;
        //TODO: wait Issue 10169
        //final data = new Map.from(session..remove(_ATTR_ORIGINAL_URI));
        //session.destroy();
        session = request.session; //re-create
        //data.forEach((key, value) {
        //  session[key] = value;
        //});
        _setCurrentUser(session, user);

        //6. remember me
        if (_rememberMe != null)
          _rememberMe.save(connect, user);

        //7. redirect
        connect.redirect(_redirector.getLoginTarget(connect, uri));
      }).catchError((ex) {
        return connect.forward(_redirector.getLoginFailed(connect));
      }, test: (ex) => ex is AuthenticationException);
    };
    _logout = (HttpConnect connect) {
      var user = currentUser(connect.request.session);
      if (user == null)
        return new Future.value();

      final result = _authenticator.logout(connect, user);
      return (result != null ? result: new Future.value()).then((Map data) {
        final session = connect.request.session..clear();
        if (data != null) {
          data.forEach((key, value) {
            session[key] = value;
          });
          _setCurrentUser(session, null); //safe if data contains it
        }
        connect.redirect(_redirector.getLogoutTarget(connect));
      });
    };
  }

  @override
  RequestFilter get filter => _filter;
  @override
  RequestHandler get login => _login;
  @override
  RequestHandler get logout => _logout;
}
