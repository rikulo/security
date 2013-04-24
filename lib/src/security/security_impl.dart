//Copyright (C) 2013 Potix Corporation. All Rights Reserved.
//History: Mon, Apr 22, 2013  6:22:24 PM
// Author: tomyeh

part of rikulo_security;

///Session attribute for storing the current user
const _ATTR_USER = "stream.user";
///Session attribute for storing the original URI
const _ATTR_ORIGINAL_URI = "stream.original.uri";

/** The implementation of the security module.
 */
class _Security implements Security {
  final Authenticator _authenticator;
  final AccessControl _accessControl;
  final Redirector _redirector;
  RequestFilter _filter;
  RequestHandler _login, _logout;

  _Security(this._authenticator, this._accessControl, this._redirector) {
    _init();
  }
  void _init() {
    _filter = (HttpConnect connect, Future chain(HttpConnect conn)) {
      var user = currentUser(connect.request.session);
      if (user == null) {
        //1. remember me (TODO0)
      }
      //2. authorize
      if (!_accessControl.canAccess(connect, user)) {
        if (user == null) {
          final request = connect.request;
          request.session[_ATTR_ORIGINAL_URI] = request.uri.toString();
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
        var session = request.session;
        String uri = session[_ATTR_ORIGINAL_URI];

        //5. session fixation attack protection
        //TODO: wait Issue 10169
        //final data = new Map.from(session..remove(_ATTR_ORIGINAL_URI));
        //session.destroy();
        session = request.session; //re-create
        //data.forEach((key, value) {
        //  session[key] = value;
        //});
        _setCurrentUser(session, user);

        //6. redirect
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
