//Copyright (C) 2013 Potix Corporation. All Rights Reserved.
//History: Mon, Apr 22, 2013  6:22:24 PM
// Author: tomyeh

part of rikulo_security;

/** The implementation of the security module.
 */
class _Security implements Security {
  final Authenticator _authenticator;
  final AccessControl _accessControl;
  final String _loginUri;
  RequestFilter _filter;
  RequestHandler _login, _logout;

  _Security(this._authenticator, this._accessControl, this._loginUri) {
    _init();
  }
  void _init() {
    _filter = (HttpConnect connect, Future chain(HttpConnect conn)) {
      return chain(connect);
    };
    _login = (HttpConnect connect) {

    };
    _logout = (HttpConnect connect) {

    };
  }

  @override
  RequestFilter get filter => _filter;
  @override
  RequestHandler get login => _login;
  @override
  RequestHandler get logout => _logout;
}