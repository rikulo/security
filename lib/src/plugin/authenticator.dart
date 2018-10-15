//Copyright (C) 2013 Potix Corporation. All Rights Reserved.
//History: Tue, Apr 23, 2013  4:54:42 PM
// Author: tomyeh

part of rikulo_security_plugin;

/** A dummy implementation for testing Rikulo Security.
 * It is definitely not a good idea to use this class in the production.
 */
class DummyAuthenticator extends Authenticator {
  final _userInfos = new HashMap<String, _DummyUserInfo>();

  ///Adds a user.
  void addUser(String username, String password, Iterable<String> roles) {
    _userInfos[username] = new _DummyUserInfo(new SimpleUser(username, roles), password);
  }

  @override
  Future<SimpleUser> login(HttpConnect connect, String username, String password) async {
    final userInfo = _userInfos[username];
    if (userInfo != null && userInfo.password == password)
      return userInfo.user;
    throw new AuthenticationException("Incorrect username or password");
  }
}

/* The user used in [DummyAuthenticator]
 * Notice that it is used only for demostration. Your implementation
 * need *not* to depend on it.
 */
class SimpleUser {
  final Set<String> _roles;
  ///The username.
  final String username;

  SimpleUser(this.username, Iterable<String> roles)
  : _roles = roles is Set<String> ? roles: new Set<String>.from(roles);

  ///The roles that this user has.
  Set<String> get roles => _roles;

  @override
  String toString() => "$username";
}

///The user information
class _DummyUserInfo {
  final SimpleUser user;
  final String password;
  _DummyUserInfo(this.user, this.password);
}
