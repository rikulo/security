//Copyright (C) 2013 Potix Corporation. All Rights Reserved.
//History: Tue, Apr 23, 2013  4:54:42 PM
// Author: tomyeh

part of rikulo_security_plugin;

/** A dummy implementation for testing Rikulo Security.
 * It is definitely not a good idea to use this class in the production.
 */
class DummyAuthenticator extends Authenticator {
  final Map<String, _DummyUserInfo> _userInfos = new Map();

  ///Adds a user.
  void addUser(String username, String password, Iterable<String> roles) {
    _userInfos[username] = new _DummyUserInfo(new SimpleUser(username, roles), password);
  }

  @override
  Future<SimpleUser> login(HttpConnect connect, String username, String password) {
    final userInfo = _userInfos[username];
    if (userInfo != null && userInfo.password == password)
      return new Future.value(userInfo.user);
    throw new AuthenticationException("Incorrect username or password");
  }

}
class _DummyUserInfo {
  final SimpleUser user;
  final String password;
  _DummyUserInfo(this.user, this.password);
}

/** A simple implementation of a user.
 * It is used in [DummyAuthenticator].
 */
class SimpleUser {
  final Set<String> _roles;
  ///The username.
  final String username;

  SimpleUser(this.username, Iterable<String> roles)
  : _roles = roles is Set ? roles: new Set.from(roles);

  ///The roles that this user has.
  Set<String> get roles => _roles;

  String toString() => "$username$roles";
}
