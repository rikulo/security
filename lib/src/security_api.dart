//Copyright (C) 2013 Potix Corporation. All Rights Reserved.
//History: Mon, Apr 22, 2013  6:22:01 PM
// Author: tomyeh

part of rikulo_security;

/** Returns the current user, or null if not authenticated.
 * It is the same object returned by [Authenticator]'s `authenticate`.
 */
currentUser(HttpSession session) {

}
/** Sets the current user.
 */
_setCurrentUser(HttpSession session, user) {

}

/** The security module.
 *
 * ##Usage
 *
 * First, you have to implement [Authenticator]. For sake of description, we use
 * a dummy implementation here called [DummyAuthenticator]:
 *
 *     final authenticator = new DummyAuthenticator()
 *       ..addUser("john", "123", ["users"])
 *       ..addUser("peter": "123", ["users", "admins"]);
 *
 * Second, you can use [SimpleAccessControl] or implement your own access control
 * ([AccessControl]):
 *
 *     final accessControl = new SimpleAccessControl({
 *       "/control/.*": ["admins"],
 *       "/member/.*": ["users", "admins"];
 *     });
 *
 * Finally, instantiate [Security] with the authenticator and access control
 * you want:
 *
 *     new StreamServer(filterMapping: {
 *       "/.*": new Security(authenticator, accessControl).filter
 *     });
 */
abstract class Security {
  /** Constructor.
   *
   * * [loginUri] - specifies the URI to redirect to, if the current session is
   * not authenticated and it accesses the resource that requires some authorities
   * (i.e., under the control of [AccessControl]).
   */
  factory Security(Authenticator authenticator, AccessControl accessControl, {
      String loginUri: "/login"})
  => new _Security(authenticator, accessControl, loginUri);

  /** The filter used to configure Stream server's filter mapping.
   */
  RequestFilter get filter;
  /** The handler used to configure Stream server's URI mapping for handling
   * the login.
   */
  RequestHandler get login;
  /** The handler used to configure Stream server's URI mapping for handling
   * the logout.
   */
  RequestHandler get logout;
}

/** The authenticator who determines authenticity.
 */
abstract class Authenticator {
  /** Authenticates the given username and password.
   * The returned `Future` object shall carry the user object if successful,
   * or null if failed, such that the caller can do something similar to:
   *
   *     authenticate(username, password).then((user) {...});
   */
  Future authenticate(String username, String password);
}

/** The access control.
 */
abstract class AccessControl {
  /** Authorizes the given URI. It returns if the given session
   * is allowed to access the URI.
   */
  void authorize(HttpSession session, String uri);
}
