//Copyright (C) 2013 Potix Corporation. All Rights Reserved.
//History: Mon, Apr 22, 2013  6:22:01 PM
// Author: tomyeh

part of rikulo_security;

/** Returns the current user, or null if not authenticated.
 * It is the same object returned by [Authenticator]'s `authenticate`.
 */
currentUser(HttpSession session) => session[_ATTR_USER];
/// Sets the current user.
_setCurrentUser(HttpSession session, user) {
  if (user != null)
    session[_ATTR_USER] = user;
  else
    session.remove(_ATTR_USER);
}

/** The security module.
 *
 * ##Usage
 *
 * First, you have to implement [Authenticator]. For sake of description, we use
 * a dummy implementation here called [DummyAuthenticator]:
 *
 *     final authenticator = new DummyAuthenticator()
 *       ..addUser("john", "123", ["user"])
 *       ..addUser("peter", "123", ["user", "admin"]);
 *
 * Second, you can use [SimpleAccessControl] or implement your own access control
 * ([AccessControl]):
 *
 *     final accessControl = new SimpleAccessControl({
 *       "/admin/.*": ["admin"],
 *       "/member/.*": ["user", "admin"]
 *     });
 *
 * Finally, instantiate [Security] with the authenticator and access control
 * you want:
 *
 *     final security = new Security(authenticator, accessControl);
 *     new StreamServer(uriMapping: {
 *       "/s_login": security.login,
 *       "/s_logout": security.logout
 *     }, filterMapping: {
 *       "/.*": security.filter
 *     }).start();
 */
abstract class Security {
  /** Constructor.
   *
   * * [loginUri] - specifies the URI to redirect to, if the current session is
   * not authenticated and it accesses the resource that requires some authorities
   * (i.e., under the control of [AccessControl]).
   */
  factory Security(Authenticator authenticator, AccessControl accessControl, {
      Redirector redirector})
  => new _Security(authenticator, accessControl,
      redirector != null ? redirector: new Redirector());

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
   * The returned `Future` object shall carry the user object if successful.
   * If failed, throw an instance of [AuthenticationException]:
   *
   *     Future login(HttpConnect connect, String username, String password) {
   *       //...
   *       if (failed)
   *         throw new AuthenticationException("the cause");
   *       return new Future.value(new User(username, roles)); //any non-null object
   *     });
   */
  Future login(HttpConnect connect, String username, String password);
  /** Logout.
   *
   * The default implementation does nothing but returns null.
   * You can override it for housekeeping if necessary.
   *
   * * [user] - the current user being logged out.
   * * Returns the data you'd like to preserve in the new session after logout.
   * If null, nothing is preserved.
   */
  Future<Map> logout(HttpConnect connect, user) => null;
}

/** The access control.
 */
abstract class AccessControl {
  /** Test if the given request is accessible by the given user.
   *
   * * [user] - the current user, or null if not logged in.
   * * It returns true if the access is granted; returns false if not allowed
   * (either not logged in or not allowed).
   *
   * If [user] is not null and this method returns false, an instance of [Http404]
   * will be thrown. If you prefer other status code (such as 401), you can
   * throw an exception in this method.
   */
  bool canAccess(HttpConnect connect, user);
}

/** The redirector to provide URI for different situations.
 */
class Redirector {
  /** Returns the URI for displaying the login page.
   *
   * Default: `'/login'`
   */
  String getLogin(HttpConnect connect) => "/login";
  /** Returns the URI for displaying the login page again when
   * the user failed to login.
   *
   * Default: `'/login?retry='`
   *
   * Unlike others, Rikulo Security *forwards* the request to the URI
   * returned by this method (rather than `HttpConnect.redirect()`).
   */
  String getLoginFailed(HttpConnect connect) => "/login?retry=";
  /** Returns the URI that the user will be taken to after logging in.
   *
   * Default: `originalUri ?? '/'`
   *
   * * [originalUri] - the original URI that the user is trying to access,
   * before redirecting to the login page. It is null, if the user
   * accesses the login page directly.
   */
  String getLoginTarget(HttpConnect connect, String originalUri)
  => originalUri != null ? originalUri: "/";

  /** Returns the URI that the user will be taken to after logging out.
   *
   * Default: `'/'`
   */
  String getLogoutTarget(HttpConnect connect) => "/";
}

/** The authentication being invalid.
 */
class AuthenticationException implements Exception {
  final String message;
  const AuthenticationException([this.message=""]);
  String toString() => "AuthenticationException: $message";
}
