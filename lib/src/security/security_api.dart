//Copyright (C) 2013 Potix Corporation. All Rights Reserved.
//History: Mon, Apr 22, 2013  6:22:01 PM
// Author: tomyeh

part of rikulo_security;

/** Returns the current user, or null if not authenticated.
 * It is the same object returned by [Authenticator]'s `authenticate`.
 */
currentUser(HttpSession session) => session[_ATTR_USER];
/// Sets the current user.
void _setCurrentUser(HttpSession session, user) {
  if (user != null)
    session[_ATTR_USER] = user;
  else
    session.remove(_ATTR_USER);
}

/** The login render handler that is returned by [Security.login].
 *
 * For form-based authentication, you have to map [Security.login]
 * to the login action, `/s_login`, as described in [Security]:
 *
 *     "/s_login": security.login,
 *
 * If you'd like to login in an Ajax request, SOAP or others,
 * you can invoke this method directly by providing the username, password
 * and, optional, rememberMe:
 *
 *     //prepare username, password, rememberMe from, say, Ajax
 *     security.login(connect, username: username, password: password,
 *       rememberMe: rememberMe, redirect: false);
 *
 * For other cases, you can use [Security.setLogin] (such as implementing
 * auto sign-in).
 *
 * * [username] - specifies the user name. If not specified, [useranme]
 * [password] and [rememberMe] will be retrieved
 * from HTTP request's body (by use of
 * `HttpUtil.decodePostedParameters(connect.request)`).
 * * [rememberMe] - whether remember-me is enabled or disabled.
 * If omitted (null), remember-me won't be updated.
 * It is meaningful
 * only if the constructor is called with a [RememberMe] instance.
 * * [redirect] - whether to redirect back to the original URI
 * (`connect.request.uri`). If omitted, it means true.
 * Notice: if [redirect] is false, the caller has to handle
 * [AuthenticationException] in `catchError` (if true, it is handled automatically).
 *
 * * [handleAuthenticationException] - whether to handle [AuthenticationException].
 * If false, the caller has to handle by himself.
 * Also notice that if [redirect] is false, it also implies *no* handling of
 * [AuthenticationException].
 *
 * * It returns a [Future] object (never null) to indicate when it completes.
 */
typedef Future LoginHandler(HttpConnect connect, {
  String username, String password, bool rememberMe, bool redirect,
  bool handleAuthenticationException});

/** The logout render handler that is returned by [Security.logout].
 *
 * For form-based authentication, you have to map [Security.logout]
 * to the lgout action, `/s_logout`, as described in [Security]:
 *
 *     "/s_logout": security.logout,
 *
 * If you'd like to logout in an Ajax request, you can invoke this method
 * directly:
 *
 *     security.logout(connect, redirect: false);
 *
 * * [redirect] - whether to redirect to the default web page (defined in
 * [Redirector]). If omitted, it means true.
 *
 * * It returns a [Future] object (never null) to indicate when it completes.
 */
typedef Future LogoutHandler(HttpConnect connect, {bool redirect});

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
 * Second, you can use `SimpleAccessControl` or implement your own access control
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
   * * [redirector] - provides the URIs that will be used in different situations.
   * If omitted, an instance of [Redirector] is instantiated and used.
   * * [rememberMe] - provides the plugin implementing *rememeber-me*.
   * If omitted, no remember-me feature at all. Also notice that *remember-me*
   * is enabled only if the `s_remember_me` parameter is specified with `true`
   * when [login] receives a request.
   * * [rememberUri] - provides the plugin implementing *remember-uri*.
   * If omitted, an instance of [RememberUri] is instantiated and used.
   * * [onLogin] and [onLogout] are used for registering a callback for handling
   * initialization of login and cleanup of logout. It can return null if
   * it completes immediately. Otherwise, return a [Future] instance to indicate
   * when it completes.
   */
  factory Security(Authenticator authenticator, AccessControl accessControl, {
      Redirector redirector, RememberMe rememberMe, RememberUri rememberUri,
      Future onLogin(HttpConnect connect, user, bool rememberMe),
      Future onLogout(HttpConnect connect, user)})
  => new _Security(authenticator, accessControl,
      redirector != null ? redirector: new Redirector(),
			rememberMe,
      rememberUri != null ? rememberUri: new RememberUri(),
      onLogin, onLogout);

  /** The filter used to configure Stream server's filter mapping.
   */
  RequestFilter get filter;
  /** The handler used to configure Stream server's URI mapping for handling
   * the login.
   *
   * > Note: the default value of [redirect] and [handleAuthenticationException]
   * are both true.
   */
  LoginHandler get login;
  /** The handler used to configure Stream server's URI mapping for handling
   * the logout.
   */
  LogoutHandler get logout;

  /** Notifies Rikulo Security that the given user logged in.
   * It is useful if you allows the user to login automatically, such as
   * remember-me mechanism and the sign-up mechanism.
   *
   * > For FORM or Ajax login, please use [login] instead.
   *
   * * [rememberMe] - whether remember-me is enabled or disabled.
   * If omitted (null), remember-me won't be updated.
   * It is meaningful
   * only if the constructor is called with a [RememberMe] instance.
   *
   * * It returns a [Future] object (never null) to indicate when it completes.
   * * [resetSession] - whether to re-create another session to replace the
   * current one. By default, it is true for session fixation attack protection.
   * * [onLogin] - whether to call the onLogin callback. Default: true.
   */
  Future setLogin(HttpConnect connect, user, {bool rememberMe,
      bool resetSession: true, bool onLogin: true});

  ///The authenticator.
  Authenticator get authenticator;
  ///The access control.
  AccessControl get accessControl;
  ///The redirector.
  Redirector get redirector;
  ///The remember me.
  RememberMe get rememberMe;
  ///The remember URI.
  RememberUri get rememberUri;
}

/** The authenticator.
 */
abstract class Authenticator {
  /** Authenticates the given username and password.
   * The returned `Future` object shall carry the user object if successful.
   * If failed, throw an instance of [AuthenticationException]:
   *
   *     Future login(HttpConnect connect, String username, String password) async {
   *       //...
   *       if (failed)
   *         throw new AuthenticationException("the cause");
   *       return new User(username, roles); //any non-null object
   *     });
   */
  Future login(HttpConnect connect, String username, String password);
  /** Logout.
   *
   * The default implementation does nothing but returns `null`.
   * You can override it for housekeeping if necessary.
   *
   * * [user] - the current user being logged out.
   * * Returns a [Future] instance carrying the data you'd like to preserve
   * in the new session after logout. If it carries null, nothing is preserved.
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
  Future<bool> canAccess(HttpConnect connect, user);
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
   * Default: `'/login?error=1&user=$username'`
   * or `'/login?error=1&user=$username&reme=1'` (if rememberMe is true)
   *
   * `HttpConnect.redirect()` will be called to redirect if
   * [isRedirectOnFail] is true. Otherwise, `HttpConnect.forward()` is called.
   *
   * + [username] - the username that the user entered.
   * + [rememberMe] - the value of the remember-me field, or null
   * if not available.
   */
  String getLoginFailed(HttpConnect connect, String username, bool rememberMe) {
    final String uri = "/login?error=1&user=$username";
    return rememberMe ? "$uri&reme=1": uri;
  }
  /** Whether to redirect the request or forward when failed to login.
   *
   * Default: true.
   */
  bool get isRedirectOnFail => true;

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

/** The remember-me plug-in.
 *
 * > Notice that [save] was called only if the `s_remember_me` parameter is
 * specified with `true`.
 */
abstract class RememberMe {
  /** Saves the given user for the given connection, such that it can be
   * recalled later when [recall] is called. If [rememberMe] is false,
   * this method shall clean up the information saved in the previous
   * invocation.
   *
   * The user's information is usually saved in a cookie (of the response).
   *
   * > Notice the cookie can be manipulated by a hostile user, so it is
   * better encoded and packed with extra information that can be verified
   * at the server.
   *
   * * [rememberMe] - whether remember-me is enabled. The user can disable
   * it if he likes. If false, it means to clean up the cookie.
   *
   * * It returns a [Future] object to indicate when it completes.
   * If it completes immediately, it can return null.
   */
  Future save(HttpConnect connect, user, bool rememberMe);
  /** It returns a Future object carrying the user if the given connection
   * is established by a user that was saved in [save]. Thus, caller can do:
   *
   *     var user = await rememberMe.recall(connect);
   *
   * It can return null to indicate nothing being recalled.
   */
  Future<dynamic> recall(HttpConnect connect);
}
/** The remember-me plug-in. It is used to redirect the user back to
 * the protected resource after logging in.
 */
class RememberUri {
  /** Saves the given request's URI, such that it can be recalled later when
   * [recall] was called.
   *
   * Default: it saves `request.uri.toString()` in the session if the request
   * is GET.
   */
  void save(HttpConnect connect) {
    final request = connect.request;
    if (request.method.toUpperCase() == "GET")
      request.session[_ATTR_REMEMBER_URI] = request.uri.toString();
  }
  /** Returns the previous saved URI, or null if nothing was saved.
   *
   * * [parameters] - the posted parameters sent with the login request.
   * It is empty if you invoke `security.login` directly (s.t., with Ajax login).
   */
  String recall(HttpConnect connect, Map<String, String> parameters)
  => connect.request.session[_ATTR_REMEMBER_URI];
}
///Session attribute for storing the original URI
const _ATTR_REMEMBER_URI = "stream.remember.uri";

/** The authentication being invalid.
 */
class AuthenticationException implements Exception {
  final String message;
  const AuthenticationException([this.message=""]);
  String toString() => "AuthenticationException: $message";
}
