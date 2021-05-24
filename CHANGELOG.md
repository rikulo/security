#CHANGES

**1.1.2+1**

* `Security.login` rejects if the posted body is over 3000 bytes.

**1.1.2**

* `Security.filter`, `login` and `logout` are instant methods instead of closures.

**1.1.1**

* `Security.switchLogin` supports the `resetSession` argument

**1.1.0**

* `Security.switchLogin` and `switchBack` added

**1.0.0**

* Upgrade to Dart 2

**0.8.7**

* `Authenticator.isSessionExpired` introduced to invalidate a session if necessary

**0.8.6**

* `AccessControl.canAcess()` returns `FutureOr<bool>`
* `onLogin` and `onLogout` callbacks return `FutureOr`

**0.8.3**

* Security.setLogin() introduces additional argument: resetSession

**0.8.1**

* #6: `AccessControl.canAccess()` became asynchronous

**0.8.0**

* #5: Able to pass the original URI as parameter of the login page
