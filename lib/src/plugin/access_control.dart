//Copyright (C) 2013 Potix Corporation. All Rights Reserved.
//History: Tue, Apr 23, 2013  4:54:32 PM
// Author: tomyeh

part of rikulo_security_plugin;

/** A simple implementation of the access control.
 * It assumes the user object has a getter called `roles` which returns
 * a collection of roles (`Iterable<String>`).
 * Each role is represented as a string.
 * For better performance, it is suggested to be `Set<String>`.
 */
class SimpleAccessControl implements AccessControl {
  final List<_ACMapping> _mapping = [];

  SimpleAccessControl([Map<String, Iterable<String>> mapping]) {
    mapping.forEach((uri, roles) => add(uri, roles));
  }

  /** Adds a protected resource.
   *
   * * [uri] - a regular expression used to match the request URI.
   */
  void add(String uri, Iterable<String> roles) {
    _mapping.add(new _ACMapping(uri, roles));
  }

  @override
  FutureOr<bool> canAccess(HttpConnect connect, user) {
    final uri = connect.request.uri.path;
    for (final mapping in _mapping) {
      if (mapping.pattern.hasMatch(uri)) { //protected
        if (user != null) {
          final roles = user.roles;
          Set<String> col1;
          Iterable<String> col2;
          if (roles is Set<String> && roles.length > mapping.allowed.length) {
            col1 = roles;
            col2 = mapping.allowed;
          } else {
            col1 = mapping.allowed;
            col2 = roles;
          }

          for (final role in col2)
            if (col1.contains(role))
              return true;
        }
        return false; //denied
      }
    }
    return true; //granted
  }
}

class _ACMapping {
  final RegExp pattern;
  final Set<String> allowed;

  _ACMapping(String uri, Iterable<String> roles)
  : pattern = new RegExp("^$uri\$"),
    allowed = roles is Set ? roles: new Set.from(roles) {
      if (uri.isEmpty || "/.[(".indexOf(uri[0]) < 0)
        throw new ServerError("URI pattern must start with '/', '.', '[' or '('; not '$uri'");
    }
}
