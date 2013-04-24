//Sample of Stream: Hello Templates
library hello_security;

import "dart:async";
import "dart:io";
import "package:stream/stream.dart";
import "package:rikulo_security/security.dart";
import "package:rikulo_security/plugin.dart";

part "home.rsp.dart";
part "login.rsp.dart";

void main() {
  //1. you have to implement [Authenticator]. For sake of description, we use a dummy one
  final authenticator = new DummyAuthenticator()
    ..addUser("john", "123", ["user"])
    ..addUser("admin", "123", ["user", "admin"]);

  //2. you can use [SimpleAccessControl] or implements your own
  final accessControl = new SimpleAccessControl({
    "/admin(|/.*)": ["admin"],
    "/member(|.*)": ["user", "admin"]
  });

  //3. instantiate [Security]
  final security = new Security(authenticator, accessControl);

  //4. start Stream server
  new StreamServer(uriMapping: {
    "/": home, //home.rsp.html
    "/login": login, //login.rsp.html
    "/s_login": security.login,
    "/s_logout": security.logout
  }, filterMapping: {
    "/.*": security.filter
  }, errorMapping: {
    "404": "/404.html"
  }).start();
}
