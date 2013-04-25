#Rikulo Security

Rikulo Security is a lightweight and highly customizable authentication and access-control framework for [Rikulo Stream](http://rikulo.org/projects/stream).

* [Home](http://rikulo.org/projects/stream)
* [Documentation](http://docs.rikulo.org/stream/latest/Add-ons/Rikulo_Security)
* [API Reference](http://api.rikulo.org/security/latest)
* [Discussion](http://stackoverflow.com/questions/tagged/rikulo)
* [Issues](https://github.com/rikulo/security/issues)

Stream is distributed under an Apache 2.0 License.

##Installation

Add this to your `pubspec.yaml` (or create it):

    dependencies:
      rikulo_security:

Then run the [Pub Package Manager](http://pub.dartlang.org/doc) (comes with the Dart SDK):

    pub install

##Usage

 First, you have to implement [Authenticator](http://api.rikulo.org/security/latest/rikulo_security/Authenticator.html). For sake of description, we use a dummy implementation here called [DummyAuthenticator](http://api.rikulo.org/security/latest/rikulo_security_plugin/DummyAuthenticator.html):

     final authenticator = new DummyAuthenticator()
       ..addUser("john", "123", ["user"])
       ..addUser("peter", "123", ["user", "admin"]);

 Second, you can use [SimpleAccessControl](http://api.rikulo.org/security/latest/rikulo_security_plugin/SimpleAccessControl.html) or implement your own access control
 ([AccessControl](http://api.rikulo.org/security/latest/rikulo_security/AccessControl.html)):

     final accessControl = new SimpleAccessControl({
       "/admin/.*": ["admin"],
       "/member/.*": ["user", "admin"]
     });

 Finally, instantiate [Security](http://api.rikulo.org/security/latest/rikulo_security/Security.html) with the authenticator and access control you want:

     final security = new Security(authenticator, accessControl);
     new StreamServer(uriMapping: {
       "/s_login": security.login,
       "/s_logout": security.logout
     }, filterMapping: {
       "/.*": security.filter
     }).start();

Please refer to [this sample application](/rikulo/security/tree/master/example/hello) for more information.

##TODO

* Session fixation attack protection (wait for [Issue 10169](https://code.google.com/p/dart/issues/detail?id=10169) to be fixed).

##Notes to Contributors

###Fork Rikulo Security

If you'd like to contribute back to the core, you can [fork this repository](https://help.github.com/articles/fork-a-repo) and send us a pull request, when it is ready.

Please be aware that one of Rikulo Security's design goals is to keep the sphere of API as neat and consistency as possible. Strong enhancement always demands greater consensus.

If you are new to Git or GitHub, please read [this guide](https://help.github.com/) first.
