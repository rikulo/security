# Rikulo Security

Rikulo Security is a lightweight and highly customizable authentication and access-control framework for [Rikulo Stream](https://github.com/rikulo//stream).

* [Home](https://github.com/rikulo/security)
* [API Reference](https://pub.dev/documentation/rikulo_security/latest/)
* [Discussion](http://stackoverflow.com/questions/tagged/rikulo)
* [Source Code Repos](https://github.com/rikulo/security)
* [Issues](https://github.com/rikulo/security/issues)

Stream is distributed under an Apache 2.0 License.

[![Build Status](https://drone.io/github.com/rikulo/security/status.png)](https://drone.io/github.com/rikulo/security/latest)

## Installation

Add this to your `pubspec.yaml` (or create it):

    dependencies:
      rikulo_security:

Then run the [Pub Package Manager](https://pub.dartlang.org/doc) (comes with the Dart SDK):

    pub install

## Usage

 First, you have to implement `Authenticator`. For sake of description, we use a dummy implementation here called `DummyAuthenticator`:

     final authenticator = new DummyAuthenticator()
       ..addUser("john", "123", ["user"])
       ..addUser("peter", "123", ["user", "admin"]);

 Second, you can use `SimpleAccessControl` or implement your own access control
 (`AccessControl`):

     final accessControl = new SimpleAccessControl({
       "/admin/.*": ["admin"],
       "/member/.*": ["user", "admin"]
     });

 Finally, instantiate `Security` with the authenticator and access control you want:

     final security = new Security(authenticator, accessControl);
     new StreamServer(uriMapping: {
       "/s_login": security.login,
       "/s_logout": security.logout
     }, filterMapping: {
       "/.*": security.filter
     }).start();

Please refer to [this sample application](https://github.com/rikulo/security/tree/master/example/hello) for more information.

## Notes to Contributors

### Fork Rikulo Security

If you'd like to contribute back to the core, you can [fork this repository](https://help.github.com/articles/fork-a-repo) and send us a pull request, when it is ready.

Please be aware that one of Rikulo Security's design goals is to keep the sphere of API as neat and consistency as possible. Strong enhancement always demands greater consensus.

If you are new to Git or GitHub, please read [this guide](https://help.github.com/) first.

## Who Uses

* [Quire](https://quire.io) - a simple, collaborative, multi-level task management tool.
* [Keikai](https://keikai.io) - a sophisticated spreadsheet for big data
