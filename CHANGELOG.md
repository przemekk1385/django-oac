# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2020-11-23

### Added

* configurable classes for providing instances of Token and User models,
* configurable state expiration time
* JWKS caching

### Fixed

* removed database unrelated stuff from models
* fixed immature signature issue
* moved templates to app-named directory
* fixed compatibility with Django 2.2 and 3.0

## [0.1.1] - 2020-08-30

### Added

* integration with Travis CI and external tools for checking code formatting etc.
* compatibility with Django 2.2 and 3.0
* defining default value for environment variables in project settings
* changelog
* sample minimal version of .env file

### Fixed

* removed unnecessary inheritance from UserModel


## [0.1.0] - 2020-08-28

### Added

* client app
* sample project
* tests

[unreleased]: https://github.com/przemekk1385/django_oac/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/przemekk1385/django_oac/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/przemekk1385/django_oac/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/przemekk1385/django_oac/releases/tag/v0.1.0
