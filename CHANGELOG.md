# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.0] - 2022-01-29
### Added
* The order of working with the module has been changed: now we first create an
object using the module (function `new`), and then the object creates a
certificate (method `getCert`).
* Added generate CSR inside the module. External CSR-file is no longer required.
* Added method for getting certificate expiration date

## [1.0.0] - 2022-01-20
The first version has been implemented. Version restrictions:
* Used ACME version 2 (version 1 - not realized)
* Prepared CSR-file required
* Requires program `openssl`
* Requires writing temporary files to a pre-specified folder

Read more [here](https://1div0.ru/acme-client-for-tarantool/) or
[here](https://habr.com/ru/post/646899/).