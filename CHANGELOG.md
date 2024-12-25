# Changelog

All notable changes to this project will be documented in this file.

## [unreleased]

### 🚀 Features

- *(client)* Add `no-keepalive` for `Client`

### ⚙️ Miscellaneous Tasks

- Argo clippy --fix

## [1.0.0-rc.3] - 2024-12-25

### 🚀 Features

- Optional to enable impersonate customization (#217)

### ⚡ Performance

- Avoiding Unnecessary Copies (#219)

### ⚙️ Miscellaneous Tasks

- Remove unnecessary `Arc` wrapper from `redirect`/`base_url` (#216)
- Update macros (#218)
- Fix clippy accidentally deleted code (#220)
- *(util/clent)* Remove extra clones

## [1.0.0-rc.2] - 2024-12-24

### 🚀 Features

- Allow pluggable tower layers in connector service stack (#214)

### 🐛 Bug Fixes

- Propagate Body::size_hint when wrapping bodies (#213)

### ⚙️ Miscellaneous Tasks

- Cargo clippy --fix
- Remove `new` method for `InnerRequestBuilder` (#212)
- Remove `clone` from `Dst`

## [1.0.0-rc.1] - 2024-12-24

### 🚀 Features

- Hyper v1 upgrade (#187)
- Support request setting HTTP override ALPN (#188)
- *(client)* Add the maximum safe retry count for HTTP/2 connections (#196)
- *(client)* Export `http1`/`http2` Builder as public API (#199)
- *(client)* Export `http1`/`http2` Builder as public API
- *(body)* Improve interop with hyper for `Body` type
- *(client)* Add impl `Service<http::Request<Body>>` for `Client` (#202)
- *(client)* Request specific proxy override (#211)

### 🐛 Bug Fixes

- *(http2)* Fix http2 header frame initial `stream_id` settings (#185)
- Fix http protocol auto-negotiation (#189)

### ⚙️ Miscellaneous Tasks

- Remove dead code (#182)
- Macros simplify some debug implement (#183)
- Static calc extension permutation (#184)
- Cargo fmt --all
- Remove unused code (#191)
- *(pool)* Use `Mutex` types that do not poison themselves (#192)
- Simplified TLS TCP stream abstraction (#193)
- Cleaned up some unnecessary code (#194)
- Remove unused code
- Refactor connect mod
- Refactor connect layer detail handle (#198)
- Remove dead code
- Use shorter feature name
- Deleted permutation storage
- Remove unused code
- Remove unused code
- Disable the exposure of internal connect dst API (#203)
- Removed TLS config examples to prevent misconfigurations by inexperienced users (#205)
- By default, impersonate from a string is disabled (#206)
- *(tls)* Compile-time calculation of extended permutation (#207)
- *(tls)* Disable custom TLS builder (#208)
- Refactor connect network request extension (#210)

### Deps

- *(tokio-util)* V0.7.0 (#190)

## [0.33.5] - 2024-12-19

### 🚀 Features

- *(client)* Http1 sends lowercase request headers by default to improve performance (#179)
- Add `firefox 133` impersonate (#181)

## [0.33.3] - 2024-12-16

### 🐛 Bug Fixes

- *(proxy)* Fix `ws`/`wss` upgrade support for `http`/`https` proxy (#176)

## [0.33.1] - 2024-12-16

### ⚙️ Miscellaneous Tasks

- Show clear errors when TLS connector build fails (#173)
- Avoiding setup bloat when customizing your DNS resolver (#174)

## [0.33.0] - 2024-12-15

### 🚀 Features

- Add `Safari 18.1.1` impersonate (#157)
- Add `Edge 131` impersonate (#158)
- *(client)* Add support for base URL parameter (#159)
- *(client)* Add support for base URL parameter
- Add loading of dynamic root certificate store (#170)
- *(client)* Request specific cookie store override (#171)

### 🐛 Bug Fixes

- *(hickory-dns)* Fix initialization when `/etc/resolv.conf` is missing (#163)
- *(client)* Return an error instead of panic when parsing invalid URL (#164)
- *(connect)* Unnecessarily panic when parsing invalid URI (#166)

### ⚙️ Miscellaneous Tasks

- Do not pre-append `content-length` in non-header sorting state (#152)
- Macro static creation of impersonate template (#156)
- Update impersonate template
- Update macro export scope
- To avoid ambiguity, `ca_cert_store` is renamed to `root_certs_store` (#162)
- Simplify root certificate load
- Simplify root certificate load (#169)
- Move `ImpersonateSettings` to implement location

### ◀️ Revert

- Remove `proxies_maybe_http_auth` state

### Deps

- *(async-tungstenite)* Downgrade `async-tungstenite` to `0.27.0` (#161)

## [0.32.1] - 2024-12-12

### 🚀 Features

- Implement IntoUrl for Cow<'a, str> (#145)
- Impl `IntoUrl` for `&Url` (#146)
- *(client)* Request specific redirect policy override (#147)
- *(redirect)* Expose method for accessing the previous and next request (#148)
- Add `Safari 18.2` impersonate (#151)

### 🚜 Refactor

- Unified naming API (#150)

### ⚙️ Miscellaneous Tasks

- *(client)* Client `set_redirect_policy` rename to `set_redirect` (#149)
- Simplify the impersonate template

## [0.31.11] - 2024-12-11

### 🚀 Features

- *(request)* Add `with_host_header` method for populating Host header (#142)
- *(client)* Set `content-length` in advance for header sorting (#144)

### ⚙️ Miscellaneous Tasks

- *(request)* Delete WASM legacy API (#141)
- *(request)* Avoid panic when adding host header

## [0.31.10] - 2024-12-10

### 🐛 Bug Fixes

- *(client)* Fix http redirect via proxy (#134)
- *(client)* Fix redirect header sorting (#135)
- *(client)* Fix redirect via connection pool extension (#137)
- *(client)* Fix retry request via connection pool extension (#138)

## [0.31.7] - 2024-12-10

### 🚀 Features

- *(client)* Add proxy management APIs: set, append, and clear proxies (#132)

### ⚙️ Miscellaneous Tasks

- *(tls)* Rename `http_version_pref` to `alpn_protos` (#131)

## [0.31.6] - 2024-12-09

### ⚙️ Miscellaneous Tasks

- Introduce macro for conditional header initialization (#127)
- Fix typo

## [0.31.5] - 2024-12-09

### 🐛 Bug Fixes

- *(connector)* Initialize pool key extension when creating a client (#126)

### ⚙️ Miscellaneous Tasks

- *(client)* Accept request header is appended by default (#125)

## [0.31.3] - 2024-12-09

### 🚀 Features

- *(client)* Add address/interface level connection pool (#123)

### ⚙️ Miscellaneous Tasks

- Refactor struct fields to use Cow<'static, T> for better efficiency (#124)
- *(client)* Impersonate does not clone request headers unless necessary

## [0.31.2] - 2024-12-08

### 🚀 Features

- *(client)* Support proxy-level connection pool (#122)

### 🚜 Refactor

- Do not create default request headers unless necessary (#120)

### ⚙️ Miscellaneous Tasks

- Update
- Cache template request headers (#121)

## [0.31.0] - 2024-12-08

### 🚀 Features

- Support changing cookie provider after initialization (#114)
- *(client)* Limit number of connections in pool (#118)

### 🚜 Refactor

- Reduce `unsafe` scope for improved safety and readability (#115)

### ⚙️ Miscellaneous Tasks

- Undo the dynamic distribution configuration headers (#111)
- Disable dynamic distribution loading of certificates (#112)
- Disable dynamic distribution loading of connector builder (#113)
- Use custom connector builder
- Inline some hot code
- Reuse redirect policies whenever possible
- Remove tunnel proxy user agent setting (#116)
- Simplify pre-configured TLS settings
- Simplify impersonate template
- *(tls)* Export extension as public API

### Build

- Fix `android`/`fuchsia`/`linux` --no-default-features build (#110)

## [0.30.5] - 2024-12-07

### 🚀 Features

- *(client)* Greatly improve the speed of creating clients (#108)

### ⚙️ Miscellaneous Tasks

- *(tls)* Remove redundant settings (#109)

## [0.30.0] - 2024-12-06

### 🐛 Bug Fixes

- Improve TLS connector creation, fix client creation taking too long (#107)

## [0.29.9] - 2024-12-06

### 🚀 Features

- *(tls)* Dynamically configure WebSocket TLS connection alpn protos (#104)
- *(client)* Added async client creation to reduce blocking of async runtime (#105)

### ⚙️ Miscellaneous Tasks

- Cargo clippy --fix (#106)

## [0.29.0] - 2024-12-06

### 🚀 Features

- Support changing redirect policy after initialization (#102)
- Support changing interface after initialization (#103)
- Support changing interface after initialization

## [0.28.5] - 2024-12-05

### 🚀 Features

- Support changing header order after initialization (#101)

## [0.28.1] - 2024-12-05

### 🚀 Features

- Support changing impersonate fingerprint after initialization (#100)

## [0.28.0] - 2024-12-05

### 🚀 Features

- Changing request headers after client initialization (#97)

### 🐛 Bug Fixes

- Fix decompressing deflate with zlib specific wrapper fails (#99)

### 🚜 Refactor

- Delete unnecessary clone (#98)

## [0.27.7] - 2024-11-21

### 🚀 Features

- Add `Chrome 131` impersonate (#94)

## [0.27.6] - 2024-11-15

### 🚀 Features

- *(proxy)* Optional disable internal proxy cache (#92)
- Expose `hickory-resolver` as public API (#93)

## [0.27.5] - 2024-11-05

### 🚀 Features

- Expose `tokio-boring` as public API (#88)

### 🐛 Bug Fixes

- *(tls)* Fix SNI verification (#87)

## [0.27.3] - 2024-11-04

### 🚀 Features

- Optionl BoringSSL PQ experimental feature (#84)

## [0.27.2] - 2024-11-01

### 🚀 Features

- *(tls)* Add option `session_ticket` extension (#79)
- *(tls)* Implement Debug for TlsSettings (#80)
- *(tls)* Update session ticket setting
- *(tls)* No additional WebSocket connector is needed for HTTP/1 client (#81)

## [0.27.1] - 2024-11-01

### 🚀 Features

- *(http2)* Exposing Http2Settings fields (#75)
- *(tls)* Expose more custom TL settings (#76)
- *(client)* Optional configuration of Client TLS extension (#78)

### 🚜 Refactor

- Integrate tls/http2 unified configuration module (#77)

## [0.27.0] - 2024-10-31

### Deps

- *(hyper)* Bump version to v0.14.60 (#74)

## [0.26.3] - 2024-10-30

### 🚀 Features

- *(http2)* Add `http2_max_frame_size` settings (#73)

## [0.26.2] - 2024-10-27

### 🚜 Refactor

- *(tls)* Refactor internal `TLS`/`HTTP2` module (#69)
- *(tls)* Simplified TLS version mappr (#70)
- *(impersonate)* Simplify Impersonate enum parsing with macro (#71)

## [0.26.1] - 2024-10-26

### 🚀 Features

- *(tls)* Simplify TLS version settings (#66)

### 🐛 Bug Fixes

- Update Chrome version from 129 to 130 (#68)

### 📚 Documentation

- Improve `TLS`/`HTTP2` custom configuration documentation (#67)

## [0.26.0] - 2024-10-25

### 🚀 Features

- *(impersonate)* Add Chrome 130 impersonate (#65)

### 🚜 Refactor

- Normalize DNS module exports (#64)

## [0.25.7] - 2024-10-25

### 🚀 Features

- *(client)* Default send header names as title case (only http1) (#61)

### Deps

- *(h2)* Use h2 dependencies export by hyper (#63)

## [0.25.6] - 2024-10-24

### 🚀 Features

- *(dns)* Export dns resolver `HickoryDnsResolver` (#55)

### 🐛 Bug Fixes

- *(http)* Compatible with some CDN servers, Http1 retains case by default when sending headers(#56)

### 📚 Documentation

- Update docs (#54)

### Deps

- Remove unnecessary libc dependencies (#53)

## [0.25.5] - 2024-10-23

### 🐛 Bug Fixes

- *(tls)* Fix unsafe code block warnings (#52)

## [0.25.2] - 2024-10-23

### 🚀 Features

- *(websocket)* Add websocket handshake with a specified websocket key (#50)

### 🐛 Bug Fixes

- *(client)* Fix `ClientBuilder` not `Send` + `Sync` (#51)

## [0.25.1] - 2024-10-22

### 🚀 Features

- *(websocket)* Improve websocket API usage (#49)

## [0.25.0] - 2024-10-22

### 🚀 Features

- *(client)* Adaptively select and upgrade the websocket connector (#48)

## [0.23.3] - 2024-10-17

### 🚜 Refactor

- *(tls)* Simplify TLS custom settings (#46)

## [0.23.2] - 2024-10-16

### Deps

- *(hyper)* Bump version to v0.14.50 (#45)

## [0.23.1] - 2024-10-16

### 🚀 Features

- Improve header sort (#43)
- Improve unnecessary header sorting storage overhead (#44)

## [0.23.0] - 2024-10-13

### 🚀 Features

- *(tls)* Optional webpki root certificates feature (#40)

### 🐛 Bug Fixes

- *(tls)* Fix CA certificate conditional compilation (#41)

### 🚜 Refactor

- *(tls)* Public and reuse tls/http2 templates (#42)

## [0.22.2] - 2024-10-12

### 🚀 Features

- *(tls)* Avoid repeated loading of native root CA (#37)

### 🚜 Refactor

- Refactor custom root CA certificate loading source (#38)

## [0.22.1] - 2024-10-12

### 🚀 Features

- *(tls)* Optional built-in root certificates feature (#36)

## [0.22.0] - 2024-10-11

### 🚀 Features

- Add file function to async::multipart (#32)
- *(dns)* Optional `LookupIpStrategy` for `hickory_dns` (#33)

### 🚜 Refactor

- *(client)* Removed confusing way to enable `hickory-dns` (#34)

## [0.21.20] - 2024-10-10

### 🚀 Features

- *(proxy)* Add support for SOCKS4 (#27)

### 🐛 Bug Fixes

- *(tls)* Fix default tls configuration to use websocket (#30)

### 🚜 Refactor

- *(proxy)* Remove internal proxy sys cache (#26)

## [0.21.15] - 2024-10-09

### Deps

- *(brotli)* 7.0.0 (#22)
- *(tokio-socks)* 0.5.2 (#23)
- *(async-tungstenite)* 0.28.0 (#24)
- *(windows-registry)* 0.3.0 (#25)

## [0.21.12] - 2024-10-06

### Deps

- *(ipnet)* 2.10.0 (#15)

### Dpes

- *(typed-builder)* V0.20.0 (#16)

## [0.21.11] - 2024-09-27

### 🐛 Bug Fixes

- *(tls)* Fix default TLS SNI context configuration conflict (#13)

## [0.21.10] - 2024-09-23

### 🚀 Features

- *(tls)* Enable permute extensions for `Chrome`/`Edge` 106 and above (#6)
- *(tls)* Some `Chrome`/`Edge` versions have `ECH` enabled by default (#8)
- *(tls)* Some `Chrome`/`Edge` versions have `ECH` enabled by default (#9)
- *(impersonate)* Add `Safari iPad 18` impersonate (#10)

### 🚜 Refactor

- *(client)* Turn off default redirect (#4)
- *(tls)* Simplify TLS configuration (#5)
- *(tls)* Simplify TLS/HTTP2 configuration (#7)

## [0.21.1] - 2024-09-22

### 🚀 Features

- *(impersonate)* Add Safari 18 impersonate

### 🚜 Refactor

- Rename the `client` module to `http`
- *(tls)* Refactored changes and refactored TLS build

## [0.20.85] - 2024-09-08

### 🐛 Bug Fixes

- *(client)* Optional setting of default accept (#133)
- *(websocket)* Fix websocket upgrade builder (#134)

## [0.20.80] - 2024-09-03

### 🚀 Features

- *(impersonate)* Add Chrome 128 impersonate (#130)

### 🐛 Bug Fixes

- *(client)* Fix the header sending order, set accept before request (#131)

## [0.20.49] - 2024-08-16

### 🚀 Features

- *(client)* Add `impersonate_with_headers` allows optionally setting request headers (#128)

### 🚜 Refactor

- *(client)* Simplify Headers Frame priority settings (#126)

## [0.20.35] - 2024-08-15

### 🚀 Features

- *(client)* Suggest `inline` to the compiler (#122)

### Remove

- *(client)* Remove blocking client support (#123) (#124) (#125)

## [0.20.30] - 2024-08-15

### Build

- Fix `--no-default-features` build

## [0.20.25] - 2024-08-15

### 🐛 Bug Fixes

- *(client)* Fix http version setting order (#120)

### Refractor

- *(tls/settings)* Generate configuration using builder mode (#121)

## [0.20.23] - 2024-08-14

### 🚀 Features

- *(tls)* Add preconfigured TLS settings (#118)

### 🚜 Refactor

- *(client)* Set_proxies accepts an slice of references (#119)

## [0.20.22] - 2024-08-13

### 🚀 Features

- *(dns)* Enable happy eyeballs when using hickory-dns (#115)
- *(proxy)* Use  instead of  for reading proxy settings on Windows (#116)
- *(tls)* Add option to configure TLS server name indication (SNI) (#117)

## [0.20.21] - 2024-08-12

### 🚀 Features

- *(tls)* Optimize tls configuration process (#113)

## [0.20.20] - 2024-08-12

### 🚀 Features

- *(client)* Simplify client configuration (#110)
- *(tls)* Add `CA Certificate` settings (#112)

### 🚜 Refactor

- *(tls)* Refactor TLS connection layer configuration (#111)

### Deps

- *(boring/hyper/h2)* Migration patch crate name (#109)

## [0.20.10] - 2024-08-10

### 🚀 Features

- *(http2)* Add headers frame default priority (#106)
- *(tls)* Reuse https connector layer (#107)

### 🎨 Styling

- *(tls)* Remove unused closure

### ◀️ Revert

- *(tls)* Revert tls_built_in_root_certs option (#105)

## [0.20.1] - 2024-08-08

### 🚀 Features

- *(client)* Simplify the header configuration process
- *(extension)* Set application protocol (ALPN) for http1 (#104)

### 🐛 Bug Fixes

- *(tls)* Fix setting config TLS version

### 🚜 Refactor

- *(tls)* Simplify TLS connector configuration (#103)

### ◀️ Revert

- *(client)* Remove use of unused TLS Server Name Indication

### Deps

- *(system-configuration)* V0.6.0
- *(winreg)* V0.52.0

## [0.20.0] - 2024-08-07

### 🚀 Features

- *(client)* Allow binding interface (#92)
- *(tls)* Add zstd support for chrome models and derivatives (#93)

### 🐛 Bug Fixes

- *(proxy)* Make HTTP(S)_PROXY variables take precedence over ALL_PROXY (#87)
- Fix incorrect Accept-Encoding header combinations in Accepts::as_str (#89)
- *(client)* `headers_order` error
- *(tls)* Fix optional config TLS size version

### 🚜 Refactor

- Change Debug of Error to output url as str (#88)
- Blocking feature doesn't need multi-threaded tokio runtime (#90)
- *(tls)* Major module changes (#91)
- *(websocket)* Major changes, abstract WebSocket message structure (#94)
- Enabling `accept-encoding` will be determined by the feature
- Enabled `accept-encoding` will be determined by the `feature` (#95)

### ⚙️ Miscellaneous Tasks

- Remove unnecessary tls feature

## [0.11.103] - 2024-08-06

### 🚀 Features

- *(client)* Add custom header order support (#83)

### 🚜 Refactor

- *(hickory-dns)* Async `new_resolver` (#84)

## [0.11.102] - 2024-08-05

### 🚀 Features

- *(http2)* Optimize http2 frame order settings (#80)

### 📚 Documentation

- Fix docs build (#81)
- Update docs (#82)

## [0.11.99] - 2024-08-04

### 🚀 Features

- *(impersonate)* Add `Safari17_0` impersonate (#71)
- *(websocket)* Improve websocket upgrade (#73)
- *(connector)* Using session cache to delay initialization of connector (#78)

### 🐛 Bug Fixes

- *(impersonate)* Fix `safari15_3`/`safari15_5` http2 fingerprint (#70)
- *(impersonate)* Fix safari header order (#72)

### ⚙️ Miscellaneous Tasks

- 1.80 as MSRV (#74)

### Deps

- *(percent-encoding)* V2.3 (#75)
- *(boring)* V4.x (#76)

## [0.11.97] - 2024-07-28

### 🐛 Bug Fixes

- *(extension)* Fix configure chrome new curves (#67)

## [0.11.96] - 2024-07-28

### 🚀 Features

- *(impersonate)* Export the Impersonate custom extension configuration (#64)
- *(impersonate)* Reuse Safari cipher list in groups (#65)

### ◀️ Revert

- *(impersonate)* Revert Edge122 configure new curves (#66)

## [0.11.93] - 2024-07-27

### 🚀 Features

- *(impersonate)* Optimize reuse of impersonate configuration (#61)
- *(connect)* Reduce unnecessary connection overhead (#62)

## [0.11.92] - 2024-07-27

### 🚀 Features

- *(connect)* Add PSK extension (#52)
- *(impersonate)* Add Edge_127 impersonate (#59)

### 🐛 Bug Fixes

- *(connector)* Fix TLS session failure when changing address (#55)

### 🚜 Refactor

- Remove unused crates (#54)
- Remove unused crates

### 🎨 Styling

- *(impersonate)* Remove dead code (#51)

### ⚙️ Miscellaneous Tasks

- 1.70 as MSRV (#53)
- 1.70 as MSRV

### Deps

- *(ipnet)* V2.9.0 (#56)
- *(mime)* V0.3.17 (#57)
- *(url)* V2.5 (#58)

## [0.11.91] - 2024-07-25

### 🎨 Styling

- *(connect)* Replace all non-refutable if let patterns with let statements (#44)

### Deps

- *(base64)* Bump version to v0.22.x (#46)
- *(cookie_store)* Bump version to v0.21.x (#47)

## [0.11.90] - 2024-07-25

### 🚀 Features

- *(impersonate)* Optimize TLS connector context handle (#37)

### ◀️ Revert

- *(impersonate)* Remove chrome99 impersonate (#38)

### Build

- *(deps)* Bump softprops/action-gh-release from 1 to 2 (#36)
- *(deps)* Bump actions/checkout from 3 to 4 (#35)

## [0.11.89] - 2024-07-25

### 🚀 Features

- *(client)* Support client proxy settings (#32)
- *(client)* Add ability to set proxies/address after client has been initialised (#34)

## [0.11.88] - 2024-07-09

### 🐛 Bug Fixes

- *(impersonate)* Add Safari17_5 from string

## [0.11.87] - 2024-07-07

### 🚀 Features

- *(impersonate)* Add Safari_17_5 impersonate (#28)
- *(impersonate)* Add Safari_17_5 impersonate

## [0.11.85] - 2024-06-24

### 🚀 Features

- *(impersonate)* Specification version number match
- *(impersonate)* Add Safari_IOS_16_5 impersonate
- *(impersonate)* Add Safari_IOS_17_4_1 impersonate
- Add zstd support

### 🚜 Refactor

- *(impersonate)* Refactor unnecessary settings
- Migrate trust-dns to hickory-dns
- Migrate trust-dns to hickory-dns
- *(impersonate)* Reuse code

### Impersonate

- Bugfix `chrome_123`, `chrome_124` headers

### Impersonate

- Chrome_123, chrome_125 - add `zstd` to Accept-Encoding header
- Add `chrome_126`

## [0.11.78] - 2024-05-08

### 🚀 Features

- *(websocket)* Export `UpgradedRequestBuilder`
- *(websocket)* Export header method
- *(websocket)* Export header method
- *(websocket)* Add upgrade with custom handshake key
- *(impersonate)* Add Chrome124 impersonate

### Deps

- *(tungstenite)* Backport dependencies

## [0.11.71] - 2024-04-30

### 🚀 Features

- *(impersonate)* Add Safari_17_4_1 impersonate

### 🧪 Testing

- Fix test_badssl_no_built_in_roots

## [0.11.69] - 2024-04-10

### 🚀 Features

- *(impersonate)* Add Safari_IOS_17_2 impersonate

## [0.11.68] - 2024-04-10

### 🚀 Features

- *(impersonate)* Improve fingerprint OkHttp fingerprint UserAgent
- *(impersonate)* Add Chrome123 impersonate

## [0.11.65] - 2024-03-05

### 🚀 Features

- *(feature)* Optional enable websocket
- *(impersonate)* Add Edge122 impersonate
- *(impersonate)* Optimize the overhead of parsing request headers at runtime

## [0.11.60] - 2024-02-27

### 🚀 Features

- *(websocket)* Support configuration websocket

## [0.11.52] - 2024-02-27

### 🚀 Features

- *(async/client)* Add try get user agent
- *(impersonate)* Optimize the overhead of parsing request headers at runtime
- *(client)* Support impersonate webSocket

## [0.11.48] - 2024-01-09

### 🚀 Features

- *(impersonate)* Add Edge99 impersonate
- *(impersonate)* Add Edge101 impersonate
- *(impersonate)* Add Safari17_2_1 impersonate

### 🐛 Bug Fixes

- Set nodelay correctly to handle when a tls feature is enabled but connection is to an http server (#2062)

### 📚 Documentation

- Remove redundant link targets (#2019)
- Add cfg notes about http3 builder methods (#2070)

### Deps

- *(hyper)* Bump version to v0.14.33

### Http3

- Upgrade dependencies (#2028)

### Proxy

- Add support for proxy authentication with user-specified header values (#2053)

### Wasm

- Add method `user_agent` to `ClientBuilder`. (#2018)

## [0.11.46] - 2023-12-23

### Deps

- *(boring-sys)* Bump version to v2.0.6

## [0.11.45] - 2023-12-22

### Deps

- *(boring-sys)* Bump version to v2.0.5

## [0.11.43] - 2023-12-21

### 🚀 Features

- *(impersonate)* Add Safari16_5 impersonate

### Deps

- *(boring-sys)* Bump version to v2.0.4

## [0.11.40] - 2023-12-18

### 🚀 Features

- *(impersonate)* Add Chrome117 impersonate

### Deps

- *(boring-sys)* Bump version to v2.0.3

## [0.11.39] - 2023-12-17

### 🚀 Features

- *(impersonate)* Add Chrome120 impersonate
- *(impersonate)* Add Chrome100 impersonate
- *(impersonate)* Add Chrome101 impersonate
- *(impersonate)* Improve safari fingerprint impersonate

### Deps

- *(hyper_imp)* Bump version to v0.14.30

## [0.11.38] - 2023-12-14

### 🚀 Features

- *(impersonate)* Add Chrome v118 Impersonate
- *(connector)* Enable encrypted client hello
- *(client)* Optional enable_ech_grease, only effective for Chrome
- *(client)* Optional enable permute_extensions
- *(impersonate)* Remove max_concurrent_streams for v118
- *(impersonate)* Use the default locations of trusted certificates for verification.
- *(impersonate)* Add Chrome v119 Impersonate
- *(impersonate)* Add Chrome v116 Impersonate
- *(impersonate)* Add Safari 15_3/15_5 Impersonate
- Update safari impersonate
- *(impersonate)* Add Safari15_6_1 impersonate
- *(impersonate)* Add Safari16 impersonate

### 🐛 Bug Fixes

- *(impersonate)* Fix v116 impersonate

## [0.11.30] - 2023-11-11

### 🚀 Features

- *(impersonate)* Add OkHttp3 Impersonate
- *(impersonate)* Add OkHttp5-alpha Impersonate
- *(impersonate)* Support more OkHttp fingerprints
- *(impersonate)* Add Safari 12 Impersonate

### Deps

- *(hyper)* Bump version to v0.14.28

## [0.11.26] - 2023-10-19

### 🚀 Features

- *(impersonate)* Support disable certs verification

## [0.11.25] - 2023-10-19

### 🚜 Refactor

- *(impersonate)* Revert to SslVerifyMode::NONE

## [0.11.24] - 2023-10-19

### 🚀 Features

- *(client)* Support configured IPv4 or IPv6 address (depending on host's preferences) before connection

### 🚜 Refactor

- *(impersonate)* Update SSL verify mode

## [0.11.22] - 2023-10-15

### 🚀 Features

- Set default headers
- Add Response::text()
- *(proxy)* Adds NO_PROXY environment variable support (#877)
- *(multipart)* Adds support for manually setting size
- Enable client to be a service without ownership (#1556)

### 🐛 Bug Fixes

- Tests::support::server
- *(response)* `copy_to()` and `text()` return `reqwest::Result`
- Upgrade to http2 if the server reports that it supports it (#1166)
- Respect https_only option when redirecting (#1313)
- Wasm client: pass response header to builder by reference (#1350)
- Strip BOM in Response::text_with_charset
- Strip BOM in `Response::text_with_charset` (#1898)
- Split connect timeout for multiple IPs (#1940)

### 🚜 Refactor

- Disable ssl verify

### 📚 Documentation

- Make encoding_rs link clickable (#674)
- Build wasm32-unknown-unknown docs (#998)
- Adds amplifying note about private key formats (#1335)
- Fix some typos (#1346)
- Provide basic auth example (#1362)
- Fix some typos (#1531)
- Fix broken doc comment example. (#1584)
- Fix some typos (#1562)
- Fix wording on main docs page (#1765)
- Fix building on docs.rs (#1789)

### 🧪 Testing

- Added some trivial tests for the RequestBuilder
- Fixed up issue with reading a Body and finished RequestBuilder tests
- Use verbose output
- Add tests for setting default headers
- Response::text()
- Add more badssl tests for rustls

### ⚙️ Miscellaneous Tasks

- Update gitignore
- Fix appveyor build for backtrace-sys dependency (#526)
- *(docs)* Fix missing link for 'blocking'
- Update changelog for 0.11.15
- A few simple cleanups/lints (#1849)

### Body

- Don't call poll_ready on tx when 0 bytes remaining. (#479)

### CI

- Check documentation (#1246)
- Make a single final job that depends on all others (#1291)
- Enable dependabot for GitHub Action Workflow (#1831)

### Doc

- `stream` feature is needed for `wrap_stream` and `From<File>` for `Body` (#1456)

### Error

- Add functions to check more error types. (#945)

### Examples

- Allow passing URL via CLI

### Feature

- Auto detect MacOS proxy settings (#1955)

### From<http

- :Response> for Response (#360)

### Lint

- Fix unused `Identity` if only using `default-tls` (#1164)

### Response.copy_to

- Fix docs markup

### WASM

- Set RequestCredentials to None by default (#1249)
- Add `try_clone` implementations to `Request` and `RequestBuilder` (#1286)

### [#1095]

- Implement `basic_auth` for WASM

### Actions

- Remove --all flag from rustfmt (#795)

### Async

- Add conversions from static slices to Body

### Async/client

- Return a impl Future on execute()

### Async/reponse

- Return a impl Future on json()

### Async/request

- Return a impl Future on send()
- Add a basic example for send()
- Add methods to split and reassemble a RequestBuilder (#1770)

### Blocking

- Opt-out CPUs auto-detection in debug mode (#807)
- Add tcp_keepalive option (#1100)

### Boring

- Upgrade latest version

### Boringssl

- Add SSL_set_permute_extensions

### Bug

- Fix custom content-type overidden by json method
- Fix custom content-type overidden by json method (#1833)

### Cargo

- Update to rustls 0.16

### Client

- Add convenience method for DELETE

### Dep

- Upgrade trust-dns-resolver from v0.22 to v0.23 (#1965)

### Dependencies

- Upgrade base64 to latest version (#692)

### Deps

- *(chore)* Update to the latest rustls (#969)
- Update async-compression v0.3.13 => v0.4.0 (#1828)
- Update rustls v0.20.1 -> v0.21.0 (#1791)
- Update winrege 0.10 -> 0.50 (#1869)

### Example

- Update usage doc for blocking example (#1112)

### Fmt

- Wasm body (#1359)

### Http3

- Don't force `webpki` when experiemental `http3` is enabled (#1845)
- Enable `runtime-tokio` for `quinn` (#1846)

### Msrv

- Bump to 1.63 (#1947)

### Multipart

- Force a CRLF at the end of request

### Native-tls

- Add Identiy::from_pkcs8_pem (#1655)

### Proxy

- Refactor a collapsible_match (#1214)

### Request

- Test adding duplicate headers to the request (#519)

### Tmp

- Use upstream git repo for hyper-native-tls

### Wasm

- Translate over response headers (#689)
- Add bytes method to wasm response (#694)
- Add request body in the form of Bytes (#696)
- Add url function to wasm response (#777)
- Add error_for_status to wasm response (#779)
- Impl TryFrom<HttpRequest<T>> for Request (#997)
- Omit request body if it's empty (#1012)
- Avoid dependency on serde-serialize feature (#1337)
- Add missing `as_bytes` method to `Body` implementation (#1270)
- Don't send request body as plain uint8 array (#1358)
- Fix standalone/multipart body conversion to JsValue (#1364)
- Fix premature abort for streaming bodies (#1782)
- Blob url support (#1797)

<!-- generated by git-cliff -->
