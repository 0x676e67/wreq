## [unreleased]

### 🐛 Bug Fixes

- *(rt)* Support fake time in legacy client and TokioTimer ([#1064](https://github.com/0x676e67/wreq/issues/1064)) - ([29acebc](https://github.com/0x676e67/wreq/commit/29acebcdc16b1cec24f0547e6d381e512322edd9))

### ⚡ Performance

- *(error)* Hint compiler to inline trivial error-handling functions ([#1061](https://github.com/0x676e67/wreq/issues/1061)) - ([7746f74](https://github.com/0x676e67/wreq/commit/7746f74c3749116a3e2148a59771c8219077e94b))
- *(http2)* Backport and apply hyper client's H2 configuration ([#1063](https://github.com/0x676e67/wreq/issues/1063)) - ([6e2f160](https://github.com/0x676e67/wreq/commit/6e2f160e6ddc9b59a8e3de64fb487f5a47f428e8))
- *(request)* Static init for common content-type header ([#1060](https://github.com/0x676e67/wreq/issues/1060)) - ([1e45fc5](https://github.com/0x676e67/wreq/commit/1e45fc557721de2d0d483cb00ccc38fe59aeb9a0))
- *(response)* Hint compiler to inline trivial response-handling functions ([#1062](https://github.com/0x676e67/wreq/issues/1062)) - ([be87bb8](https://github.com/0x676e67/wreq/commit/be87bb85646817cdb6c356ae8efa6eec587fac03))

### ⚙️ Miscellaneous Tasks

- *(core)* Clear code - ([9411b19](https://github.com/0x676e67/wreq/commit/9411b19d16d1dee6b66657dc681c96c89394fe6f))
- Fix clippy - ([cf29946](https://github.com/0x676e67/wreq/commit/cf2994669b1be87d3fc5555a5a5179acb54d62d5))

### Bench

- Add benchmarks for HTTP/1.1 and HTTP/2 ([#1065](https://github.com/0x676e67/wreq/issues/1065)) - ([71fb97a](https://github.com/0x676e67/wreq/commit/71fb97a6a19065e6655875ee3811deaa9c3ae429))


## [6.0.0-rc.28](https://github.com/0x676e67/wreq/compare/v6.0.0-rc.27..v6.0.0-rc.28) - 2026-02-11

### 🐛 Bug Fixes

- *(http1)* Use case-insensitive matching for trailer fields ([#1059](https://github.com/0x676e67/wreq/issues/1059)) - ([1b7d57b](https://github.com/0x676e67/wreq/commit/1b7d57bce1fcc7e471ba383a5b0c14fcc926d1de))

### ⚡ Performance

- *(request)* Reduce overhead by lazy-loading headers for `json`/`form` data ([#1058](https://github.com/0x676e67/wreq/issues/1058)) - ([6992b6f](https://github.com/0x676e67/wreq/commit/6992b6ffd69bf61f710d97d97b436d630e38cbe7))


## [6.0.0-rc.27](https://github.com/0x676e67/wreq/compare/v6.0.0-rc.26..v6.0.0-rc.27) - 2026-01-17

### ⛰️  Features

- *(cookie)* Consolidate cookie methods into a unified add() ([#1043](https://github.com/0x676e67/wreq/issues/1043)) - ([59999e6](https://github.com/0x676e67/wreq/commit/59999e613305e8aa8e13150cec858525b9f4cb6f))
- *(tls)* Add peer certificate chain to `TlsInfo` ([#1049](https://github.com/0x676e67/wreq/issues/1049)) - ([f27cb78](https://github.com/0x676e67/wreq/commit/f27cb789c8db32ca4fd0bc4e6d8e007307639ba6))

### 🐛 Bug Fixes

- *(verbose)* Correct connection verbose tracing ([#1055](https://github.com/0x676e67/wreq/issues/1055)) - ([22516ae](https://github.com/0x676e67/wreq/commit/22516ae9f1a4becf3827e1ba9889a6add59e38b6))

### 🚜 Refactor

- *(redirect)* Expose `Attempt` fields as public API ([#1046](https://github.com/0x676e67/wreq/issues/1046)) - ([b97fa4f](https://github.com/0x676e67/wreq/commit/b97fa4fac5530fb455777db986f2f31f8719a6ad))

### ⚡ Performance

- *(redirect)* Use static `HeaderName` for `cookie2` to avoid allocation ([#1047](https://github.com/0x676e67/wreq/issues/1047)) - ([0211cad](https://github.com/0x676e67/wreq/commit/0211cad5595220095179c0045aff1c3a76690a1e))
- *(tls)* Use `Bytes` for `peer_certificate` to enable cheap cloning ([#1050](https://github.com/0x676e67/wreq/issues/1050)) - ([27c8e74](https://github.com/0x676e67/wreq/commit/27c8e74936e6eff30761954f3e9f4133b08f611b))

### 🎨 Styling

- *(cookie)* Prefer `dt <= SystemTime::now()` in expires check ([#1045](https://github.com/0x676e67/wreq/issues/1045)) - ([5da3114](https://github.com/0x676e67/wreq/commit/5da3114e749b6a7a0aeb0f8cdd72759bc1a216d5))
- *(cookie)* Prefer `Duration::is_zero()` in Max-Age=0 check ([#1044](https://github.com/0x676e67/wreq/issues/1044)) - ([1e607dd](https://github.com/0x676e67/wreq/commit/1e607dd0b0d9822dfc9873d7a2e0093defc6b445))

### ⚙️ Miscellaneous Tasks

- *(test)* Fix windows tests ([#1042](https://github.com/0x676e67/wreq/issues/1042)) - ([a22ca01](https://github.com/0x676e67/wreq/commit/a22ca01315ab62659a1498f3d157fb767cdeb828))

### Build

- *(deps)* Add `prefix-symbols` to resolve `OpenSSL` symbol conflicts ([#1056](https://github.com/0x676e67/wreq/issues/1056)) - ([9c40d0f](https://github.com/0x676e67/wreq/commit/9c40d0ff294ae6d15477284c205607147361c90a))
- *(deps)* Bump `url` dependency version to 2.5.8 ([#1053](https://github.com/0x676e67/wreq/issues/1053)) - ([f0ba09e](https://github.com/0x676e67/wreq/commit/f0ba09e08fbd24a4736b256ef87a1f10da3c0754))
- *(deps)* Update `http2` dependency version to 0.5.11 ([#1051](https://github.com/0x676e67/wreq/issues/1051)) - ([0ccc4e8](https://github.com/0x676e67/wreq/commit/0ccc4e8e6db4885dada569ecf161bf5104d8a37f))

## New Contributors ❤️

* @Abernson made their first contribution in [#1049](https://github.com/0x676e67/wreq/pull/1049)

## [6.0.0-rc.26](https://github.com/0x676e67/wreq/compare/v6.0.0-rc.25..v6.0.0-rc.26) - 2025-12-31

### ⛰️  Features

- Add `query` and `form` crate features ([#1035](https://github.com/0x676e67/wreq/issues/1035)) - ([091b9e9](https://github.com/0x676e67/wreq/commit/091b9e9e93fef8bc838910dc383a3fb6bdcb8778))

### 🐛 Bug Fixes

- *(proxy)* Skip proxy headers for HTTPS destinations ([#1039](https://github.com/0x676e67/wreq/issues/1039)) - ([972737f](https://github.com/0x676e67/wreq/commit/972737f540150819d9659cb17e8cdc097dbb078f))
- *(redirect)* Fix redirect `location` encoding ([#1034](https://github.com/0x676e67/wreq/issues/1034)) - ([f8e2114](https://github.com/0x676e67/wreq/commit/f8e21143abe06f7ae65d26d3ffb979433fcfe394))

### 🚜 Refactor

- *(header)* Hide internal details of `OrigHeaderName` ([#1036](https://github.com/0x676e67/wreq/issues/1036)) - ([5424935](https://github.com/0x676e67/wreq/commit/5424935235270cead6c5f2e9a7f59a5398ad001c))

### ⚡ Performance

- *(proxy)* Improve proxy credential handling for concurrent requests ([#1041](https://github.com/0x676e67/wreq/issues/1041)) - ([4016d1b](https://github.com/0x676e67/wreq/commit/4016d1bfeb7b24122ecdc0906129e65841c3700c))
- *(uri)* Improve `String` to `Uri` conversion performance ([#1038](https://github.com/0x676e67/wreq/issues/1038)) - ([fcd5cc5](https://github.com/0x676e67/wreq/commit/fcd5cc54a7d3d0d0c2d3575af6f8c6ea1f0fdabe))

### ⚙️ Miscellaneous Tasks

- *(redirect)* Remove macros - ([c92fbaf](https://github.com/0x676e67/wreq/commit/c92fbaf87d33c11d681c7d47c09a54d47b2674fb))

## New Contributors ❤️

* @blinjrm made their first contribution in [#1039](https://github.com/0x676e67/wreq/pull/1039)

## [6.0.0-rc.25](https://github.com/0x676e67/wreq/compare/v6.0.0-rc.23..v6.0.0-rc.25) - 2025-12-23

### ⛰️  Features

- *(cookie)* Refactor `CookieStore` cookie compression strategy ([#1005](https://github.com/0x676e67/wreq/issues/1005)) - ([2dc14cd](https://github.com/0x676e67/wreq/commit/2dc14cd9207d0c1cb41583395a7f544acb40aadf))
- *(error)* Add `is_proxy_connect` for proxy connection errors ([#1014](https://github.com/0x676e67/wreq/issues/1014)) - ([0578465](https://github.com/0x676e67/wreq/commit/0578465eb64a23b2d47fb7080ea372646c4783d6))
- *(proxy)* Compatibility for sending HTTP requests without HTTPS tunneling ([#991](https://github.com/0x676e67/wreq/issues/991)) - ([bd1d58b](https://github.com/0x676e67/wreq/commit/bd1d58bcf3b87924486b9515f6f678dc8ca36800))
- *(redirect)* Add async support to redirect policy ([#996](https://github.com/0x676e67/wreq/issues/996)) - ([bc6f113](https://github.com/0x676e67/wreq/commit/bc6f11376d884dcd614889861bb55157907cdab7))
- *(response)* Introduce trailers support ([#1021](https://github.com/0x676e67/wreq/issues/1021)) - ([28bcc63](https://github.com/0x676e67/wreq/commit/28bcc63cb0e9083c944d55ca3895ee70a1ed636b))

### 🐛 Bug Fixes

- *(proxy)* Improve domain matching case insensitivity ([#1031](https://github.com/0x676e67/wreq/issues/1031)) - ([87f9019](https://github.com/0x676e67/wreq/commit/87f90191bbb5fe39174ab2777b4d526145f2e75c))
- *(proxy)* Fix HTTP requests proxied through an `SOCKS5`/`HTTPS tunnel` ([#990](https://github.com/0x676e67/wreq/issues/990)) - ([7207dd5](https://github.com/0x676e67/wreq/commit/7207dd55989f9ef2d3577261928252b5dc90f206))
- *(redirect)* Ensure redirect URLs are properly encoded ([#1017](https://github.com/0x676e67/wreq/issues/1017)) - ([8ad5023](https://github.com/0x676e67/wreq/commit/8ad5023932b480c1cf94d8bbddc9bb2b59a83d6c))
- *(request)* Fix missing `http::Request` conversion extensions ([#1000](https://github.com/0x676e67/wreq/issues/1000)) - ([9df5f14](https://github.com/0x676e67/wreq/commit/9df5f14f3657692ae19691105826d30c23056996))
- *(test)* Fix decompression test ([#998](https://github.com/0x676e67/wreq/issues/998)) - ([54f5ee6](https://github.com/0x676e67/wreq/commit/54f5ee63877e5ec3ef04167dcdb25b1025a0b2f7))

### 🚜 Refactor

- *(config)* Simplify extension config type wrappers ([#1009](https://github.com/0x676e67/wreq/issues/1009)) - ([adf84e3](https://github.com/0x676e67/wreq/commit/adf84e38abaa921f10a3994920bbe494bafc608a))
- *(core)* Use flat module style - ([30a8c13](https://github.com/0x676e67/wreq/commit/30a8c135c26bc4853c24f3a5209b6ad098a4f74a))
- *(decoder)* Reorder decoder tower layers ([#1026](https://github.com/0x676e67/wreq/issues/1026)) - ([910378d](https://github.com/0x676e67/wreq/commit/910378d9965cd11a9d0c9bf0478428d1f200802d))
- *(ext)* Remove extension wrapper types ([#999](https://github.com/0x676e67/wreq/issues/999)) - ([15b4866](https://github.com/0x676e67/wreq/commit/15b48664364a436d863b5f94881d6e36402b7f10))
- *(mod)* Use flat module style and merge legacy client ([#993](https://github.com/0x676e67/wreq/issues/993)) - ([75db3ea](https://github.com/0x676e67/wreq/commit/75db3eaa3b63d52580cef711cd2b3a5960d3850d))
- *(proxy)* Use flat module style - ([0925369](https://github.com/0x676e67/wreq/commit/0925369c903046ae745bba8eb7330ae2086fa4b7))
- *(redirect)* Refactor handling of redirect history ([#1002](https://github.com/0x676e67/wreq/issues/1002)) - ([b1ce184](https://github.com/0x676e67/wreq/commit/b1ce184b901aa5f1d11eb1af4dd6b02dffedfed6))

### 📚 Documentation

- *(proxy)* Fix docs prompt ([#1010](https://github.com/0x676e67/wreq/issues/1010)) - ([989e691](https://github.com/0x676e67/wreq/commit/989e6910014124cc579eabd372a34ea665d37c63))
- Update documentation for `Request` and `RequestBuilder` - ([e30b393](https://github.com/0x676e67/wreq/commit/e30b3932323f23e902ae97d0178d1409ff2ef290))
- Fix documentation build warning ([#1008](https://github.com/0x676e67/wreq/issues/1008)) - ([303c54e](https://github.com/0x676e67/wreq/commit/303c54eba89e4cd2252da3a986710ad330034da8))

### ⚡ Performance

- *(client)* Reduce one `HeaderMap` clone during header merge ([#987](https://github.com/0x676e67/wreq/issues/987)) - ([ce030b8](https://github.com/0x676e67/wreq/commit/ce030b8c3ba6bb233775fad271e1ecff49a95a61))
- *(ext)* Update query handling to avoid copying ([#1007](https://github.com/0x676e67/wreq/issues/1007)) - ([be0366f](https://github.com/0x676e67/wreq/commit/be0366fb656cdffde5504c0354ebff36a65a34b2))
- *(proxy)* Reduce branch matching ([#992](https://github.com/0x676e67/wreq/issues/992)) - ([ed00aec](https://github.com/0x676e67/wreq/commit/ed00aec00371097810d634901bd648dc990041f5))
- *(redirect)* Avoid cloning inner service for non-redirect requests ([#1028](https://github.com/0x676e67/wreq/issues/1028)) - ([7933341](https://github.com/0x676e67/wreq/commit/79333414a4c6a83e35356ab68ea301b0976472f4))

### 🎨 Styling

- *(connector)* Fmt code - ([8a15bf4](https://github.com/0x676e67/wreq/commit/8a15bf418c902ada7975976d5278d20487535831))
- *(layer)* Use flat module style ([#1027](https://github.com/0x676e67/wreq/issues/1027)) - ([519e4ca](https://github.com/0x676e67/wreq/commit/519e4ca6c3ceba8e355838fb2ba0a359ddb3feff))
- Fmt code - ([53df061](https://github.com/0x676e67/wreq/commit/53df061e44f049c38de1d63b1ef2077070eea7fe))
- Fmt code - ([c15fc08](https://github.com/0x676e67/wreq/commit/c15fc08abc9210bcd98460e112e3fc746b39e748))

### 🧪 Testing

- *(response)* Remove duplicate tests - ([7c1df27](https://github.com/0x676e67/wreq/commit/7c1df27efecb5f0a5abdaeec33d5f2bf9a885610))

### ⚙️ Miscellaneous Tasks

- *(body)* Remove `Debug` trait implementation for Body - ([72aea5e](https://github.com/0x676e67/wreq/commit/72aea5eb8e48fc2c561b0b4718f8a4654d0d31cf))
- *(body)* Remove unnecessary `cfg_attr` for stream feature - ([9c698b3](https://github.com/0x676e67/wreq/commit/9c698b38088529c9d79c293f41b3697a784b5b7a))
- *(body)* Simplify body construction ([#1020](https://github.com/0x676e67/wreq/issues/1020)) - ([7116f11](https://github.com/0x676e67/wreq/commit/7116f11e0e80ad9651b6f19ced93c2ac8a4d3731))
- *(decoder)* Add debug assertion for decoder presence - ([977a7ba](https://github.com/0x676e67/wreq/commit/977a7ba80ff4080a19460f8c74908eac509084e6))
- *(layer)* Move body timeout layer to the outermost layer ([#1032](https://github.com/0x676e67/wreq/issues/1032)) - ([294e9d8](https://github.com/0x676e67/wreq/commit/294e9d8b4b257eb69ad23e7f1b0508ff5c6a8442))
- *(multipart)* Remove custom `Debug` trait implementations - ([4512913](https://github.com/0x676e67/wreq/commit/45129134b0c67dafb26fc2038f8fd9a4dc92b4ca))
- *(req/resp)* Fmt docs ([#1022](https://github.com/0x676e67/wreq/issues/1022)) - ([d395827](https://github.com/0x676e67/wreq/commit/d39582730c9d92cdb76e133648a4582511bac647))
- *(request)* Simplify request construction ([#1018](https://github.com/0x676e67/wreq/issues/1018)) - ([2b044fb](https://github.com/0x676e67/wreq/commit/2b044fbb8b748418b3dfd551c8b9b3ba629b5529))
- *(request)* Fmt code - ([32fa617](https://github.com/0x676e67/wreq/commit/32fa61771646a1c1c22cb205e94016006b87232a))
- *(response)* Remove `Debug` implementation for `Response` - ([51f86a5](https://github.com/0x676e67/wreq/commit/51f86a56bb35ca317a108796430e97cfe386bb0f))
- *(response)* Simplify response construction ([#1016](https://github.com/0x676e67/wreq/issues/1016)) - ([08a8066](https://github.com/0x676e67/wreq/commit/08a8066d690a2b902017a5ed9598c4e6972ca57c))
- *(style)* Fmt code - ([9f1fd12](https://github.com/0x676e67/wreq/commit/9f1fd12f4af694be89ca2c4e0a8f054ab4e6a310))
- Add MSRV job to CI workflow - ([681a763](https://github.com/0x676e67/wreq/commit/681a763eeac5bd75f29868d5907f72d0d8033e8e))
- Use `http_body_util::BodyDataStream` ([#1015](https://github.com/0x676e67/wreq/issues/1015)) - ([75baf44](https://github.com/0x676e67/wreq/commit/75baf44b84bccb3236e8d1b13249d61e344a4b44))
- Remove cmake pinning from Windows CI step - ([87fc1f6](https://github.com/0x676e67/wreq/commit/87fc1f69989101ac412e4e8e585a4d2a5dfb1073))
- Add Android NDK tests ([#1011](https://github.com/0x676e67/wreq/issues/1011)) - ([adab15a](https://github.com/0x676e67/wreq/commit/adab15ac1c02411470f914311e299fc84ee3772f))

### ◀️ Revert

- *(request)* Restore upstream header insertion strategy ([#995](https://github.com/0x676e67/wreq/issues/995)) - ([00c1d6d](https://github.com/0x676e67/wreq/commit/00c1d6d98d760512885270fa5211769ce311fc2a))

### Build

- *(deps)* Update `system-configuration` version to 0.7.0 ([#1024](https://github.com/0x676e67/wreq/issues/1024)) - ([040fc99](https://github.com/0x676e67/wreq/commit/040fc9942ab677a56d9432910db181ec181904f6))
- *(deps)* Bump actions/checkout from 5 to 6 ([#1023](https://github.com/0x676e67/wreq/issues/1023)) - ([814b9c8](https://github.com/0x676e67/wreq/commit/814b9c880727def1f6cf1586526971d91a473a4f))
- Cargo diet - ([f0d1ea1](https://github.com/0x676e67/wreq/commit/f0d1ea18226b46185106e9d096acd542ee39a454))


## [6.0.0-rc.23](https://github.com/0x676e67/wreq/compare/v6.0.0-rc.22..v6.0.0-rc.23) - 2025-11-28

### 🐛 Bug Fixes

- *(client)* Handle multi-value default headers without overriding requests ([#986](https://github.com/0x676e67/wreq/issues/986)) - ([745fa26](https://github.com/0x676e67/wreq/commit/745fa265a99a857c394226f4d2b64f7783813d17))
- *(test)* Fix decompression empty body test ([#979](https://github.com/0x676e67/wreq/issues/979)) - ([9e11af1](https://github.com/0x676e67/wreq/commit/9e11af143fc452e65a42cd720138b96c7433ffd4))

### 🚜 Refactor

- *(http1)* Replace many args of `Chunked::step` with struct - ([6ffef6c](https://github.com/0x676e67/wreq/commit/6ffef6ca138f341340aa4f2086fdbca009ca301e))
- Change fast_random from xorshift to siphash a counter ([#983](https://github.com/0x676e67/wreq/issues/983)) - ([a386091](https://github.com/0x676e67/wreq/commit/a38609107949bc88e2dd38a0978bde91f8684b38))

### Build

- *(deps)* Bump actions/checkout from 5 to 6 ([#978](https://github.com/0x676e67/wreq/issues/978)) - ([81d8d82](https://github.com/0x676e67/wreq/commit/81d8d82f811d60a71f6a5e0eff712134dfd15f80))

### Deps

- Update tokio-tungstenite version to 0.28.0 ([#982](https://github.com/0x676e67/wreq/issues/982)) - ([cf8a71e](https://github.com/0x676e67/wreq/commit/cf8a71ea6957ccd40beda136678954787fcab9db))


## [6.0.0-rc.22](https://github.com/0x676e67/wreq/compare/v6.0.0-rc.21..v6.0.0-rc.22) - 2025-11-21

### ⛰️  Features

- *(rt)* Add Timer::now() method to allow overriding the instant returned ([#976](https://github.com/0x676e67/wreq/issues/976)) - ([7cf3b95](https://github.com/0x676e67/wreq/commit/7cf3b95f8f445aff46ddd6455e0afaadb72bba36))

### 🐛 Bug Fixes

- *(http1)* Fix rare missed write wakeup on connections ([#974](https://github.com/0x676e67/wreq/issues/974)) - ([d6bccef](https://github.com/0x676e67/wreq/commit/d6bccefe0e7d474e9bb1a375a3707326fa5db9a4))
- *(proxy)* Fix 407 proxy auth failures for HTTP requests ([#975](https://github.com/0x676e67/wreq/issues/975)) - ([df67842](https://github.com/0x676e67/wreq/commit/df6784232b9f3b146c872ecb8606336ad2a06256))

### ⚡ Performance

- *(uri)* Avoid double copying during URI percent encoding ([#977](https://github.com/0x676e67/wreq/issues/977)) - ([6a1a406](https://github.com/0x676e67/wreq/commit/6a1a406d6f12eb3baf320a435330256b71bf8cf3))

### ⚙️ Miscellaneous Tasks

- *(client)* Refactor proxy auth handling logic - ([e54df35](https://github.com/0x676e67/wreq/commit/e54df351be60c6957759f82c3ca6861aca31db33))


## [6.0.0-rc.21](https://github.com/0x676e67/wreq/compare/v6.0.0-rc.20..v6.0.0-rc.21) - 2025-11-07

### ⛰️  Features

- *(uri)* Percent-encode spaces when building request URLs ([#972](https://github.com/0x676e67/wreq/issues/972)) - ([de1c937](https://github.com/0x676e67/wreq/commit/de1c9379c101764e1dc5f32d300154edec7f89f6))

### 🐛 Bug Fixes

- *(proxy)* Support proxy auth where password is omitted ([#971](https://github.com/0x676e67/wreq/issues/971)) - ([f7ffd56](https://github.com/0x676e67/wreq/commit/f7ffd565b8129007b2ee8ccd756f0ccf248decef))

### 🚜 Refactor

- *(dns)* Redesign DNS API for improved ergonomics and functionality ([#968](https://github.com/0x676e67/wreq/issues/968)) - ([9c3c3f5](https://github.com/0x676e67/wreq/commit/9c3c3f50fe4249be3a1a878d5ad24506bf7778f1))
- *(proxy)* Consolidate platform-specific modules into mod.rs ([#956](https://github.com/0x676e67/wreq/issues/956)) - ([99d3ed7](https://github.com/0x676e67/wreq/commit/99d3ed74ce0c520baba77301a3a6da20701b550c))

### 📚 Documentation

- *(retry)* Fix typo ([#957](https://github.com/0x676e67/wreq/issues/957)) - ([ed5fef2](https://github.com/0x676e67/wreq/commit/ed5fef2a18f473b770799abfa64c092529ebf74d))

### ⚡ Performance

- *(connector)* Disable Nagle's algorithm for TLS handshake ([#955](https://github.com/0x676e67/wreq/issues/955)) - ([35f4265](https://github.com/0x676e67/wreq/commit/35f426502dada4e4fb245048feccd3b6762f0ea0))

### 🧪 Testing

- *(redirect)* Improve redirect cookie tests ([#963](https://github.com/0x676e67/wreq/issues/963)) - ([852f280](https://github.com/0x676e67/wreq/commit/852f28059719f3e485e58e9b92f2591466d0f342))

### ⚙️ Miscellaneous Tasks

- *(connector)* Fmt code - ([00fa021](https://github.com/0x676e67/wreq/commit/00fa021349eec058456e2e51ed6b01ab72eedecf))
- *(dcos)* Improve API docs ([#954](https://github.com/0x676e67/wreq/issues/954)) - ([10eabd7](https://github.com/0x676e67/wreq/commit/10eabd775aacce16a8e0a616c5919124bb5456ef))
- Update docs - ([9c08747](https://github.com/0x676e67/wreq/commit/9c0874711a10b5d68ee6710218dac4ee3a07d982))
- Fix style check ([#959](https://github.com/0x676e67/wreq/issues/959)) - ([6c3c02b](https://github.com/0x676e67/wreq/commit/6c3c02bab811893de65b599a8fc75fd50dadd103))

### Build

- *(deps)* Update windows-registry requirement from 0.5.0 to 0.6.0 ([#962](https://github.com/0x676e67/wreq/issues/962)) - ([b51a8fb](https://github.com/0x676e67/wreq/commit/b51a8fbfb5b9f6e3c235ce389926021236e57386))


## [6.0.0-rc.20](https://github.com/0x676e67/wreq/compare/v6.0.0-rc.16..v6.0.0-rc.20) - 2025-09-19

### 🚜 Refactor

- *(tls)* Replace `prefer_chacha20` with `preserve_tls13_cipher_list` ([#953](https://github.com/0x676e67/wreq/issues/953)) - ([3d4f61d](https://github.com/0x676e67/wreq/commit/3d4f61d1135c066df07073899c1cfe81c1fcf961))


## [6.0.0-rc.16](https://github.com/0x676e67/wreq/compare/v6.0.0-rc.15..v6.0.0-rc.16) - 2025-09-17

### ⛰️  Features

- *(ws)* Implement `FusedStream` trait for WebSocket ([#949](https://github.com/0x676e67/wreq/issues/949)) - ([d292ef7](https://github.com/0x676e67/wreq/commit/d292ef799a4dfac4500f5ccd785e3fdebeecbe7c))

### 🐛 Bug Fixes

- *(client)* Allow absolute-form if is_proxied is set even on HTTPS ([#945](https://github.com/0x676e67/wreq/issues/945)) - ([0df02e1](https://github.com/0x676e67/wreq/commit/0df02e1c8db43cd94e32541ce0e24b3966441804))
- *(error)* Drop leftover debug logging ([#948](https://github.com/0x676e67/wreq/issues/948)) - ([3f73ae6](https://github.com/0x676e67/wreq/commit/3f73ae688bd7acd8a7292eb2a5a6ab7b9892de3b))
- *(http2)* Fix chained calls ([#952](https://github.com/0x676e67/wreq/issues/952)) - ([a1765dc](https://github.com/0x676e67/wreq/commit/a1765dce6403ea037769331bf51e520f13b7f024))

### 🚜 Refactor

- *(ws)* Improve close method API ergonomics ([#947](https://github.com/0x676e67/wreq/issues/947)) - ([de9e36b](https://github.com/0x676e67/wreq/commit/de9e36b98e1d372d658c55eeb2cc324d67177b06))

### ⚙️ Miscellaneous Tasks

- *(client)* Fmt code - ([ccc54f7](https://github.com/0x676e67/wreq/commit/ccc54f7cb0805749fac896d3e388383916cf1200))
- *(examples)* Remove tracing logs from examples - ([dae70b4](https://github.com/0x676e67/wreq/commit/dae70b4320372c00387a2090ba34099ca1e22246))
- *(examples)* Change HTTP client to use wreq with proxy - ([ba92b95](https://github.com/0x676e67/wreq/commit/ba92b95a913811f7979ff8e51239390c2c62f3d4))


## [6.0.0-rc.15](https://github.com/0x676e67/wreq/compare/v6.0.0-rc.14..v6.0.0-rc.15) - 2025-09-12

### ⛰️  Features

- *(http1)* Remove `preserve_header_case` support ([#943](https://github.com/0x676e67/wreq/issues/943)) - ([fd59127](https://github.com/0x676e67/wreq/commit/fd59127a8afebc42adf4e7eb40faaf792377e62b))
- *(retry)* Introduce configurable retry policy ([#935](https://github.com/0x676e67/wreq/issues/935)) - ([f4644d8](https://github.com/0x676e67/wreq/commit/f4644d8a08545de19638abd80484210190f123f2))

### 🚜 Refactor

- *(ext)* Introduce ergonomic and functional API ([#942](https://github.com/0x676e67/wreq/issues/942)) - ([52709b3](https://github.com/0x676e67/wreq/commit/52709b3dc3b3c7a756bb370c8efc31dba86f2fc9))
- *(keylog)* Redesign API for better ergonomics and functionality ([#941](https://github.com/0x676e67/wreq/issues/941)) - ([7845b9b](https://github.com/0x676e67/wreq/commit/7845b9b9d6c3c31cda3c52f573a1446e710710d7))

### 🧪 Testing

- *(client)* Update header tests and examples ([#939](https://github.com/0x676e67/wreq/issues/939)) - ([bfb8739](https://github.com/0x676e67/wreq/commit/bfb8739b0c0a03e06e54d9c68f7783ca1415b0a3))

### ⚙️ Miscellaneous Tasks

- *(internal)* Remove unnecessary `Debug` bounds - ([4aa1088](https://github.com/0x676e67/wreq/commit/4aa1088888ba8fe4e64a2ff7cf874b1d0174b154))
- *(response)* Drop `Uri::try_from` in From<http::Response<T>> - ([9e16fba](https://github.com/0x676e67/wreq/commit/9e16fba5e1be1bf95b9b06ad16e0a9858c0b60c2))
- *(retry)* Remove unused code - ([147fe60](https://github.com/0x676e67/wreq/commit/147fe60d5c62048b064e7896d90e96011383ffa9))
- *(sync)* Remove unused code ([#940](https://github.com/0x676e67/wreq/issues/940)) - ([a17f799](https://github.com/0x676e67/wreq/commit/a17f79957e722589b6e122f54fae2f1a82893c5b))


## [6.0.0-rc.14](https://github.com/0x676e67/wreq/compare/v6.0.0-rc.13..v6.0.0-rc.14) - 2025-09-05

### 🐛 Bug Fixes

- *(client)* Ensure `Accept-Encoding` header is applied correctly ([#928](https://github.com/0x676e67/wreq/issues/928)) - ([f9f9331](https://github.com/0x676e67/wreq/commit/f9f9331ca28f07fd1d5ad4067d297c66dfe013c1))

### 🚜 Refactor

- *(client)* Enforce `ClientBuilder` initialization via `Client::builder()` ([#932](https://github.com/0x676e67/wreq/issues/932)) - ([513e6f5](https://github.com/0x676e67/wreq/commit/513e6f56169ba357c8d830d77745092d1a90750c))
- *(response)* Accept AsRef<str> for charset for better ([#934](https://github.com/0x676e67/wreq/issues/934)) - ([b95e3b5](https://github.com/0x676e67/wreq/commit/b95e3b5791b983b436c892569a1d3a678999ed26))

### ⚡ Performance

- *(client)* Prevent header duplication by reordering layers ([#930](https://github.com/0x676e67/wreq/issues/930)) - ([ca72a53](https://github.com/0x676e67/wreq/commit/ca72a5341e0ca7d0afe187d1fcd63e1ce1895596))
- *(client)* Avoid redundant header copy ([#929](https://github.com/0x676e67/wreq/issues/929)) - ([c0d8df7](https://github.com/0x676e67/wreq/commit/c0d8df7c1b8d4dfb002dc6bf6ff417ba67f2d587))

### ⚙️ Miscellaneous Tasks

- *(client)* Speed up client initialization ([#931](https://github.com/0x676e67/wreq/issues/931)) - ([be90796](https://github.com/0x676e67/wreq/commit/be90796bda2c481c773c9c93e26420da92faa932))
- *(test)* Fmt code - ([f5ab83c](https://github.com/0x676e67/wreq/commit/f5ab83cfb4d28518dab06e63d28c6f234bfd590f))
- *(tests)* Fmt code ([#933](https://github.com/0x676e67/wreq/issues/933)) - ([86ee4e3](https://github.com/0x676e67/wreq/commit/86ee4e3343466f0284837d4bec6429f28620fc1a))


## [6.0.0-rc.13](https://github.com/0x676e67/wreq/compare/v6.0.0-rc.12..v6.0.0-rc.13) - 2025-09-02

### 🐛 Bug Fixes

- *(cookie)* Normalize host handling with port ([#926](https://github.com/0x676e67/wreq/issues/926)) - ([66368be](https://github.com/0x676e67/wreq/commit/66368be48fd8437c1f2c8cd3ef9e7f0f8432a245))

### 🎨 Styling

- *(redirect)* Fmt code - ([db195ef](https://github.com/0x676e67/wreq/commit/db195efaedd4232cf27c4161414de64c4898b1fe))


## [6.0.0-rc.12](https://github.com/0x676e67/wreq/compare/v6.0.0-rc.11..v6.0.0-rc.12) - 2025-09-02

### ⛰️  Features

- *(lib)* Introduce request shortcut ([#924](https://github.com/0x676e67/wreq/issues/924)) - ([ad6b79d](https://github.com/0x676e67/wreq/commit/ad6b79d0042df52e0e1c418a66a66760308837ac))


## [6.0.0-rc.11](https://github.com/0x676e67/wreq/compare/v6.0.0-rc.9..v6.0.0-rc.11) - 2025-08-31

### ⛰️  Features

- *(tls)* Allow custom ALPN configuration ([#921](https://github.com/0x676e67/wreq/issues/921)) - ([9edfd54](https://github.com/0x676e67/wreq/commit/9edfd54732bae3fd98510d307c4320f48bf44a6d))

### 🐛 Bug Fixes

- *(cookie)* Fix cookie deletion and lookup logic ([#923](https://github.com/0x676e67/wreq/issues/923)) - ([e6014ef](https://github.com/0x676e67/wreq/commit/e6014ef049826062e305e475e10e4c142980a3d5))

### 📚 Documentation

- *(tls)* Refine `TlsOptions` field documentation ([#922](https://github.com/0x676e67/wreq/issues/922)) - ([2b42c9c](https://github.com/0x676e67/wreq/commit/2b42c9c3b43b3aabaed6d1c66b0f0bc21070cd48))
- *(tls)* Update module docs ([#920](https://github.com/0x676e67/wreq/issues/920)) - ([04c1258](https://github.com/0x676e67/wreq/commit/04c12583c67f0205e5dfd049db19316acbc32cce))

### ⚙️ Miscellaneous Tasks

- *(tls)* Streamline conn module type re-exports - ([362c12a](https://github.com/0x676e67/wreq/commit/362c12a50956eb3955a5a6735ebd0bfac39b1e8b))
- *(tls)* Remove ext & cert compression wrappers ([#918](https://github.com/0x676e67/wreq/issues/918)) - ([d9c3e84](https://github.com/0x676e67/wreq/commit/d9c3e8420075f8f6feca0f1725728f0cc25603aa))


## [6.0.0-rc.9](https://github.com/0x676e67/wreq/compare/v6.0.0-rc.8..v6.0.0-rc.9) - 2025-08-30

### ⛰️  Features

- *(cookie)* Improve `cookie_provider` for better ergonomics and flexibility ([#895](https://github.com/0x676e67/wreq/issues/895)) - ([70dd6d9](https://github.com/0x676e67/wreq/commit/70dd6d9d13181b252ce8b69ba807fd5b7b9a15a4))
- *(dns)* Export `IntoResolve` as public API ([#913](https://github.com/0x676e67/wreq/issues/913)) - ([b1b6278](https://github.com/0x676e67/wreq/commit/b1b6278830e20496e965cdbb9adca7d03974f928))
- *(lib)* Add shortcut request methods ([#903](https://github.com/0x676e67/wreq/issues/903)) - ([03cce5e](https://github.com/0x676e67/wreq/commit/03cce5e87dfc9fc77d7ce8eb10bcb60069a3114e))
- *(proxy)* Add Unix socket proxy support ([#900](https://github.com/0x676e67/wreq/issues/900)) - ([d60a6f3](https://github.com/0x676e67/wreq/commit/d60a6f30b0d299f2f1e44f79ec5f9b6cdf94bddf))
- *(redirect)* Support accessing redirect history in response  ([#917](https://github.com/0x676e67/wreq/issues/917)) - ([46278eb](https://github.com/0x676e67/wreq/commit/46278eb6a38b48a75803cf7b49161690d0b90161))
- *(redirect)* Allow custom redirects to access response headers ([#916](https://github.com/0x676e67/wreq/issues/916)) - ([7a1c86a](https://github.com/0x676e67/wreq/commit/7a1c86abab7d835a5da92b2573d7e5ef71ff6980))
- *(response)* Preserve URL when converting `Response` to `http::Response` ([#897](https://github.com/0x676e67/wreq/issues/897)) - ([72b24c7](https://github.com/0x676e67/wreq/commit/72b24c7284d21af2bfbfcc0bcdbac9bc20a5feac))
- *(ws)* Remove Utf8Bytes::from_bytes_unchecked, unsafe UTF-8 ([#912](https://github.com/0x676e67/wreq/issues/912)) - ([e6b8bcf](https://github.com/0x676e67/wreq/commit/e6b8bcfd33ec6a70cf705da1665ca6d15cae520e))

### 🚜 Refactor

- *(connect)* Safely convert `socket2::Socket` to Tokio `TcpSocket` ([#904](https://github.com/0x676e67/wreq/issues/904)) - ([2461be9](https://github.com/0x676e67/wreq/commit/2461be98fc73e2fd78c396a69c70ce9ab4f7bbf0))
- *(core)* Replace Tokio I/O abstraction ([#909](https://github.com/0x676e67/wreq/issues/909)) - ([16976b9](https://github.com/0x676e67/wreq/commit/16976b935f01a6464d4c0ae1e3611e45429b351b))
- *(deps)* Remove dependency on `url::Url` ([#914](https://github.com/0x676e67/wreq/issues/914)) - ([356950d](https://github.com/0x676e67/wreq/commit/356950d2cfbcb9f4f4ff5832ca696a95880171f2))
- *(h2)* Refactor legacy unsafe wrapper code ([#905](https://github.com/0x676e67/wreq/issues/905)) - ([172f1c5](https://github.com/0x676e67/wreq/commit/172f1c558292b4630875b0e3910ee2cb4337f071))
- *(io)* Use Pin::as_deref_mut() from std instead of custom polyfill ([#906](https://github.com/0x676e67/wreq/issues/906)) - ([d3d80f1](https://github.com/0x676e67/wreq/commit/d3d80f16e23e8e1594f2c45041b9403ea2b6be03))

### 📚 Documentation

- *(identity)* Update documentation - ([459afd6](https://github.com/0x676e67/wreq/commit/459afd6a90c4da254dd6598f604c3b1fd1841cec))
- *(proxy)* Remove type export section - ([ae81ef5](https://github.com/0x676e67/wreq/commit/ae81ef533e2439d0398a22b6740521fddcb6cc0d))
- *(request)* Update docs on request methods with cfg support - ([654e225](https://github.com/0x676e67/wreq/commit/654e2258d8472c3427af09b13c19f70949f38ca9))

### ⚡ Performance

- *(http1)* Write during header sorting ([#899](https://github.com/0x676e67/wreq/issues/899)) - ([f025e3f](https://github.com/0x676e67/wreq/commit/f025e3fcfce4d8a8d31726b46e92ad8f51dcf46f))
- *(http2)* Significantly improve http2 multi-core performance ([#892](https://github.com/0x676e67/wreq/issues/892)) - ([2c3f873](https://github.com/0x676e67/wreq/commit/2c3f8736b21589ab4f9f2dec1f56c0a9de321dd0))
- *(layer)* Inline layer creation for faster client build - ([78e8fc7](https://github.com/0x676e67/wreq/commit/78e8fc7b203ac382a5fb70183564513c7346cbe1))

### 🎨 Styling

- *(cookie)* Fmt code - ([315bccf](https://github.com/0x676e67/wreq/commit/315bccfc65101642b2a56f583c573b6d11148bb7))
- *(header)* Simplify header sorting branch match - ([ee23d25](https://github.com/0x676e67/wreq/commit/ee23d25fd258f51eb33b20d72460913c38e7a517))
- *(proto)* Fmt code - ([02e0bc0](https://github.com/0x676e67/wreq/commit/02e0bc06876a458536268863938a4906354791b9))
- *(request)* Fmt code - ([d6e56e4](https://github.com/0x676e67/wreq/commit/d6e56e4b9e85ab73d627d72a51ed04198483cf98))

### ⚙️ Miscellaneous Tasks

- *(ci)* Speed up tests with feature matrix in GitHub Actions ([#894](https://github.com/0x676e67/wreq/issues/894)) - ([d66dc66](https://github.com/0x676e67/wreq/commit/d66dc6671fadbd427ea2c1d0e4fa07e61d62b4db))
- *(proxy)* Debug-print HTTP headers - ([628e6b4](https://github.com/0x676e67/wreq/commit/628e6b462561a7fd5fe987dff6e14a76b02272de))
- *(upgrade)* Drop unused code - ([bb26177](https://github.com/0x676e67/wreq/commit/bb261776fe41f1024f3af1d73147fd0440b2f908))
- Minimize package size - ([938e3f5](https://github.com/0x676e67/wreq/commit/938e3f56c113bd721ceb9216f15c2e8e141f6d50))

### Build

- *(deps)* Bump actions/checkout from 4 to 5 ([#908](https://github.com/0x676e67/wreq/issues/908)) - ([5f6723a](https://github.com/0x676e67/wreq/commit/5f6723a7a8aad0db11f27ff9aa8e5b208f5f6cb4))
- *(deps)* Minimize out-of-the-box dependencies ([#902](https://github.com/0x676e67/wreq/issues/902)) - ([5b68106](https://github.com/0x676e67/wreq/commit/5b68106bcda7ae78209afb35925704f13765717b))
- *(deps)* Bump actions/checkout from 3 to 5 ([#893](https://github.com/0x676e67/wreq/issues/893)) - ([9877ed6](https://github.com/0x676e67/wreq/commit/9877ed6c177c139719bf35245027399e39a7cae7))


## [6.0.0-rc.8](https://github.com/0x676e67/wreq/compare/v6.0.0-rc.7..v6.0.0-rc.8) - 2025-08-12

### ⛰️  Features

- *(dns)* Improve `dns_resolver` for better ergonomics and flexibility ([#891](https://github.com/0x676e67/wreq/issues/891)) - ([9e3f974](https://github.com/0x676e67/wreq/commit/9e3f97450af724abba62cc1ee586c292b16e8498))

### 🐛 Bug Fixes

- *(deps)* Upgrade url to v2.5.4 to address CVE-2024-12224 ([#887](https://github.com/0x676e67/wreq/issues/887)) - ([7038272](https://github.com/0x676e67/wreq/commit/70382725752d44682b5e684d7af3522614941f94))
- *(pool)* Prevent failure when registering the waker with this oneshot ([#888](https://github.com/0x676e67/wreq/issues/888)) - ([f7d914d](https://github.com/0x676e67/wreq/commit/f7d914d96712bb3f20403d1dce1c30c4d03c7586))

### 🚜 Refactor

- *(client)* Remove `no_keepalive` method ([#890](https://github.com/0x676e67/wreq/issues/890)) - ([0c15943](https://github.com/0x676e67/wreq/commit/0c159431a296163eb52cf95d0ea9f1e9fc84e3c0))

### 📚 Documentation

- *(README)* Update example - ([b620408](https://github.com/0x676e67/wreq/commit/b6204085abbfba933e6bfb368f7a8579b4bea417))
- *(service)* Update service docs - ([a644502](https://github.com/0x676e67/wreq/commit/a64450253447a8a4287c89e28c66cbd5f9a8c689))

### 🧪 Testing

- *(common)* Add missing assertion in full_rewind test ([#889](https://github.com/0x676e67/wreq/issues/889)) - ([c84746a](https://github.com/0x676e67/wreq/commit/c84746af284f4b0c2ec72f4d01150cb53de30ac9))

### Build

- *(deps)* Update async-tungstenite requirement from 0.30.0 to 0.31.0 ([#884](https://github.com/0x676e67/wreq/issues/884)) - ([d484f71](https://github.com/0x676e67/wreq/commit/d484f71b1ba2ad26ee9fa28b230d6c4ce5f63df8))


## [6.0.0-rc.7](https://github.com/0x676e67/wreq/compare/v6.0.0-rc.5..v6.0.0-rc.7) - 2025-08-10

### ⛰️  Features

- *(ws)* Option for `default_headers` method in websocket ([#883](https://github.com/0x676e67/wreq/issues/883)) - ([fd36b7a](https://github.com/0x676e67/wreq/commit/fd36b7a817f3fb8d2b59dea73c34ff4fd3249d87))

### 🐛 Bug Fixes

- *(request)* Correct `default_headers` method semantics ([#882](https://github.com/0x676e67/wreq/issues/882)) - ([2cbd0ac](https://github.com/0x676e67/wreq/commit/2cbd0ac56813a9e4b022d1747dce512943c31993))

### 🚜 Refactor

- *(dns)* Make hickory module internal ([#881](https://github.com/0x676e67/wreq/issues/881)) - ([e441048](https://github.com/0x676e67/wreq/commit/e441048a6b5df1af3e715cbeceba7e178bbb22eb))

### ⚙️ Miscellaneous Tasks

- *(client)* Expose additional configuration options - ([65bd959](https://github.com/0x676e67/wreq/commit/65bd95963500af6205f9f06b4cc059b67a0ed740))


## [6.0.0-rc.5](https://github.com/0x676e67/wreq/compare/v6.0.0-rc.4..v6.0.0-rc.5) - 2025-08-09

### ⛰️  Features

- *(ws)* Expose the `message` module for external use ([#874](https://github.com/0x676e67/wreq/issues/874)) - ([abed4ac](https://github.com/0x676e67/wreq/commit/abed4ac82d8ad82c72593ad931477acea70557b0))

### 🚜 Refactor

- *(cookie)* Refactor legacy jar cookie implementation ([#871](https://github.com/0x676e67/wreq/issues/871)) - ([ebb1504](https://github.com/0x676e67/wreq/commit/ebb1504400102c71af9d76e9084f8d2ea14c16c7))
- *(dns)* Consolidate legacy DNS modules ([#876](https://github.com/0x676e67/wreq/issues/876)) - ([f54367c](https://github.com/0x676e67/wreq/commit/f54367cad0d5c699596f80857af234e78ba3d166))

### 📚 Documentation

- *(module)* Improve module-level documentation ([#877](https://github.com/0x676e67/wreq/issues/877)) - ([4e2c15f](https://github.com/0x676e67/wreq/commit/4e2c15f39ba0bdf61b0aedb30d43779a4c455d58))
- *(tls)* Update documentation for configuration fields ([#880](https://github.com/0x676e67/wreq/issues/880)) - ([94c060e](https://github.com/0x676e67/wreq/commit/94c060ed2a3fcc744223ab6a7224e67fae8c9210))

### ⚡ Performance

- *(upgrade)* Inline hot methods in async IO wrapper ([#875](https://github.com/0x676e67/wreq/issues/875)) - ([8388b52](https://github.com/0x676e67/wreq/commit/8388b5241a253bb8f550435aa9e487d9ce16b44d))

### 🎨 Styling

- *(internal)* Refactor internal code layout and naming ([#878](https://github.com/0x676e67/wreq/issues/878)) - ([fbf11fd](https://github.com/0x676e67/wreq/commit/fbf11fd588cb773471fb46302405655eb53cafe6))

### 🧪 Testing

- *(client)* Verify multiple identical headers are appended correctly ([#879](https://github.com/0x676e67/wreq/issues/879)) - ([f245f9c](https://github.com/0x676e67/wreq/commit/f245f9c47965ee4b7682050357f350e05a2ca549))

### ⚙️ Miscellaneous Tasks

- *(retry)* Remove unnecessary clone in request duplication - ([d78568c](https://github.com/0x676e67/wreq/commit/d78568cc6079aaefe3f3b02c3537e21646a1f7f0))

### Build

- *(ws)* Switch to runtime-agnostic WebSocket implementation ([#873](https://github.com/0x676e67/wreq/issues/873)) - ([3fb93ef](https://github.com/0x676e67/wreq/commit/3fb93efb76773d8349ade8f66fe3cabb543faa7b))


## [6.0.0-rc.4](https://github.com/0x676e67/wreq/compare/v6.0.0-rc.2..v6.0.0-rc.4) - 2025-08-07

### 🐛 Bug Fixes

- *(cookie)* Store response cookies even with manual `Cookie` header ([#868](https://github.com/0x676e67/wreq/issues/868)) - ([d2f3bf0](https://github.com/0x676e67/wreq/commit/d2f3bf0ec425ad4880dbcba03951f260f8bb1015))
- *(header)* Preserve multi-value headers in `OrigHeaderMap` sorting ([#867](https://github.com/0x676e67/wreq/issues/867)) - ([b650956](https://github.com/0x676e67/wreq/commit/b6509561c779dde492a1208a2fe5f7c64832419d))

### 🚜 Refactor

- *(client)* Allow `?Sized` trait objects in `dns_resolver` ([#870](https://github.com/0x676e67/wreq/issues/870)) - ([2baf195](https://github.com/0x676e67/wreq/commit/2baf1953024fdb646e205478d9dc568113ba2ec1))

### ⚡ Performance

- *(cookie)* Optimize cookie layer to skip unnecessary matching ([#866](https://github.com/0x676e67/wreq/issues/866)) - ([ce9b531](https://github.com/0x676e67/wreq/commit/ce9b531bd4d0211b73fb64211f51a8549c948cfc))


## [6.0.0-rc.2](https://github.com/0x676e67/wreq/compare/v6.0.0-rc.1..v6.0.0-rc.2) - 2025-08-04

### 🐛 Bug Fixes

- *(build)* Resolve build failure on Windows when `default-features` are disabled ([#864](https://github.com/0x676e67/wreq/issues/864)) - ([4418e47](https://github.com/0x676e67/wreq/commit/4418e4773a711bf15a2e86777473f16b0af3d8e3))

### 📚 Documentation

- *(options)* Fix `Http2Options` description ([#863](https://github.com/0x676e67/wreq/issues/863)) - ([89b0957](https://github.com/0x676e67/wreq/commit/89b0957a196debafaeef6a6fa271a53b4a3f7964))


## [6.0.0-rc.1](https://github.com/0x676e67/wreq/compare/v5.1.0..v6.0.0-rc.1) - 2025-08-03

### ⛰️  Features

- *(client)* Set default values for TCP keepalive and user_timeout ([#852](https://github.com/0x676e67/wreq/issues/852)) - ([f06fe61](https://github.com/0x676e67/wreq/commit/f06fe616b72a8d672c9a6118acfab7b96f18bbb6))
- *(client)* Expose TCP socket Happy Eyeballs timeout API ([#844](https://github.com/0x676e67/wreq/issues/844)) - ([bcbfbf8](https://github.com/0x676e67/wreq/commit/bcbfbf802c03b6cf58eaa566d38b4a8c29037635))
- *(client)* Expose TCP socket send/recv buffer APIs ([#843](https://github.com/0x676e67/wreq/issues/843)) - ([2ea1052](https://github.com/0x676e67/wreq/commit/2ea105290434339cdf84a83afe4d6f65c864e09a))
- *(client)* Disable redirects by default ([#805](https://github.com/0x676e67/wreq/issues/805)) - ([ecf6019](https://github.com/0x676e67/wreq/commit/ecf60193deaa6951212d862445645e0ba9175cd7))
- *(client)* Add convenience method for sending `OPTIONS` requests ([#787](https://github.com/0x676e67/wreq/issues/787)) - ([34f1586](https://github.com/0x676e67/wreq/commit/34f158610a52228ad4d0bc665c268714c5b34e0d))
- *(client)* Make `HTTP`/`TLS` config options publicly accessible ([#783](https://github.com/0x676e67/wreq/issues/783)) - ([a4e7b98](https://github.com/0x676e67/wreq/commit/a4e7b981790942364b07f65333602f4fcbb68a7a))
- *(client)* Add `SO_REUSEADDR` support for tcp socket ([#762](https://github.com/0x676e67/wreq/issues/762)) - ([8aced63](https://github.com/0x676e67/wreq/commit/8aced637eed476faeb2212930ba91570a0c4cbda))
- *(client)* Add tower HTTP request middleware layer ([#694](https://github.com/0x676e67/wreq/issues/694)) - ([0ad0021](https://github.com/0x676e67/wreq/commit/0ad0021bde7dd890aa58e3a1d4f422984fab9eec))
- *(client)* Add tcp_user_timeout builder option ([#688](https://github.com/0x676e67/wreq/issues/688)) - ([d1d0eb4](https://github.com/0x676e67/wreq/commit/d1d0eb459b4859a73fc7b75934804bfa30bc907a))
- *(client)* Add tcp_keepalive_interval and tcp_keepalive_retries to ClientBuilder ([#643](https://github.com/0x676e67/wreq/issues/643)) - ([32fe31e](https://github.com/0x676e67/wreq/commit/32fe31e0b6aca538909d3e5367d12d58269bf818))
- *(client)* Drop API for retrieving default headers ([#640](https://github.com/0x676e67/wreq/issues/640)) - ([1b4a445](https://github.com/0x676e67/wreq/commit/1b4a4451fb7bd28e610431a12b2a427b3da64e9b))
- *(client)* Add identity to be used for client certificate authentication ([#617](https://github.com/0x676e67/wreq/issues/617)) - ([55c2490](https://github.com/0x676e67/wreq/commit/55c249067c267099c400119e12491441e4c0e63a))
- *(client)* Adds support for SSLKEYLOGFILE output from client ([#605](https://github.com/0x676e67/wreq/issues/605)) - ([dc0c40b](https://github.com/0x676e67/wreq/commit/dc0c40bed2faa7b743d5a22496e83029a9b84dcf))
- *(client)* ClientBuilder::interface on Solarish OS ([#594](https://github.com/0x676e67/wreq/issues/594)) - ([c0a7fbc](https://github.com/0x676e67/wreq/commit/c0a7fbcaf98f276de74e9b11dbc23f5bb5ce457c))
- *(cookie)* Provide access to raw cookie API ([#830](https://github.com/0x676e67/wreq/issues/830)) - ([5c5e3e5](https://github.com/0x676e67/wreq/commit/5c5e3e5ccdc3383c7c2b71fe4954da039882f877))
- *(emulation)* Expose config fields via accessors while preserving `non_exhaustive` ([#854](https://github.com/0x676e67/wreq/issues/854)) - ([dfdf707](https://github.com/0x676e67/wreq/commit/dfdf707e3fb7ca6f3800e4741572eb51323d06cb))
- *(error)* Report custom reason phrase in error message ([#767](https://github.com/0x676e67/wreq/issues/767)) - ([b492bc1](https://github.com/0x676e67/wreq/commit/b492bc1d408f1742c1f1e688784707f877cc1d5b))
- *(error)* Check if the error is an upgrade error ([#623](https://github.com/0x676e67/wreq/issues/623)) - ([ddae516](https://github.com/0x676e67/wreq/commit/ddae516928663b2a9a181eb387dc1ff9aa567c79))
- *(examples)* Add emulation twitter android  `TLS`/`HTTP2` example ([#612](https://github.com/0x676e67/wreq/issues/612)) - ([40c9a70](https://github.com/0x676e67/wreq/commit/40c9a70ad015e4f8db1e9dac8416c61b25d05318))
- *(header)* Enhance the usability of `OriginalHeaders` API ([#731](https://github.com/0x676e67/wreq/issues/731)) - ([99bfc39](https://github.com/0x676e67/wreq/commit/99bfc391dc5e90f439576da282f94be9bb78b1f8))
- *(headers)* Omit payload length for HTTP/2 `OPTIONS` ([#785](https://github.com/0x676e67/wreq/issues/785)) - ([bb00275](https://github.com/0x676e67/wreq/commit/bb00275602ea2468d42ee4674652315b4ae2dc6d))
- *(http2)* Upgrade `http2` dependency to 0.5.0 ([#651](https://github.com/0x676e67/wreq/issues/651)) - ([a21827b](https://github.com/0x676e67/wreq/commit/a21827bb30bc656d9ae0e71a5e6fa3cff4d6e94f))
- *(lib)* Export `EmulationBuilder` as a public API ([#825](https://github.com/0x676e67/wreq/issues/825)) - ([080f85f](https://github.com/0x676e67/wreq/commit/080f85f1021a5555586b986c4e6addaabaeba018))
- *(pool)* Distinguish connections by request emulation ([#841](https://github.com/0x676e67/wreq/issues/841)) - ([67884ee](https://github.com/0x676e67/wreq/commit/67884eea31720d743c98bca27b8c9fea02a2f555))
- *(redirect)* Per-request redirect config support ([#710](https://github.com/0x676e67/wreq/issues/710)) - ([265df64](https://github.com/0x676e67/wreq/commit/265df646689eceb08ab020535f756ce055182ec1))
- *(request)* Support per-request emulation configuration ([#759](https://github.com/0x676e67/wreq/issues/759)) - ([2ec6d21](https://github.com/0x676e67/wreq/commit/2ec6d21ad9ba1c815c81c9152fc35f70744b7211))
- *(request)* Adjust internal structure and allow skip default headers ([#723](https://github.com/0x676e67/wreq/issues/723)) - ([7be331d](https://github.com/0x676e67/wreq/commit/7be331d2dffc4dbe5226c95c5b8b3dd96897a324))
- *(request)* Setting headers order at the request level ([#602](https://github.com/0x676e67/wreq/issues/602)) - ([3b280f8](https://github.com/0x676e67/wreq/commit/3b280f845538e12a92f0976b9455604f8260ef90))
- *(response)* Add `Response.local_addr()` to get local address ([#835](https://github.com/0x676e67/wreq/issues/835)) - ([35652f5](https://github.com/0x676e67/wreq/commit/35652f547fc293a8339b5e475fd5e8b41e2fafd3))
- *(tls)* Treat different TLS configs as distinct sessions ([#779](https://github.com/0x676e67/wreq/issues/779)) - ([e05406d](https://github.com/0x676e67/wreq/commit/e05406d4bfdb93837c9168fecd24a467908ba7a5))
- *(tls)* Add API to set list of stable curves ([#633](https://github.com/0x676e67/wreq/issues/633)) - ([ea0eb17](https://github.com/0x676e67/wreq/commit/ea0eb17ed425d6477eebe629b7851f0e51a1bc75))
- *(websocket)* Support per-request emulation configuration ([#764](https://github.com/0x676e67/wreq/issues/764)) - ([468f86f](https://github.com/0x676e67/wreq/commit/468f86fd5811043a1d89437f1bea30c8cfbf93b8))
- *(ws)* Add support for header order on websocket builder ([#608](https://github.com/0x676e67/wreq/issues/608)) - ([ad9e0b9](https://github.com/0x676e67/wreq/commit/ad9e0b97d5733a800b17c32851c1824da83d05c4))

### 🐛 Bug Fixes

- *(client)* Fix `HTTP/2` safe retry policy ([#715](https://github.com/0x676e67/wreq/issues/715)) - ([3a5c356](https://github.com/0x676e67/wreq/commit/3a5c35697d12dcf67d30db88abb8d1fe37b638a7))
- *(client)* Prevent future stack overflow in request handling ([#685](https://github.com/0x676e67/wreq/issues/685)) - ([402ffe3](https://github.com/0x676e67/wreq/commit/402ffe3184362a18696791621261c744a5f413b2))
- *(client)* Update client to retain tls keylog configuration ([#619](https://github.com/0x676e67/wreq/issues/619)) - ([22c0770](https://github.com/0x676e67/wreq/commit/22c0770d3a123fa2569d9174112fa7c2a309220f))
- *(client)* Fix `HTTP2` extensions to be applied in retry requests ([#596](https://github.com/0x676e67/wreq/issues/596)) - ([a1f0d32](https://github.com/0x676e67/wreq/commit/a1f0d32ede0bb146230781603d532217ccdc0430))
- *(core)* Improve client errors details if available ([#665](https://github.com/0x676e67/wreq/issues/665)) - ([fb41f70](https://github.com/0x676e67/wreq/commit/fb41f70c7b70a556c2a97f9b699049a5e1fb58f4))
- *(dns)* Prefer IPv6 addresses before IPv4 even if resolver ordered differently ([#658](https://github.com/0x676e67/wreq/issues/658)) - ([e913768](https://github.com/0x676e67/wreq/commit/e913768cf1be11b277b9b84b2f31b0090e426450))
- *(error)* Error::is_timeout() checks for crate::core::Error::is_timeout() - ([34e79f1](https://github.com/0x676e67/wreq/commit/34e79f1ea81085c66e9ffb66066c8a35254ebdc1))
- *(error)* Include request URL in error messages ([#737](https://github.com/0x676e67/wreq/issues/737)) - ([f312645](https://github.com/0x676e67/wreq/commit/f312645c31f53bcbf24d3899132b6fd9af890beb))
- *(hash)* Fix #780 ([#784](https://github.com/0x676e67/wreq/issues/784)) - ([7b5808d](https://github.com/0x676e67/wreq/commit/7b5808dbb6073cb81e657aedb19ce2f9965875d5))
- *(http2)* Rename `unknown_setting8` to `enable_connect_protocol` ([#647](https://github.com/0x676e67/wreq/issues/647)) - ([3464105](https://github.com/0x676e67/wreq/commit/34641053a7e2f6737ccf9803cc7ab02cc9d3c103))
- *(pool)* Cap pool idle interval to a minimum ([#814](https://github.com/0x676e67/wreq/issues/814)) - ([daba062](https://github.com/0x676e67/wreq/commit/daba06298e60ef67a8a57de15aaad0ac071294be))
- *(pool)* Don't spawn pool idle interval if timeout is 0 ([#806](https://github.com/0x676e67/wreq/issues/806)) - ([a6deeb4](https://github.com/0x676e67/wreq/commit/a6deeb44b8e8d67e322a33759b264bc81a17e7d4))
- *(proxy)* Restore default port 1080 for SOCKS proxies without explicit port ([#821](https://github.com/0x676e67/wreq/issues/821)) - ([256de2b](https://github.com/0x676e67/wreq/commit/256de2bb5ff60bd0f040277e0020ef84d0ea8b12))
- *(proxy)* Set https system proxy on windows ([#678](https://github.com/0x676e67/wreq/issues/678)) - ([7111b13](https://github.com/0x676e67/wreq/commit/7111b131db66abdddbbccafa5450f3d1637d229b))
- *(redirect)* Make the number of redirects of policy matches its maximum limit ([#629](https://github.com/0x676e67/wreq/issues/629)) - ([85bad99](https://github.com/0x676e67/wreq/commit/85bad9996a9d8785feb92cf3d2c3c845bc10a306))
- *(request)* Fix headers order ([#603](https://github.com/0x676e67/wreq/issues/603)) - ([9c85532](https://github.com/0x676e67/wreq/commit/9c8553229f62c901a2b739fed413be08fa558d4b))
- *(tls)* Fix encoding error when multiple ALPS extensions are present ([#861](https://github.com/0x676e67/wreq/issues/861)) - ([6ce6c73](https://github.com/0x676e67/wreq/commit/6ce6c73cd0479a169d0f7e6f90c4073cf6e3fc0a))
- *(ws)* Improve status code message on WebSocket upgrade failure ([#824](https://github.com/0x676e67/wreq/issues/824)) - ([4f6f6da](https://github.com/0x676e67/wreq/commit/4f6f6da67bc990be1753c4bb8e546c1b7ed35889))

### 🚜 Refactor

- *(client)* Use `Either` to unify generic and boxed `Client` service types ([#849](https://github.com/0x676e67/wreq/issues/849)) - ([9cb05e7](https://github.com/0x676e67/wreq/commit/9cb05e794a6d5f1421482e15117ece37180099a7))
- *(client)* Move HTTP/2 safe retry logic into `tower` middleware ([#713](https://github.com/0x676e67/wreq/issues/713)) - ([136c791](https://github.com/0x676e67/wreq/commit/136c7912b54bb74cecc48618415a64f865d7830c))
- *(client)* Move read timeout logic into `tower` middleware ([#702](https://github.com/0x676e67/wreq/issues/702)) - ([06d5e47](https://github.com/0x676e67/wreq/commit/06d5e47f7dfb6353553d9bf5e99b185f644c19fd))
- *(client)* Move total timeout logic into Tower middleware ([#701](https://github.com/0x676e67/wreq/issues/701)) - ([ed8b2ea](https://github.com/0x676e67/wreq/commit/ed8b2eab0ee71278fd2f787089026cb66f64dd29))
- *(client)* Remove legacy HTTP/1 and HTTP/2 tuning options ([#644](https://github.com/0x676e67/wreq/issues/644)) - ([f019267](https://github.com/0x676e67/wreq/commit/f019267dd11fc7dd5ce4ab72b4c85a689a206710))
- *(client)* Replace header map by key - ([6012542](https://github.com/0x676e67/wreq/commit/60125429e1764e50b064c835a77e009e06a18827))
- *(client)* Replace header map by key ([#618](https://github.com/0x676e67/wreq/issues/618)) - ([237b17a](https://github.com/0x676e67/wreq/commit/237b17a649cf201fbac706044bb665e84c514804))
- *(config)* Replace duplicate types with type aliases ([#740](https://github.com/0x676e67/wreq/issues/740)) - ([6bb210b](https://github.com/0x676e67/wreq/commit/6bb210b95d550ac415e7fea3d142d2296e1d4fa1))
- *(config)* Unify request extensions config processing ([#712](https://github.com/0x676e67/wreq/issues/712)) - ([fb1b7b2](https://github.com/0x676e67/wreq/commit/fb1b7b2f3aab1e2c02ee9a0927ae5750e0ae740e))
- *(config)* Remove public config fields and improve backward compatibility ([#614](https://github.com/0x676e67/wreq/issues/614)) - ([6631c5c](https://github.com/0x676e67/wreq/commit/6631c5c9f4489b5b323eab25d953fb9d13b698f8))
- *(connect)* Modularize components by responsibility ([#819](https://github.com/0x676e67/wreq/issues/819)) - ([c996ec7](https://github.com/0x676e67/wreq/commit/c996ec7b0b6dca703b75b0007f9f36b142c9cc64))
- *(connect)* Remove `Connect` trait alias wrapper around `tower::Service` ([#807](https://github.com/0x676e67/wreq/issues/807)) - ([947a25b](https://github.com/0x676e67/wreq/commit/947a25b7f158f84c8483fbf18e780dc4747970b2))
- *(connect)* Streamline connector builder structure ([#705](https://github.com/0x676e67/wreq/issues/705)) - ([eb9308b](https://github.com/0x676e67/wreq/commit/eb9308bb3ded0b9fd6eabd77a947738f9ac78705))
- *(connect)* Cleanup dead code for `tracing` feature ([#689](https://github.com/0x676e67/wreq/issues/689)) - ([5574786](https://github.com/0x676e67/wreq/commit/5574786b1a2572a13b5dea8c59e554cf9b63acf0))
- *(connect)* Refactored internal connector builder - ([39f779b](https://github.com/0x676e67/wreq/commit/39f779b90b3a12705f5658f6a3c43a00c721d88e))
- *(cookie)* Integrate cookie store into `tower` layer ([#695](https://github.com/0x676e67/wreq/issues/695)) - ([c0cf8e3](https://github.com/0x676e67/wreq/commit/c0cf8e396b5b9743e6b19b9b59b60753a3052802))
- *(cookie)* Remove redundant store abstraction API ([#635](https://github.com/0x676e67/wreq/issues/635)) - ([8e34a91](https://github.com/0x676e67/wreq/commit/8e34a913e45cf684711c9c5c45a7e62f48d62cee))
- *(core)* Separate `body` and `proto` responsibilities ([#839](https://github.com/0x676e67/wreq/issues/839)) - ([9e65c9f](https://github.com/0x676e67/wreq/commit/9e65c9f1d4d4a00ded6a3916e74a99486cb41eb6))
- *(core)* Add socket addr to ConnectError ([#663](https://github.com/0x676e67/wreq/issues/663)) - ([877aa9c](https://github.com/0x676e67/wreq/commit/877aa9c7e791717a8c5ff106a376877d14442211))
- *(core)* Reduce dependency on `futures-util` ([#636](https://github.com/0x676e67/wreq/issues/636)) - ([87ed77b](https://github.com/0x676e67/wreq/commit/87ed77b02a251b65aed014a9d329a75a6d92e76a))
- *(core/client)* Remove old body delay_eof code ([#736](https://github.com/0x676e67/wreq/issues/736)) - ([a9d5db1](https://github.com/0x676e67/wreq/commit/a9d5db12aadfc17132c8444acaedb660ae67febe))
- *(decoder)* Migrate decompression handling to tower-http ([#720](https://github.com/0x676e67/wreq/issues/720)) - ([e2427d8](https://github.com/0x676e67/wreq/commit/e2427d8c60ea370ba092dda766d74ffd119e1655))
- *(dns)* Disable export of `hickory_resolver` module ([#646](https://github.com/0x676e67/wreq/issues/646)) - ([68fc1e4](https://github.com/0x676e67/wreq/commit/68fc1e4dcd65b0567a3e3b1fa4b485c42652d1b3))
- *(error)* Use standard library-style error handling ([#722](https://github.com/0x676e67/wreq/issues/722)) - ([97657fd](https://github.com/0x676e67/wreq/commit/97657fd816202dbd8f34a0f0733422dedd27184e))
- *(future)* Simplify `Client` future types with `Either` ([#851](https://github.com/0x676e67/wreq/issues/851)) - ([b6922d0](https://github.com/0x676e67/wreq/commit/b6922d0902dbe24daa656c06dcc4172b5193e43a))
- *(header)* Preserve header order and casing in `OrigHeaderMap` redesign ([#860](https://github.com/0x676e67/wreq/issues/860)) - ([cc0e637](https://github.com/0x676e67/wreq/commit/cc0e637798a115f4fdc41a1fd3799c5bdd10e127))
- *(http1)* Remove support for `title_case_headers` - ([4501d9a](https://github.com/0x676e67/wreq/commit/4501d9ace91a6adab041cddc8ce6d5e964e278c8))
- *(http2)* Add decriptive error for non-empty body in CONNECT request ([#634](https://github.com/0x676e67/wreq/issues/634)) - ([fa413e6](https://github.com/0x676e67/wreq/commit/fa413e629687df306d937d3f69e64619c80ad524))
- *(internally)* Normalize internal module structure ([#790](https://github.com/0x676e67/wreq/issues/790)) - ([8b768e7](https://github.com/0x676e67/wreq/commit/8b768e7579cacf8c85cb580abb47c88b9b7662dd))
- *(internally)* Backport hyper client ([#624](https://github.com/0x676e67/wreq/issues/624)) - ([4efc5a7](https://github.com/0x676e67/wreq/commit/4efc5a7c227dd257ca866fe1772341803d3c91bc))
- *(internally)* Refactor internal certificate loading ([#616](https://github.com/0x676e67/wreq/issues/616)) - ([2bf9da8](https://github.com/0x676e67/wreq/commit/2bf9da8b0defd4f805fccbd60d4468b14c9dfcdd))
- *(io)* Drop duplicated legacy IO code ([#836](https://github.com/0x676e67/wreq/issues/836)) - ([0b22b58](https://github.com/0x676e67/wreq/commit/0b22b585d7da3f7375d4d42d109f056c3769a089))
- *(layer)* Simplify tower `Service` error conversion ([#850](https://github.com/0x676e67/wreq/issues/850)) - ([e577afc](https://github.com/0x676e67/wreq/commit/e577afc903ff416b6db486b0e7c2fe0112914cf9))
- *(module)* Separate hash responsibilities ([#856](https://github.com/0x676e67/wreq/issues/856)) - ([a5f5caa](https://github.com/0x676e67/wreq/commit/a5f5caadd3513bd8d70081d20a131bd77fdc8451))
- *(module)* Separate util responsibilities ([#838](https://github.com/0x676e67/wreq/issues/838)) - ([9756969](https://github.com/0x676e67/wreq/commit/975696987c4e04a570f7af7fbd2f81de7de932b4))
- *(module)* Separate `proxy` and `client` responsibilities ([#833](https://github.com/0x676e67/wreq/issues/833)) - ([6b71f74](https://github.com/0x676e67/wreq/commit/6b71f74f70179a3499480b10d19f9bd26f0c5bd9))
- *(pool)* Simplify idle task using async/await ([#812](https://github.com/0x676e67/wreq/issues/812)) - ([808da8c](https://github.com/0x676e67/wreq/commit/808da8ceda00e88188339fde3477f097ce4d12a3))
- *(proxy)* Remove duplicated basic auth encoder ([#845](https://github.com/0x676e67/wreq/issues/845)) - ([5b0cf72](https://github.com/0x676e67/wreq/commit/5b0cf72b98be499c9fe4fe8a789d8ac8f9dbf88f))
- *(proxy)* Replace string comparison with constant comparison ([#820](https://github.com/0x676e67/wreq/issues/820)) - ([d5d60ab](https://github.com/0x676e67/wreq/commit/d5d60ab5c4b445e4584dbec8e65c801f6a6baaf2))
- *(proxy)* Remove support for `Proxy::custom` ([#756](https://github.com/0x676e67/wreq/issues/756)) - ([1a5a36a](https://github.com/0x676e67/wreq/commit/1a5a36a5b26de80f70f5116cfdf86806f39f2938))
- *(proxy)* Migrate proxy matcher from hyper-util ([#675](https://github.com/0x676e67/wreq/issues/675)) - ([fafe3a6](https://github.com/0x676e67/wreq/commit/fafe3a615319386ab5a908780996d61ab87dbe61))
- *(redirect)* Migrate from `iri-string` to `url` crate for URI resolution ([#757](https://github.com/0x676e67/wreq/issues/757)) - ([7b72c18](https://github.com/0x676e67/wreq/commit/7b72c18707c661e3e2eb4256a3d6aa00c6c1dd51))
- *(redirect)* Redesign redirection logic in `tower` middleware ([#708](https://github.com/0x676e67/wreq/issues/708)) - ([a53ce43](https://github.com/0x676e67/wreq/commit/a53ce43adde765be625fc5e1b176fffdfd5c0975))
- *(rewind)* Replace manual implementations of `ReadBufCursor` methods ([#595](https://github.com/0x676e67/wreq/issues/595)) - ([e11e214](https://github.com/0x676e67/wreq/commit/e11e214248f8a9bbe1a998f70b823f026035f3f6))
- *(service)* Eliminate unnecessary URL parsing ([#831](https://github.com/0x676e67/wreq/issues/831)) - ([4339692](https://github.com/0x676e67/wreq/commit/4339692b7333c8be6c6ed779ac8f172aaca12e40))
- *(socks)* Migrate to `tokio-socks` for easier maintenance ([#766](https://github.com/0x676e67/wreq/issues/766)) - ([b405fda](https://github.com/0x676e67/wreq/commit/b405fda0da727f35457a2a8b751be5c27455c50c))
- *(socks)* Reuse socks module logic from hyper-util ([#686](https://github.com/0x676e67/wreq/issues/686)) - ([ecb1493](https://github.com/0x676e67/wreq/commit/ecb1493d6cc259bf754ffdc0c93fd946c6a47d97))
- *(timeout)* Simplify `Pin<B>` wrapping ([#732](https://github.com/0x676e67/wreq/issues/732)) - ([40518b6](https://github.com/0x676e67/wreq/commit/40518b6d4488474f098661de1f11393931d9ccdd))
- *(tls)* Allow setting `ALPN`/`ALPS` protocol preference order ([#743](https://github.com/0x676e67/wreq/issues/743)) - ([7d7f65f](https://github.com/0x676e67/wreq/commit/7d7f65f7e70194a4ec69af143d906302dd587486))
- *(tls)* Redesign certificate compression API for clarity and consistency ([#742](https://github.com/0x676e67/wreq/issues/742)) - ([7097c8d](https://github.com/0x676e67/wreq/commit/7097c8da26db2b7ac28287de257e0477ca1d0043))
- *(tls)* Remove unnecessary lazy closure from `TlsConnector` ([#739](https://github.com/0x676e67/wreq/issues/739)) - ([37cd919](https://github.com/0x676e67/wreq/commit/37cd919b41cf74c241071e8b7cc8f6ba29f9864f))
- *(tls)* Refactor TLS keylog tracking policy ([#655](https://github.com/0x676e67/wreq/issues/655)) - ([d88c83d](https://github.com/0x676e67/wreq/commit/d88c83dd2db6953415a62cb395efa3f07d95e355))
- *(tls)* Remove configuration not associated with TLS extensions ([#654](https://github.com/0x676e67/wreq/issues/654)) - ([d62475f](https://github.com/0x676e67/wreq/commit/d62475f7d4766e4e2356dc21a39cf244b21c0d36))
- *(tls)* Refactor certificate compression algorithm configuration API ([#639](https://github.com/0x676e67/wreq/issues/639)) - ([058fc9a](https://github.com/0x676e67/wreq/commit/058fc9a6c9152d088d723369fe408c658b4eea6c))
- *(tls)* Fefactor extension permutation configuration API ([#638](https://github.com/0x676e67/wreq/issues/638)) - ([da9059b](https://github.com/0x676e67/wreq/commit/da9059b9d44a429dd82abf9d883209662ad5cdbe))
- *(tls)* Distinguish certificate identity from store ([#621](https://github.com/0x676e67/wreq/issues/621)) - ([89e2c5c](https://github.com/0x676e67/wreq/commit/89e2c5ce687dab7c08c6da7c77c089afd97a3ab8))
- *(websocket)* Standardize WebSocket module exports ([#645](https://github.com/0x676e67/wreq/issues/645)) - ([f61a89f](https://github.com/0x676e67/wreq/commit/f61a89f0cc0e1279469d70a99c055fea53e8d173))
- *(ws)* Refactor HTTP2 upgrade to WebSocket ([#802](https://github.com/0x676e67/wreq/issues/802)) - ([e7b7052](https://github.com/0x676e67/wreq/commit/e7b705234e68f9a0e39eb86791931d985506a04b))
- Restructure the core implementation of the client ([#668](https://github.com/0x676e67/wreq/issues/668)) - ([1d445cb](https://github.com/0x676e67/wreq/commit/1d445cb15f444e8104cb264a0fae2e05091e3b8d))
- Store request timeout in request extensions instead ([#660](https://github.com/0x676e67/wreq/issues/660)) - ([e666be4](https://github.com/0x676e67/wreq/commit/e666be434af04458a86a4f8ae3d7bd1cf624002c))
- Remove futures-util unless using stream/multipart/compression/websocket/core ([#653](https://github.com/0x676e67/wreq/issues/653)) - ([e3d0c9f](https://github.com/0x676e67/wreq/commit/e3d0c9f960dd7803e83b2c024d1e5f736bccd50c))
- Drop futures-util for leaner core ([#648](https://github.com/0x676e67/wreq/issues/648)) - ([f46c161](https://github.com/0x676e67/wreq/commit/f46c1618e6a42722f024acad7db526b121536b44))
- Backport use `hyper-util` Tunnel ([#642](https://github.com/0x676e67/wreq/issues/642)) - ([446719d](https://github.com/0x676e67/wreq/commit/446719daecf7e4e2479f7c7b5f3785c6da2bddad))
- Renamed `tls_key_log_file` to `tls_keylog_file` for consistency ([#610](https://github.com/0x676e67/wreq/issues/610)) - ([5d1a85a](https://github.com/0x676e67/wreq/commit/5d1a85a1cc04a2380091398dee43146823590545))

### 📚 Documentation

- *(README)* Update for HTTP/3 over QUIC support - ([bba899c](https://github.com/0x676e67/wreq/commit/bba899c2b579f97a399b628c71f179ed07236a75))
- *(client)* Update `tcp_user_timeout` docs - ([1fa4d44](https://github.com/0x676e67/wreq/commit/1fa4d44394bd3fe1efe3bbbbd127a05cfc80d20d))
- *(client)* Clarify `Client` method usage ([#795](https://github.com/0x676e67/wreq/issues/795)) - ([3f56875](https://github.com/0x676e67/wreq/commit/3f56875e6c58176b7a73ed0464b0e6fcf5e16f8c))
- *(client)* Update `tower` middleware integration documentation ([#716](https://github.com/0x676e67/wreq/issues/716)) - ([6094176](https://github.com/0x676e67/wreq/commit/60941762e8addec2788c3ae97cf7714eab9967cd))
- *(connect)* Update docs for `Connector` builder - ([62b3b4a](https://github.com/0x676e67/wreq/commit/62b3b4a7291847faf36b694513ab38970fd3bda2))
- *(layer)* Update docs - ([ff14827](https://github.com/0x676e67/wreq/commit/ff1482791d218acff48469c04af4bccc8e38e44b))
- *(middleware)* Update module docs - ([b6b7071](https://github.com/0x676e67/wreq/commit/b6b7071c74844f365ffb4aa137f29be3f73cfd02))
- *(proxy)* Fix some typos in comment ([#592](https://github.com/0x676e67/wreq/issues/592)) - ([25f85b0](https://github.com/0x676e67/wreq/commit/25f85b06ce72181009e8e2727977557b47df4c68))
- *(timeout)* Update docs - ([512fa22](https://github.com/0x676e67/wreq/commit/512fa2281e665cb79e459ce6e3b5d6e124aed25a))
- *(tls)* Update prefer chacha20 documentation - ([9652f46](https://github.com/0x676e67/wreq/commit/9652f46735ad774e956b747fd2c2ff4f3dcb7bd9))
- *(ws)* Remove redundant comments - ([b401440](https://github.com/0x676e67/wreq/commit/b4014407690c8c73850c2a4299553f336e659fe5))
- *(x509)* Clarify thread safety and usage of CertStore ([#846](https://github.com/0x676e67/wreq/issues/846)) - ([f1423f8](https://github.com/0x676e67/wreq/commit/f1423f8414ff01bb4b1c3e5318e1f917754ab9ca))
- Revise and correct API documentation ([#724](https://github.com/0x676e67/wreq/issues/724)) - ([458e473](https://github.com/0x676e67/wreq/commit/458e4731ff25ca2625c4c2c53921be66c8a6bb8b))
- Improve formatting in documentation ([#696](https://github.com/0x676e67/wreq/issues/696)) - ([867a8a2](https://github.com/0x676e67/wreq/commit/867a8a273028926a838f71e7b6ead728c3234d11))
- Fix package docs - ([da20f76](https://github.com/0x676e67/wreq/commit/da20f766e9a25cad0cff7c128be8f7f1c0f2099e))
- Cleanup legacy server documentation - ([7a0b11c](https://github.com/0x676e67/wreq/commit/7a0b11cf8f013e644d63d70d07a0e21289c86bb9))
- Update documentation build ([#609](https://github.com/0x676e67/wreq/issues/609)) - ([eb06ebc](https://github.com/0x676e67/wreq/commit/eb06ebc81ac24ae821c4756196b58585303b723a))

### ⚡ Performance

- *(client)* Avoid full `ClientRef` clone by matching and cloning service in-place ([#758](https://github.com/0x676e67/wreq/issues/758)) - ([8e547ad](https://github.com/0x676e67/wreq/commit/8e547ad17a504a230eb770a1ce3b92b6d0765186))
- *(client)* Replace `Box<dyn Trait>` with generic type for `Box<T>` ([#755](https://github.com/0x676e67/wreq/issues/755)) - ([eb07a2a](https://github.com/0x676e67/wreq/commit/eb07a2af08afb8be084f6623625af0f13a87745a))
- *(client)* Optimize dyn trait response to reduce runtime overhead ([#746](https://github.com/0x676e67/wreq/issues/746)) - ([0d5cbaf](https://github.com/0x676e67/wreq/commit/0d5cbaf03ff4646c0b81152022fb223a2ffee329))
- *(client)* Optimize response future wrapping calls ([#726](https://github.com/0x676e67/wreq/issues/726)) - ([e24a0cd](https://github.com/0x676e67/wreq/commit/e24a0cdc422576f68b450f7b96c678fc2655f400))
- *(client)* Remove redundant execute request calls ([#718](https://github.com/0x676e67/wreq/issues/718)) - ([4285cf7](https://github.com/0x676e67/wreq/commit/4285cf7278813a9c2e6e1de7d77bfe7c9fc82470))
- *(client)* Avoid redundant box of `tower` layers ([#717](https://github.com/0x676e67/wreq/issues/717)) - ([0ae67f8](https://github.com/0x676e67/wreq/commit/0ae67f8b6aed1b956d1314fa2dc03f310f430286))
- *(connect)* Simplify complex `TokioIo` wrapper ([#763](https://github.com/0x676e67/wreq/issues/763)) - ([807c33b](https://github.com/0x676e67/wreq/commit/807c33b0a2e47ef5da081b475c584541f27a54d0))
- *(connect)* Embed single timeout layer directly to avoid `Box::pin` ([#725](https://github.com/0x676e67/wreq/issues/725)) - ([9d24080](https://github.com/0x676e67/wreq/commit/9d2408034372617a49f863f4fab9be381e46f1d7))
- *(cookie)* Avoid redundant conditional checks ([#730](https://github.com/0x676e67/wreq/issues/730)) - ([574ab8e](https://github.com/0x676e67/wreq/commit/574ab8ef32b8fd91007681d987336e518802c27e))
- *(cookie)* Avoid unnecessary URL parsing in cookie handling ([#699](https://github.com/0x676e67/wreq/issues/699)) - ([fa07991](https://github.com/0x676e67/wreq/commit/fa079912830a947df50632dd98751f7f351d5b4d))
- *(decoder)* Avoid unnecessary clone of decompression service ([#828](https://github.com/0x676e67/wreq/issues/828)) - ([ce78205](https://github.com/0x676e67/wreq/commit/ce78205750b08ae9c2565118870c9974681dd95e))
- *(ext)* Avoid deep calls when inlining is disabled ([#799](https://github.com/0x676e67/wreq/issues/799)) - ([e14a159](https://github.com/0x676e67/wreq/commit/e14a1592f68e235af88a275d52ce7b21f7a3306e))
- *(hash)* Improve hashing efficiency for large structures ([#780](https://github.com/0x676e67/wreq/issues/780)) - ([7a7730e](https://github.com/0x676e67/wreq/commit/7a7730e2c71b0005a31ce94298236691be5a5750))
- *(proxy)* Remove unnecessary sorting from `HeaderMap` ([#857](https://github.com/0x676e67/wreq/issues/857)) - ([2de64fe](https://github.com/0x676e67/wreq/commit/2de64fe14c591d07c07cf28d582dc8bebe7069d5))
- *(proxy)* Remove unnecessary call wrapping ([#855](https://github.com/0x676e67/wreq/issues/855)) - ([2472d39](https://github.com/0x676e67/wreq/commit/2472d39e2128740e437c3d0846f18ea0ff96c148))
- *(proxy)* Use zero-copy Bytes for proxy credentials ([#729](https://github.com/0x676e67/wreq/issues/729)) - ([5bb8e06](https://github.com/0x676e67/wreq/commit/5bb8e06499613d13fab1dc573ce8a1b61b70c23f))
- *(redirect)* Avoid copy when redirection is unsupported ([#728](https://github.com/0x676e67/wreq/issues/728)) - ([741b81e](https://github.com/0x676e67/wreq/commit/741b81edc5201f79542c7e09eb3d46b0f3440062))
- *(req/resp)* Inline frequently called accessor methods - ([7dc3424](https://github.com/0x676e67/wreq/commit/7dc3424a807bb5c60481cb0c6fb6551be2cefacd))
- *(response)* Avoid unnecessary URL cloning ([#747](https://github.com/0x676e67/wreq/issues/747)) - ([95743b3](https://github.com/0x676e67/wreq/commit/95743b37522f8992803427809ed2e0a90ae7902d))
- *(socks)* Optimize SOCKS connection handling ([#769](https://github.com/0x676e67/wreq/issues/769)) - ([5d3fe85](https://github.com/0x676e67/wreq/commit/5d3fe8530dedf76f4fc937981a29fccfbfb764c1))
- *(socks)* Optimize DNS resolution with custom non-blocking resolver ([#687](https://github.com/0x676e67/wreq/issues/687)) - ([49520ce](https://github.com/0x676e67/wreq/commit/49520ce80b6211ec85abfda9655b9196e34c0438))
- *(timeout)* Encapsulate all per-request timeout extensions uniformly ([#804](https://github.com/0x676e67/wreq/issues/804)) - ([dab45fd](https://github.com/0x676e67/wreq/commit/dab45fde9c70e646d576f049e4a46b7c5113fcb3))
- *(timeout)* Reduce unnecessary `as_mut` calls ([#719](https://github.com/0x676e67/wreq/issues/719)) - ([fa9570c](https://github.com/0x676e67/wreq/commit/fa9570c35220963e2c17a0741edaebf0fc340974))
- *(tls)* Inline builder hot path code - ([bc2ff43](https://github.com/0x676e67/wreq/commit/bc2ff43c1b4c39293426cce42724db1b2afd789f))
- *(tls)* Flatten TLS info construction for better performance ([#847](https://github.com/0x676e67/wreq/issues/847)) - ([2ab4edd](https://github.com/0x676e67/wreq/commit/2ab4edd01c2c022ae4bda0312c3f6307371916e9))
- *(tls)* Connect stage reduces call chains - ([29c9bd8](https://github.com/0x676e67/wreq/commit/29c9bd8d9beae3be15de37693341e192b8225e0a))
- *(ws)* Inline frequently called accessor methods ([#782](https://github.com/0x676e67/wreq/issues/782)) - ([929d917](https://github.com/0x676e67/wreq/commit/929d91777539911994527ed6d15ebf31e463b689))
- Inline hotspot `poll` method to reduce call overhead ([#714](https://github.com/0x676e67/wreq/issues/714)) - ([8c26d8b](https://github.com/0x676e67/wreq/commit/8c26d8b8f58de8a00d7e0a17dc63ccdfe1145653))

### 🎨 Styling

- *(client)* Shorten paths in type aliases ([#733](https://github.com/0x676e67/wreq/issues/733)) - ([c83b8e8](https://github.com/0x676e67/wreq/commit/c83b8e82a4b21d63c79922df09b737066e3f314d))
- *(connector)* Simplify user-defined timeout layer setup ([#827](https://github.com/0x676e67/wreq/issues/827)) - ([d620a25](https://github.com/0x676e67/wreq/commit/d620a252eb7549b8cdd079897736d2847e1019cc))
- *(cookie)* Sync upstream API style ([#659](https://github.com/0x676e67/wreq/issues/659)) - ([03041af](https://github.com/0x676e67/wreq/commit/03041af75026269db1763636390a3bf72fe000d4))
- *(proxy)* Simplify `Matcher` Debug implementation - ([f15f36e](https://github.com/0x676e67/wreq/commit/f15f36e158091bf352fcfc334d9056d84889e6f8))
- *(proxy)* Simplify path constraint for `http::Uri` - ([171e7b8](https://github.com/0x676e67/wreq/commit/171e7b83b6e8647f05313f9b4bfbf24e6300cc78))
- *(redirect)* Rename `TowerRedirectPolicy` to `RedirectPolicy` - ([1e4431b](https://github.com/0x676e67/wreq/commit/1e4431b92f765397f89f92f542111bf5e694682f))
- *(request)* Simplify request config access ([#793](https://github.com/0x676e67/wreq/issues/793)) - ([0f6f523](https://github.com/0x676e67/wreq/commit/0f6f5232510cb9cce4b437a9e81685377f56fae2))
- *(socks)* Clippy format - ([20c8236](https://github.com/0x676e67/wreq/commit/20c8236d85e87c1693e01e61566f9d6f46652055))
- *(tunnel)* Fmt code - ([1a489b5](https://github.com/0x676e67/wreq/commit/1a489b5305512094d43274659173f2625a45ba0c))
- Format crate imports for consistency ([#709](https://github.com/0x676e67/wreq/issues/709)) - ([777c6e5](https://github.com/0x676e67/wreq/commit/777c6e5e137024d6f09bf1b53eff7434e573cbb4))
- Fmt code - ([7fb9b1e](https://github.com/0x676e67/wreq/commit/7fb9b1e88df9e088b3920620c84aad1ea0d2a7bb))

### 🧪 Testing

- *(badssl)* Enable test_aes_hw_override test - ([a37219a](https://github.com/0x676e67/wreq/commit/a37219a47b0903375d033cc9a5c6e3701dcb4b74))
- *(deps)* Bump `hyper-util` to v0.1.13 ([#667](https://github.com/0x676e67/wreq/issues/667)) - ([862361c](https://github.com/0x676e67/wreq/commit/862361cac33a200bddbdd2c6b3430da36bccadda))
- *(emulation)* Add tests for additional emulation options ([#823](https://github.com/0x676e67/wreq/issues/823)) - ([e0b76a8](https://github.com/0x676e67/wreq/commit/e0b76a8d40cf0795fc5a81704248edc88b55b439))
- *(emulation)* Add firefox tests ([#822](https://github.com/0x676e67/wreq/issues/822)) - ([6ed1974](https://github.com/0x676e67/wreq/commit/6ed1974744138b6d6f0cd678d652ec32fcab1751))
- *(timeout)* Update timeout tests ([#691](https://github.com/0x676e67/wreq/issues/691)) - ([3781cef](https://github.com/0x676e67/wreq/commit/3781cefb547d0052d8b96a781ec6096ce86e2a64))
- Remove redundant decompression tests ([#734](https://github.com/0x676e67/wreq/issues/734)) - ([8efcd19](https://github.com/0x676e67/wreq/commit/8efcd19925d654ff4cc4a2f61c70672e2890fa60))
- Tests affected by removal of proxy-related environment variables ([#692](https://github.com/0x676e67/wreq/issues/692)) - ([79648b5](https://github.com/0x676e67/wreq/commit/79648b531199cbe86b1c0db4d570e38cf25ff2da))
- Switch over from libflate to flate2 in tests to reduce dependency footprint ([#593](https://github.com/0x676e67/wreq/issues/593)) - ([dc74305](https://github.com/0x676e67/wreq/commit/dc74305dc83a19ce0f0320a91d42ee1e76f13860))

### ⚙️ Miscellaneous Tasks

- *(body)* Re-expose body mod - ([99e27f2](https://github.com/0x676e67/wreq/commit/99e27f203c2dd766707494f3c76f8f5a4d69b092))
- *(body)* Re-expose body mod - ([1d9ee72](https://github.com/0x676e67/wreq/commit/1d9ee729de0eacb68167506f456db871146ec85c))
- *(client)* Remove unused comment - ([efac842](https://github.com/0x676e67/wreq/commit/efac842c9d54bf4e6e7fd83779c4123dab81f48c))
- *(client)* Defer initialization of internal client ([#811](https://github.com/0x676e67/wreq/issues/811)) - ([f5817c6](https://github.com/0x676e67/wreq/commit/f5817c63aa020faf6146343b002cd912a5dbe6cc))
- *(client)* Fmt future.rs - ([3a6c265](https://github.com/0x676e67/wreq/commit/3a6c26545ed768e8e7a7ce73427bef538a74604c))
- *(client)* Eliminate redundant cloning of `tower` middleware ([#698](https://github.com/0x676e67/wreq/issues/698)) - ([c52bb1d](https://github.com/0x676e67/wreq/commit/c52bb1d6b7f5be7158d1cf28c7df41b90dd7fc14))
- *(client)* Refactor client into responsibility-specific modules ([#683](https://github.com/0x676e67/wreq/issues/683)) - ([d70a9f2](https://github.com/0x676e67/wreq/commit/d70a9f29ce0c6f7b66f60b1c83af16f906b72821))
- *(config)* Merge standalone `config` into `middleware/config` ([#771](https://github.com/0x676e67/wreq/issues/771)) - ([96168aa](https://github.com/0x676e67/wreq/commit/96168aa679a600d402eb1f4daca124ddcc16dd40))
- *(connect)* Simplify parameters and improve documentation ([#858](https://github.com/0x676e67/wreq/issues/858)) - ([0eb219b](https://github.com/0x676e67/wreq/commit/0eb219be71f8d005c48fcd80988e758f176f83da))
- *(connect)* Simplify conditional cfg for TCP keepalive ([#842](https://github.com/0x676e67/wreq/issues/842)) - ([0c40c3a](https://github.com/0x676e67/wreq/commit/0c40c3a09c5d4bf9dec805b2fa1e79fc686afa9a))
- *(connect)* Relocate `connect` module to `http` ([#818](https://github.com/0x676e67/wreq/issues/818)) - ([77b00be](https://github.com/0x676e67/wreq/commit/77b00be6dd2f3f46704a152bbde9fbdabf787f1e))
- *(connect)* Simplified type import - ([fe10748](https://github.com/0x676e67/wreq/commit/fe10748d88a23979192e5141a119c8d40dc49d22))
- *(connect)* Fmt code - ([53c9a24](https://github.com/0x676e67/wreq/commit/53c9a24ddc998f0bbde5812725ea869a63707ca7))
- *(connector)* Fmt code - ([a703915](https://github.com/0x676e67/wreq/commit/a703915da5d5f78ed4887bd868b3ebcf5f9b756c))
- *(cookie)* Cleanup unused error types - ([81bcf3f](https://github.com/0x676e67/wreq/commit/81bcf3fed32c6f00c133c794c9aa9162a42b0c81))
- *(cookie)* Fmt code - ([c9e03b1](https://github.com/0x676e67/wreq/commit/c9e03b1f39222c03d49a620189ba9131996189d2))
- *(core)* Format `http1` and `http2` options wrappers ([#813](https://github.com/0x676e67/wreq/issues/813)) - ([6803663](https://github.com/0x676e67/wreq/commit/680366361c809d226e08ab5e5cfcd9635c88a409))
- *(core)* Shorten `crate::core::Error` to `Error` via import ([#797](https://github.com/0x676e67/wreq/issues/797)) - ([1bd5666](https://github.com/0x676e67/wreq/commit/1bd5666143dcfcae2b020fb0fea06362375ceffe))
- *(core)* Remove unused `task` mod - ([121a46b](https://github.com/0x676e67/wreq/commit/121a46bcc0888ea0b7525cd2f0e29020da30da8a))
- *(core)* Remove unused `rewind` mod - ([e6a6ec0](https://github.com/0x676e67/wreq/commit/e6a6ec03bebf77332d26400104c6045268b87622))
- *(core)* Remove legacy code duplicated with `tower::util` ([#727](https://github.com/0x676e67/wreq/issues/727)) - ([ed218cf](https://github.com/0x676e67/wreq/commit/ed218cf18c1b6208aee727c77b1627b070f36559))
- *(core)* Remove duplicate code - ([a22bcf7](https://github.com/0x676e67/wreq/commit/a22bcf73888f5e53a6f77ed535c736c97146a8fb))
- *(decoder)* Merge standalone `decoder` into `middleware/decoder` ([#770](https://github.com/0x676e67/wreq/issues/770)) - ([b917192](https://github.com/0x676e67/wreq/commit/b917192b6e0e62374bf216974f006ccb52035696))
- *(dispatch)* Cleanup legacy unused code ([#796](https://github.com/0x676e67/wreq/issues/796)) - ([4153e07](https://github.com/0x676e67/wreq/commit/4153e07a38bf21c6d3ecfeb366948f1ea6684710))
- *(emulation)* Derive(Clone) for Emulation ([#862](https://github.com/0x676e67/wreq/issues/862)) - ([1ec7a09](https://github.com/0x676e67/wreq/commit/1ec7a093340c5c2f1c2c5fbc0b2adf60b388019a))
- *(example)* Format code in examples - ([a0e63c5](https://github.com/0x676e67/wreq/commit/a0e63c54b55ef4cda748609289d02a0caf570f89))
- *(example)* Update examples - ([b089c6e](https://github.com/0x676e67/wreq/commit/b089c6e892d214e48a43f5c53c896211219039f1))
- *(examples)* Update examples - ([b8b52ba](https://github.com/0x676e67/wreq/commit/b8b52ba3c86a6e29ec6c4e7f9f6c12d8688a0049))
- *(ext)* Encapsulate all per-request extensions uniformly ([#801](https://github.com/0x676e67/wreq/issues/801)) - ([d77d340](https://github.com/0x676e67/wreq/commit/d77d340e2d9c0b8c7440805c248b09797fe62d10))
- *(ext)* Move `http2::ext::Protocol` extension into request config ([#798](https://github.com/0x676e67/wreq/issues/798)) - ([b7cfbe9](https://github.com/0x676e67/wreq/commit/b7cfbe97ea7e9d03b3b9adb32d49ea665ea34566))
- *(internal)* Normalize internal error handling APIs ([#773](https://github.com/0x676e67/wreq/issues/773)) - ([65b574a](https://github.com/0x676e67/wreq/commit/65b574a2ea6b42b5f5f9c347d49e5a6c89382125))
- *(internal)* Normalize internal APIs ([#772](https://github.com/0x676e67/wreq/issues/772)) - ([3cfa301](https://github.com/0x676e67/wreq/commit/3cfa301080cb9a0dd97256a170f6801f5ce1b977))
- *(lib)* Sort module declarations - ([adc8b58](https://github.com/0x676e67/wreq/commit/adc8b58635acb638e1bcccf51801c65be5d07760))
- *(pool)* Eliminate type duplication with aliases - ([5ea3b07](https://github.com/0x676e67/wreq/commit/5ea3b07a62f85c5beb46ba673d26bf76415c06e6))
- *(proxy)* Assign proper connector names for `Tunnel` and `Socks` ([#815](https://github.com/0x676e67/wreq/issues/815)) - ([22d2be1](https://github.com/0x676e67/wreq/commit/22d2be1073988f8f7c76f592b731b0156c72c898))
- *(rt/tokio)* Cleanup unused code - ([c1c5e34](https://github.com/0x676e67/wreq/commit/c1c5e34a15c484d6829e03a2a903bbbf3357ccd3))
- *(socks)* Rename 'with_local_dns' to 'with_dns_mode' - ([7430a6a](https://github.com/0x676e67/wreq/commit/7430a6a213b278cb2f6356b0ed8da26d2cd323a2))
- *(sync)* Simplify lifetime annotations - ([834258c](https://github.com/0x676e67/wreq/commit/834258c75455a35be1c978b43deda8104af73876))
- *(sync)* Remove dead code - ([a628d1c](https://github.com/0x676e67/wreq/commit/a628d1c17b3748379a493245cf71254ce6800fbb))
- *(test)* Remove miri exception configs - ([0511365](https://github.com/0x676e67/wreq/commit/0511365422af4d70d045f9c00e34fd77e9c15a8d))
- *(tls)* Add examples for root and self-signed certificates ([#792](https://github.com/0x676e67/wreq/issues/792)) - ([8691db0](https://github.com/0x676e67/wreq/commit/8691db07db75ea5f6a9dafd9bc0c44cd3dadab20))
- *(tls)* Remove the legacy curves configuration API ([#637](https://github.com/0x676e67/wreq/issues/637)) - ([2459de9](https://github.com/0x676e67/wreq/commit/2459de97819e3eeb7b0569d99387e63ee099c6a4))
- *(types)* Merge `GenericClientService` related types - ([303584c](https://github.com/0x676e67/wreq/commit/303584cbfc832c9528439ba320651aada1d10504))
- *(x509)* Cleanup mixed parsing of pem/der certificates - ([edc4e7d](https://github.com/0x676e67/wreq/commit/edc4e7df38150f899b353b0766653b867a384e05))
- *(x509)* Cleanup dead code - ([42b741b](https://github.com/0x676e67/wreq/commit/42b741bef019e63b0c05d573a550c6e423458bac))
- Sort module declarations - ([8699a4b](https://github.com/0x676e67/wreq/commit/8699a4b2cc06990e9848962563289fa4a7b4b059))
- Remove unused `#[allow]` attributes ([#809](https://github.com/0x676e67/wreq/issues/809)) - ([5bc5cca](https://github.com/0x676e67/wreq/commit/5bc5cca594b4717d343e04b7a7b348b371be7486))
- Fix typo - ([7b800c5](https://github.com/0x676e67/wreq/commit/7b800c5efbe48899d9ae7e6f9a129a0d8459a990))
- Cleanup dead code - ([5be4443](https://github.com/0x676e67/wreq/commit/5be4443f78d0cbad72ffa640414e094d20e0fe09))
- Cleanup unused macros and format definitions - ([9f925d3](https://github.com/0x676e67/wreq/commit/9f925d384f5723c68001041c00e4865172f68c8e))
- Cleanup redundant and unused type exports ([#704](https://github.com/0x676e67/wreq/issues/704)) - ([a583a7f](https://github.com/0x676e67/wreq/commit/a583a7ff9e179efccdf6d4877792e09016029e7f))
- Clean up redundant type exports ([#684](https://github.com/0x676e67/wreq/issues/684)) - ([4af36f5](https://github.com/0x676e67/wreq/commit/4af36f5bbaa0ea1614e70e8a0c60a9bbb2079e93))
- Fmt example code ([#656](https://github.com/0x676e67/wreq/issues/656)) - ([7ad2496](https://github.com/0x676e67/wreq/commit/7ad24960c352257104d60d5be477631446e8793e))
- Apply clippy fixes required by CI ([#649](https://github.com/0x676e67/wreq/issues/649)) - ([d1e43d4](https://github.com/0x676e67/wreq/commit/d1e43d4a8019f73cb13c69ddf6e6c0852e95c5d3))
- Fix clippy module inception - ([6e66dd6](https://github.com/0x676e67/wreq/commit/6e66dd6fd18bb586a24a6988faea0398f7093923))
- Update examples and clean up dead code - ([636b510](https://github.com/0x676e67/wreq/commit/636b510a63ed4a3ff71abffc6c5eef24245fa889))
- Remove unused comments - ([ff484b2](https://github.com/0x676e67/wreq/commit/ff484b2888333b5e17adb3bd7681271ba6e6d201))

### Build

- *(deps)* Update tokio requirement from 1 to 1.47.0 - ([e7bab63](https://github.com/0x676e67/wreq/commit/e7bab6356d30115c2251eff8f9b10f7d7de58778))
- *(deps)* Update dependencies - ([42eaba7](https://github.com/0x676e67/wreq/commit/42eaba7444f6d19bb85200b58c8c837a25fbf146))
- *(deps)* Reduce dependency on `tokio-util` ([#837](https://github.com/0x676e67/wreq/issues/837)) - ([69c178d](https://github.com/0x676e67/wreq/commit/69c178dc3bb2655ff7dd5e782e957898f8933011))
- *(deps)* Simplify dev dependencies - ([2b6ae59](https://github.com/0x676e67/wreq/commit/2b6ae5925d79c19f6adb13cf1a1bb8c051a33eda))
- *(deps)* Simplify dev dependencies - ([9743ca7](https://github.com/0x676e67/wreq/commit/9743ca7138723659a5fb7946947c59518c3d0123))
- *(deps)* Update cookie_store requirement from 0.21 to 0.22 ([#829](https://github.com/0x676e67/wreq/issues/829)) - ([8453aa2](https://github.com/0x676e67/wreq/commit/8453aa272d8756fbd9a69d061803926d86f6774c))
- *(deps)* Update socket2 requirement from 0.5.10 to 0.6.0 ([#778](https://github.com/0x676e67/wreq/issues/778)) - ([73bd5a0](https://github.com/0x676e67/wreq/commit/73bd5a027e2dddaaa313ae19ed363cbea637cbf6))
- *(deps)* Drop `tower-service` (redundant with `tower::Service`) ([#800](https://github.com/0x676e67/wreq/issues/800)) - ([9de6cb3](https://github.com/0x676e67/wreq/commit/9de6cb31e417b00210d277ffd8460da5eb8e0eea))
- *(deps)* Remove redundant `atomic-waker` dependency ([#776](https://github.com/0x676e67/wreq/issues/776)) - ([b0cc9cd](https://github.com/0x676e67/wreq/commit/b0cc9cd6e96108a522b9299aaa8581d5f1780848))
- *(deps)* Remove redundant `futures-core` dep ([#774](https://github.com/0x676e67/wreq/issues/774)) - ([b04e162](https://github.com/0x676e67/wreq/commit/b04e162995afbabbbbc1dcf47464e2dd372a7574))
- *(deps)* Replace `lru` with faster `schnellru` implementation ([#754](https://github.com/0x676e67/wreq/issues/754)) - ([100bab9](https://github.com/0x676e67/wreq/commit/100bab9cfebf2df645314f83102fc4fa079e4479))
- *(deps)* Remove support for `rustls-native-certs` ([#752](https://github.com/0x676e67/wreq/issues/752)) - ([144bc8a](https://github.com/0x676e67/wreq/commit/144bc8abac0a0a38b8ff2c44e5d6edb1ff2b7046))
- *(deps)* Optionally use `parking_lot` for lock implementation ([#750](https://github.com/0x676e67/wreq/issues/750)) - ([da30d6b](https://github.com/0x676e67/wreq/commit/da30d6beef7182e507659417c4357751866cbdd7))
- *(deps)* Prepare for Boring 5 upgrade ([#735](https://github.com/0x676e67/wreq/issues/735)) - ([77cfc8d](https://github.com/0x676e67/wreq/commit/77cfc8dcb7d4aec9df9ed7c3656633a4ffcc407e))
- *(deps)* Update tokio-tungstenite requirement from 0.26.2 to 0.27.0 ([#721](https://github.com/0x676e67/wreq/issues/721)) - ([63f7a4b](https://github.com/0x676e67/wreq/commit/63f7a4b68881a2e453fdf9413082fac7e5d4021e))
- *(deps)* Update webpki-root-certs requirement from 0.26.0 to 1.0.0 ([#631](https://github.com/0x676e67/wreq/issues/631)) - ([acb44fe](https://github.com/0x676e67/wreq/commit/acb44fe8c78b98f3c54dab05ab68035a6d449515))
- *(deps)* Remove `typed-builder` dependency ([#620](https://github.com/0x676e67/wreq/issues/620)) - ([5e037ac](https://github.com/0x676e67/wreq/commit/5e037ac61cbadc98bb37b3d851d3401e78023fb7))
- *(deps)* Update libc requirement from 2.0.11 to 0.2.172 ([#611](https://github.com/0x676e67/wreq/issues/611)) - ([888ef8a](https://github.com/0x676e67/wreq/commit/888ef8a2b709c113d2dbeac3457d35f61436b741))
- *(deps)* Update async-compression requirement from 0.4.21 to 0.4.23 ([#606](https://github.com/0x676e67/wreq/issues/606)) - ([6dc0026](https://github.com/0x676e67/wreq/commit/6dc002668c72038b87d1bd5e3edae4b47cc2f125))
- *(deps)* Update boring2 requirement from 4.15.11 to 4.15.12 ([#607](https://github.com/0x676e67/wreq/issues/607)) - ([bfe8c12](https://github.com/0x676e67/wreq/commit/bfe8c1256eded7b68826993e91d9729074d699f6))
- *(deps)* Update brotli requirement from 7.0.0 to 8.0.0 ([#601](https://github.com/0x676e67/wreq/issues/601)) - ([86849dd](https://github.com/0x676e67/wreq/commit/86849dd73b5753a3bf0cbddfd613686d6013ab9a))
- *(deps)* Update socket2 requirement from 0.5.8 to 0.5.9 ([#599](https://github.com/0x676e67/wreq/issues/599)) - ([dec8352](https://github.com/0x676e67/wreq/commit/dec8352ca33a74314e7a671858763ced272bc12f))
- *(deps)* Update lru requirement from 0.13 to 0.14 ([#597](https://github.com/0x676e67/wreq/issues/597)) - ([e557749](https://github.com/0x676e67/wreq/commit/e557749d078d50cf2fddf59df094ed5ce591128d))
- *(feature)* Drop redundant `sync_wrapper` ([#817](https://github.com/0x676e67/wreq/issues/817)) - ([a737f56](https://github.com/0x676e67/wreq/commit/a737f56e3c398378726666851773242470cb40a7))
- *(feature)* Rename `websocket` feature to `ws` ([#816](https://github.com/0x676e67/wreq/issues/816)) - ([d15b2d5](https://github.com/0x676e67/wreq/commit/d15b2d530e37299dc9e77559f2c2289424a4799d))
- *(sync)* Remove optional `parking_lot` support - ([b109eb9](https://github.com/0x676e67/wreq/commit/b109eb99c424d92f9912509105b50a26f02bee36))
- Drop `full` feature ([#803](https://github.com/0x676e67/wreq/issues/803)) - ([12b4d64](https://github.com/0x676e67/wreq/commit/12b4d64eba7c2c5c34f89b1a10247814f01be095))
- Drop deprecated `macos-system-configuration` feature ([#775](https://github.com/0x676e67/wreq/issues/775)) - ([7caa4ad](https://github.com/0x676e67/wreq/commit/7caa4ad5327d437ece815fda99635f99f9cd062c))
- Cleanup deprecated feature - ([8d1632b](https://github.com/0x676e67/wreq/commit/8d1632b73e0994091136c7a60a2e801e65e9b440))

### Deps

- *(boring)* Basic support for LoongArch ([#622](https://github.com/0x676e67/wreq/issues/622)) - ([bcc53cf](https://github.com/0x676e67/wreq/commit/bcc53cf260e31605376bc72fb7acae53fb385a4b))
- Prune unnecessary dependencies ([#681](https://github.com/0x676e67/wreq/issues/681)) - ([d9aecea](https://github.com/0x676e67/wreq/commit/d9aecead61dccb481b8d39744ece30d66d1ea41f))

## New Contributors ❤️

* @incizzle made their first contribution in [#608](https://github.com/0x676e67/wreq/pull/608)

## [5.1.0](https://github.com/0x676e67/wreq/compare/v5.0.0..v5.1.0) - 2025-03-29

### ⛰️  Features

- *(cookie)* Optional enable of sending multiple cookies in `CookieStore` ([#578](https://github.com/0x676e67/wreq/issues/578)) - ([6678fbf](https://github.com/0x676e67/wreq/commit/6678fbfa22aa259a20fe1868bb41d94851765492))
- *(cookie)* Cookies feature optionally preserves order ([#573](https://github.com/0x676e67/wreq/issues/573)) - ([803852b](https://github.com/0x676e67/wreq/commit/803852b43e127f0c89aea2a81e75ad4d04c951bd))
- *(proxy)* Enhanced websocket level proxy options ([#569](https://github.com/0x676e67/wreq/issues/569)) - ([a6c9a75](https://github.com/0x676e67/wreq/commit/a6c9a75dd68f99095bbf70cb95d2955b89b2271b))
- *(request)* Optionally allow compression in request ([#581](https://github.com/0x676e67/wreq/issues/581)) - ([dc2c148](https://github.com/0x676e67/wreq/commit/dc2c1483dca066f4bc9b02f3504c5c86edd45438))
- *(x509)* Support for using a private key and X.509 certificate as a client certificate ([#588](https://github.com/0x676e67/wreq/issues/588)) - ([3fbcc89](https://github.com/0x676e67/wreq/commit/3fbcc89775fe0e65e5c5cfa86319350ab4cada7d))
- *(x509)* Auto detect and parse `DER`/`PEM` certificate formats ([#584](https://github.com/0x676e67/wreq/issues/584)) - ([3ab1681](https://github.com/0x676e67/wreq/commit/3ab168126ed4fe41c5dbe5e0bc56d2f87734d679))
- Expose `tls` and `websocket` modules ([#587](https://github.com/0x676e67/wreq/issues/587)) - ([a771463](https://github.com/0x676e67/wreq/commit/a771463508f66314f52a725bca6bb8de042843b7))

### 🐛 Bug Fixes

- *(client)* Adapt sorting for duplicate headers such as cookies ([#576](https://github.com/0x676e67/wreq/issues/576)) - ([a786a85](https://github.com/0x676e67/wreq/commit/a786a8595079b1647c1d1a6ab571ffb199b11a5d))
- *(request)* Fix `try_clone` missing protocol extension ([#579](https://github.com/0x676e67/wreq/issues/579)) - ([0e9872d](https://github.com/0x676e67/wreq/commit/0e9872dd370a8a70d38139b30c14113495418b86))

### 📚 Documentation

- *(request)* Improve request header parameter docs ([#580](https://github.com/0x676e67/wreq/issues/580)) - ([f03c1c8](https://github.com/0x676e67/wreq/commit/f03c1c8d6aff7e2fba2aeb60a03e991f714e9662))
- *(response)* Link to `char::REPLACEMENT_CHARACTER` ([#586](https://github.com/0x676e67/wreq/issues/586)) - ([b0abcb6](https://github.com/0x676e67/wreq/commit/b0abcb636b5c5b86089cfbf1f39ebdc966da1e30))
- Update certificate store description ([#572](https://github.com/0x676e67/wreq/issues/572)) - ([f1b076f](https://github.com/0x676e67/wreq/commit/f1b076f8321987f9d4ece641b557261277128cbb))
- Improved emulation description ([#571](https://github.com/0x676e67/wreq/issues/571)) - ([5924815](https://github.com/0x676e67/wreq/commit/5924815a05b4512381815a2f4d66daf4e855f538))
- Update examples docs ([#570](https://github.com/0x676e67/wreq/issues/570)) - ([591e4b3](https://github.com/0x676e67/wreq/commit/591e4b3e1b63bc5911b6e1f64643c32c7d3475f0))

### ⚡ Performance

- *(cookie)* Optimize the performance of cookies compression ([#574](https://github.com/0x676e67/wreq/issues/574)) - ([6c2280c](https://github.com/0x676e67/wreq/commit/6c2280c82a252f4de2289e74fc88a9d6058a6941))
- *(request)* Improve `json`/`form` request performance ([#583](https://github.com/0x676e67/wreq/issues/583)) - ([cce1fcf](https://github.com/0x676e67/wreq/commit/cce1fcfbad9b6f7d519b0c6f629087bded222ae4))

### 🎨 Styling

- *(client)* Fmt import - ([f509c52](https://github.com/0x676e67/wreq/commit/f509c5298e4f1865f71a862e6882d420b9c06d24))
- *(client)* Fmt code - ([ca9bc96](https://github.com/0x676e67/wreq/commit/ca9bc96d85cfdd90e6f06c1b59b952a46946d98a))
- *(x509)* Fmt code - ([cc6fa5d](https://github.com/0x676e67/wreq/commit/cc6fa5d6bed622d569c50c5153d98e96664bac29))
- *(x509)* Format compatible code ([#589](https://github.com/0x676e67/wreq/issues/589)) - ([a12a414](https://github.com/0x676e67/wreq/commit/a12a414105433151a583a605b9e0a0767639143c))

### 🧪 Testing

- *(badssl)* Dynamically update peer certificate SSL pinning test ([#582](https://github.com/0x676e67/wreq/issues/582)) - ([a87b95f](https://github.com/0x676e67/wreq/commit/a87b95fbe37318a5e0e3a0c3b2e90c39bde49654))

### ⚙️ Miscellaneous Tasks

- *(client)* Remove dead code - ([4de2978](https://github.com/0x676e67/wreq/commit/4de29785cd506fedb82ecfbb2355dcb966984d63))
- *(http)* Rename `ClientInner` to `ClientRef` - ([1d01390](https://github.com/0x676e67/wreq/commit/1d01390103b0e424dfacc211fcb9b56b0c848da6))
- *(tests)* Update client tests conditional ([#577](https://github.com/0x676e67/wreq/issues/577)) - ([684eb89](https://github.com/0x676e67/wreq/commit/684eb89a42febe7175c4f0fa5a2f2d8204514160))

### Build

- *(deps)* Upgrade dependencies ([#575](https://github.com/0x676e67/wreq/issues/575)) - ([cf6daf0](https://github.com/0x676e67/wreq/commit/cf6daf0662268f5f6d64bb06d4d8ea361cac46aa))


## [5.0.0](https://github.com/0x676e67/wreq/compare/v3.0.6..v5.0.0) - 2025-03-23

### ⛰️  Features

- *(client)* Add a straightforward method for SSL pinning setup ([#556](https://github.com/0x676e67/wreq/issues/556)) - ([071d5ed](https://github.com/0x676e67/wreq/commit/071d5ed8ded32e5f40b6d21d2cea39920ddbe355))
- *(client)* Ignore the requirement to configure tls in order ([#545](https://github.com/0x676e67/wreq/issues/545)) - ([213b0ac](https://github.com/0x676e67/wreq/commit/213b0ac73b0cace1cb70dee443de2de1bcc32b16))
- *(cookie)* Impl `into_inner` for `Cookie` ([#542](https://github.com/0x676e67/wreq/issues/542)) - ([1f09ed5](https://github.com/0x676e67/wreq/commit/1f09ed5f46bb105618855e7a22f61b0a61454489))
- *(cookie)* Impl `Display` for `Cookie` ([#541](https://github.com/0x676e67/wreq/issues/541)) - ([729669c](https://github.com/0x676e67/wreq/commit/729669cd23b87e8c303e7ae70c4bf60c9ee0f68c))
- *(cookie)* Impl `into_owned` for cookie ([#535](https://github.com/0x676e67/wreq/issues/535)) - ([04d11ad](https://github.com/0x676e67/wreq/commit/04d11ada3cfe618927bad83304a886c39e7053bb))
- *(error)* Added `Error::is_connection_reset()` - ([8a68b1a](https://github.com/0x676e67/wreq/commit/8a68b1a299b3f44108a475e5837d109c635fbf24))
- *(proxy)* Enhanced client proxy options ([#534](https://github.com/0x676e67/wreq/issues/534)) - ([4edbfef](https://github.com/0x676e67/wreq/commit/4edbfefadbfec1a797c179d3442a1a7b3345ec3f))
- *(proxy)* Enhanced request level proxy options ([#533](https://github.com/0x676e67/wreq/issues/533)) - ([a69ac1b](https://github.com/0x676e67/wreq/commit/a69ac1ba37d4828d5f409ac6124497d7a84af42b))
- *(ws)* Impl `from_bytes_unchecked` of `Utf8Bytes` ([#550](https://github.com/0x676e67/wreq/issues/550)) - ([0663aa5](https://github.com/0x676e67/wreq/commit/0663aa5e44d389d1b34c0ee6efd1d2136c774f57))
- Remove shortcut for quickly make requests ([#560](https://github.com/0x676e67/wreq/issues/560)) - ([cb43f23](https://github.com/0x676e67/wreq/commit/cb43f23f9885a04b595c1caa4eef6323b63845aa))

### 🐛 Bug Fixes

- *(client)* Preserve TLS settings when update client ([#552](https://github.com/0x676e67/wreq/issues/552)) - ([6a2e3e6](https://github.com/0x676e67/wreq/commit/6a2e3e60a6ac92977681c4c43308be05989c5dfe))
- *(client)* Preserve TLS `RootCertStore` settings when update client ([#551](https://github.com/0x676e67/wreq/issues/551)) - ([ad72976](https://github.com/0x676e67/wreq/commit/ad7297660a753a97d614fd9bb657303b04c0eba5))
- *(client)* Preserve TLS verify settings when update client ([#546](https://github.com/0x676e67/wreq/issues/546)) - ([21ad6e8](https://github.com/0x676e67/wreq/commit/21ad6e8beeeced18e928c35c6fee856047944321))
- *(proxy)* Re-enable NO_PROXY envs on Windows ([#544](https://github.com/0x676e67/wreq/issues/544)) - ([f5eb6fe](https://github.com/0x676e67/wreq/commit/f5eb6fe28d167485ceec79afee25180e9b268314))

### 🚜 Refactor

- *(client)* Rename max_retry_count to http2_max_retry_count - ([be29947](https://github.com/0x676e67/wreq/commit/be29947166db5c2ac7bcd3700f6cc50fcc9118dc))
- *(client)* Delete tls fine-tuning config ([#530](https://github.com/0x676e67/wreq/issues/530)) - ([d7a75e3](https://github.com/0x676e67/wreq/commit/d7a75e393aa8d48b570d15aa66ce600a2ac8691c))
- *(cookie)* Redesign cookie store API signature ([#538](https://github.com/0x676e67/wreq/issues/538)) - ([2968839](https://github.com/0x676e67/wreq/commit/2968839c37c01950fd2be037c7bec1d64381f1f9))
- *(cookie)* `max_age` type conversion fails to avoid panic ([#536](https://github.com/0x676e67/wreq/issues/536)) - ([ceb0bd5](https://github.com/0x676e67/wreq/commit/ceb0bd5d05886fb172a33da2c23f69078ed147a0))
- *(tls)* Simplify RootCertStore wrapper implementation ([#553](https://github.com/0x676e67/wreq/issues/553)) - ([b24bc40](https://github.com/0x676e67/wreq/commit/b24bc4060e84734b0fa99d35f111c5638ec1bdb7))
- Unified naming of historical legacy APIs - ([c7c6a0d](https://github.com/0x676e67/wreq/commit/c7c6a0db32445dda27b285e4c7a812f4ca236b39))
- Unified naming of historical legacy APIs ([#554](https://github.com/0x676e67/wreq/issues/554)) - ([9022641](https://github.com/0x676e67/wreq/commit/902264184d938d8b8cb138dbc28e8eca1e25891d))

### 📚 Documentation

- *(client)* Update emulation method documentation - ([5dd33ab](https://github.com/0x676e67/wreq/commit/5dd33aba02be7d6b0136a5d6e839d9974f1303d3))
- *(client)* Deleting outdated documents ([#532](https://github.com/0x676e67/wreq/issues/532)) - ([2cffe47](https://github.com/0x676e67/wreq/commit/2cffe471deca62c86ed18346cbd7b12caf2e0579))
- *(cookie)* Delete irrelevant library documents - ([6c44c38](https://github.com/0x676e67/wreq/commit/6c44c38f589057f3a64bb7152a34ca62630b7586))
- *(response)* Clarify in docs that `Response::content_length()` is not based on the `Content-Length` header ([#558](https://github.com/0x676e67/wreq/issues/558)) - ([5c174c4](https://github.com/0x676e67/wreq/commit/5c174c48b4ec09544de379c5254fc11e74d5bd7b))
- *(response)* Clarify that content_length() is not based on the Content-Length header in the docs - ([7257f34](https://github.com/0x676e67/wreq/commit/7257f34ca23c7cd0b9f0a1aa6e0da3507ad58956))
- Update library examples - ([62d6266](https://github.com/0x676e67/wreq/commit/62d6266f425e83ad0998d1b2f290cb56d44df93f))
- Update features description ([#540](https://github.com/0x676e67/wreq/issues/540)) - ([bd18719](https://github.com/0x676e67/wreq/commit/bd1871957df8304a0a55485cc7c2eb3e5add00bc))

### ⚡ Performance

- *(client)* Fine-tune request performance and testing ([#566](https://github.com/0x676e67/wreq/issues/566)) - ([a07c233](https://github.com/0x676e67/wreq/commit/a07c2332cc751a98d48e0a8cf3fca958e19f09e3))
- *(http)* Inline hotspot method ([#528](https://github.com/0x676e67/wreq/issues/528)) - ([2038231](https://github.com/0x676e67/wreq/commit/20382318693de4e2aaa4b55c3943c5ad1bd2689c))

### 🧪 Testing

- *(badssl)* Update ssl pinning test ([#557](https://github.com/0x676e67/wreq/issues/557)) - ([b883d7f](https://github.com/0x676e67/wreq/commit/b883d7fb9b7b6c6f1b5b48271bd4d5c7de9666d8))

### ⚙️ Miscellaneous Tasks

- *(emulation)* Impl `default` for EmulationProvider - ([b726363](https://github.com/0x676e67/wreq/commit/b7263637f23bac976a54fe644b96f89047217647))
- *(tls)* Simplified `IntoCertStore` macro impl ([#562](https://github.com/0x676e67/wreq/issues/562)) - ([5052342](https://github.com/0x676e67/wreq/commit/505234223f28dd749f10414e1fee9161119e1d98))
- *(tls)* Simplified `IntoCertCompressionAlgorithm` macro impl ([#561](https://github.com/0x676e67/wreq/issues/561)) - ([a7606d9](https://github.com/0x676e67/wreq/commit/a7606d9d50cc295dfbd5374a55c6841f790ae6c2))
- Update example documentation crate package name - ([363e98b](https://github.com/0x676e67/wreq/commit/363e98b6b97809f2a6802a131e884cb302430da8))
- Update apache license copyright - ([50d73a3](https://github.com/0x676e67/wreq/commit/50d73a35afd3c482538a23f34e125bfbd9be6f69))

### Build

- *(action)* Added compression features tests ([#564](https://github.com/0x676e67/wreq/issues/564)) - ([5767ce8](https://github.com/0x676e67/wreq/commit/5767ce81d59b5f1d0e2e702c2200dfd3713b4f0b))
- *(action)* Added features tests ([#563](https://github.com/0x676e67/wreq/issues/563)) - ([b8f7968](https://github.com/0x676e67/wreq/commit/b8f7968f0ed52d6fe6282ef189fe8f8514ba1071))
- *(action)* Added check semver action ([#559](https://github.com/0x676e67/wreq/issues/559)) - ([a58e989](https://github.com/0x676e67/wreq/commit/a58e989819fb29e89823ee764d26df2646a840e2))
- *(deps)* Pin `async-compression` to version `0.4.21` ([#567](https://github.com/0x676e67/wreq/issues/567)) - ([0be61d7](https://github.com/0x676e67/wreq/commit/0be61d7db8641170ca143220de348b1e423d8f83))
- *(deps)* Pin `tokio-tungstenite` to version `0.26.2` ([#565](https://github.com/0x676e67/wreq/issues/565)) - ([a5ee2a2](https://github.com/0x676e67/wreq/commit/a5ee2a2d99fcb1c8afab7a2636c7c657132744ed))
- *(deps)* Update hickory-resolver requirement from 0.24 to 0.25 ([#549](https://github.com/0x676e67/wreq/issues/549)) - ([f7de3f5](https://github.com/0x676e67/wreq/commit/f7de3f5ba54c9bbb4701138a69adeaa563c9b4c0))
- *(deps)* Update typed-builder requirement from 0.20.0 to 0.21.0 ([#548](https://github.com/0x676e67/wreq/issues/548)) - ([099c257](https://github.com/0x676e67/wreq/commit/099c257ef3d244a464633deb04ccca6cd4a87898))


## [3.0.6](https://github.com/0x676e67/wreq/compare/v3.0.5..v3.0.6) - 2025-03-10

### ⛰️  Features

- *(ws)* Improved WebSocket message creation ([#524](https://github.com/0x676e67/wreq/issues/524)) - ([508d869](https://github.com/0x676e67/wreq/commit/508d8695216a1ca28c91fe5d9e04cce745839a67))

### 🧪 Testing

- *(zstd)* Test connection reuse with new zstd decompression ([#522](https://github.com/0x676e67/wreq/issues/522)) - ([a277f80](https://github.com/0x676e67/wreq/commit/a277f8036da135533efd55bd561941b992cfb1fa))


## [3.0.5](https://github.com/0x676e67/wreq/compare/v3.0.3..v3.0.5) - 2025-03-09

### ⛰️  Features

- *(tls)* Allow overriding AES encryption for TLS ECH ([#515](https://github.com/0x676e67/wreq/issues/515)) - ([0045e3d](https://github.com/0x676e67/wreq/commit/0045e3d105a1c38ffb1ceb1cdc15cb2d4265e9ac))

### 🐛 Bug Fixes

- *(decoder)* Handle multi-frame zstd response body decompression ([#517](https://github.com/0x676e67/wreq/issues/517)) - ([bbc02ae](https://github.com/0x676e67/wreq/commit/bbc02ae0a837138054321bfcb8223a3fafd2e286))

### ⚙️ Miscellaneous Tasks

- *(connect)* Remove `ServiceBuilder` dead code ([#518](https://github.com/0x676e67/wreq/issues/518)) - ([8cf0dc4](https://github.com/0x676e67/wreq/commit/8cf0dc4034707e73205cc5849c473e2a6ca87201))
- Update docs - ([d077c3d](https://github.com/0x676e67/wreq/commit/d077c3d40b43441ddebd8d3049b4d9094b23ec3b))


## [3.0.3](https://github.com/0x676e67/wreq/compare/v3.0.1..v3.0.3) - 2025-03-07

### 🐛 Bug Fixes

- *(decoder)* Fix conditional compilation of decompress features ([#507](https://github.com/0x676e67/wreq/issues/507)) - ([8ffa73b](https://github.com/0x676e67/wreq/commit/8ffa73bdd6a8aea1651f31f2a70c6ed727cd65f3))

### 🎨 Styling

- Clippy fix example `set_root_cert_store` - ([9b3b49a](https://github.com/0x676e67/wreq/commit/9b3b49ac5172d09369b64a1b3b4cfe3550139fb8))

### ⚙️ Miscellaneous Tasks

- Remove pub(super) visibility from `method_has_defined_payload_semantics` - ([b689112](https://github.com/0x676e67/wreq/commit/b689112bdb1bd60798e264ba43b5d073009df0f1))

### Build

- *(deps)* Update async-compression requirement from 0.4.0 to 0.4.20 ([#505](https://github.com/0x676e67/wreq/issues/505)) - ([71562ce](https://github.com/0x676e67/wreq/commit/71562ce70b0418fbd0a516727bb6107f83585f89))
- *(deps)* Update bytes requirement from 1.0 to 1.10.1 ([#504](https://github.com/0x676e67/wreq/issues/504)) - ([c10f5e1](https://github.com/0x676e67/wreq/commit/c10f5e15c63660ac33413d6c929a11ac70302e53))


## [3.0.1-rc4](https://github.com/0x676e67/wreq/compare/v3.0.1-rc3..v3.0.1-rc4) - 2025-03-05

### ⛰️  Features

- *(cert)* Expose `RootCertStoreBuilder` as public API ([#494](https://github.com/0x676e67/wreq/issues/494)) - ([849558f](https://github.com/0x676e67/wreq/commit/849558f2607e7b23521193c74e794cc192decf76))

### 🚜 Refactor

- *(client)* Simplify DNS resolver initialization in ClientBuilder ([#499](https://github.com/0x676e67/wreq/issues/499)) - ([1368d07](https://github.com/0x676e67/wreq/commit/1368d075121a9cb9d2f9ca9cb674264e84c5e4e5))
- *(client)* `pool_max_size` signature changed from `Into<Option<NonZeroUsize>>` to `usize` ([#498](https://github.com/0x676e67/wreq/issues/498)) - ([57223e2](https://github.com/0x676e67/wreq/commit/57223e2ed4996239b8cfa696c68f550104de9f65))

### 📚 Documentation

- *(emulation)* Improve emulation documentation - ([776f2db](https://github.com/0x676e67/wreq/commit/776f2dbd18fa5fb3f635dceb2d22e92af358405d))
- Update docs ([#496](https://github.com/0x676e67/wreq/issues/496)) - ([a4862e8](https://github.com/0x676e67/wreq/commit/a4862e870d002f71761863bae22ec81de2bc5f52))

### ⚡ Performance

- *(clinet)* Reading `user-agent` to avoid full clone ([#495](https://github.com/0x676e67/wreq/issues/495)) - ([89fd750](https://github.com/0x676e67/wreq/commit/89fd750e8f239c0bb31cf8699d7d4a54440933c0))
- *(decoder)* Statically check compression headers ([#503](https://github.com/0x676e67/wreq/issues/503)) - ([c912d8d](https://github.com/0x676e67/wreq/commit/c912d8d428b6787f4203a06ff9d2fd7abc6fb3d2))

### 🎨 Styling

- *(network)* Fmt code - ([5941b39](https://github.com/0x676e67/wreq/commit/5941b390b46de184ecb57160cd64d08a7ab708e0))

### ⚙️ Miscellaneous Tasks

- Revert `impl_debug` export - ([3fc3f69](https://github.com/0x676e67/wreq/commit/3fc3f697982cee4fc24e28e10cfba04ceeaf1773))


## [3.0.1-rc3](https://github.com/0x676e67/wreq/compare/v3.0.1-rc2..v3.0.1-rc3) - 2025-03-04

### ⛰️  Features

- *(cookie)* Abstract public cookie store trait ([#493](https://github.com/0x676e67/wreq/issues/493)) - ([a565884](https://github.com/0x676e67/wreq/commit/a5658847433928673964b79a7937b35dc4db6296))
- *(proxy)* Supports `http`/`https` proxy custom headers ([#490](https://github.com/0x676e67/wreq/issues/490)) - ([02fdc5b](https://github.com/0x676e67/wreq/commit/02fdc5bcd1b40d27538163279f4424a666957eef))

### 🧪 Testing

- Update badssl test ([#487](https://github.com/0x676e67/wreq/issues/487)) - ([8831a9e](https://github.com/0x676e67/wreq/commit/8831a9e42d67dd5234955fc4594f8d3e564b04cc))

### ⚙️ Miscellaneous Tasks

- Replace `get_or_insert_with(Vec::new)` to `get_or_insert_default()` - ([2ca23a1](https://github.com/0x676e67/wreq/commit/2ca23a17068ef5c1b132029abcb25b47db029db7))

### Build

- `MSRV 1.85` / `edition 2024` ([#488](https://github.com/0x676e67/wreq/issues/488)) - ([f5bcc71](https://github.com/0x676e67/wreq/commit/f5bcc71d70a86e52a19596988c1ed08f71c12769))


## [3.0.1-rc2](https://github.com/0x676e67/wreq/compare/v3.0.1-rc1..v3.0.1-rc2) - 2025-03-03

### 🚜 Refactor

- *(client)* Rename `as_mut` to `update` for clarity and consistency   ([#482](https://github.com/0x676e67/wreq/issues/482)) - ([e8137ec](https://github.com/0x676e67/wreq/commit/e8137ec6448e53124b58d5c7e4bdb7eb1d923bb7))

### 🎨 Styling

- *(client)* Fmt code - ([897a373](https://github.com/0x676e67/wreq/commit/897a373b460ea3e0c8558e9d72843ef28578e61a))

### 🧪 Testing

- Add client cloned test ([#485](https://github.com/0x676e67/wreq/issues/485)) - ([4a5419b](https://github.com/0x676e67/wreq/commit/4a5419b56d57a54b1cfde121fee9f41acb6c411f))
- Add client emulation update test ([#484](https://github.com/0x676e67/wreq/issues/484)) - ([f72648f](https://github.com/0x676e67/wreq/commit/f72648feafe1440dc1ae942b75421faf940fff76))
- Add client headers update test ([#483](https://github.com/0x676e67/wreq/issues/483)) - ([730fdaa](https://github.com/0x676e67/wreq/commit/730fdaa3b18c7e0d2e2c732a408677ba8c483854))

### ⚙️ Miscellaneous Tasks

- *(client)* Update docs - ([bbcdd1f](https://github.com/0x676e67/wreq/commit/bbcdd1f15843c63aa8fee47ac0507620fb9468e6))

### Build

- Fix docs build ([#486](https://github.com/0x676e67/wreq/issues/486)) - ([915c36b](https://github.com/0x676e67/wreq/commit/915c36bb4a666be3acd26a4416a39534e661419b))


## [3.0.1-rc1](https://github.com/0x676e67/wreq/compare/v2.0.3..v3.0.1-rc1) - 2025-03-03

### ⛰️  Features

- *(client)* Remove cross-origin redirect proxy support ([#477](https://github.com/0x676e67/wreq/issues/477)) - ([3a241ef](https://github.com/0x676e67/wreq/commit/3a241ef4b342b1bd46a8e4cd7ecbeb641d043b4f))
- *(client)* Added a remove cookie function ([#475](https://github.com/0x676e67/wreq/issues/475)) - ([7142963](https://github.com/0x676e67/wreq/commit/71429634012e03a710793591727cbf4bd5d8de28))
- *(client)* Remove `set_cookies_by_ref` ([#474](https://github.com/0x676e67/wreq/issues/474)) - ([56de727](https://github.com/0x676e67/wreq/commit/56de72716b1cd89f724f8720dc3fa2fb75ac0399))
- *(client)* Added a clear cookies function ([#472](https://github.com/0x676e67/wreq/issues/472)) - ([d934716](https://github.com/0x676e67/wreq/commit/d93471631440a28a0dfb63dad85f4acf3768cab2))
- *(client)* Adapt thread-safe update client configuration ([#404](https://github.com/0x676e67/wreq/issues/404)) - ([e6397d6](https://github.com/0x676e67/wreq/commit/e6397d68f216a86e75b46bb2f7b9345ecf58e08f))
- *(client)* Apply configuration sequentially ([#391](https://github.com/0x676e67/wreq/issues/391)) - ([775db82](https://github.com/0x676e67/wreq/commit/775db824653b162e4dfc6bb14c79b811206f79c2))
- *(imp)* Add `chrome 132`/`chrome 133` impersonate ([#423](https://github.com/0x676e67/wreq/issues/423)) - ([3430645](https://github.com/0x676e67/wreq/commit/34306457c0ba01f95e46b5b0bbe443a3abe3fb87))
- *(pool)* Connection pool distinguishes request versions ([#431](https://github.com/0x676e67/wreq/issues/431)) - ([22b0e92](https://github.com/0x676e67/wreq/commit/22b0e92835a786be030f405fd70ea311cecb6de4))
- *(proxy)* Add `socks4a` proxy protocol support ([#416](https://github.com/0x676e67/wreq/issues/416)) - ([1f98b6e](https://github.com/0x676e67/wreq/commit/1f98b6e2578ab55ff4fcfb86c66548a7161469a7))
- *(tls)* Encapsulate and simplify certificate loading ([#417](https://github.com/0x676e67/wreq/issues/417)) - ([a32207e](https://github.com/0x676e67/wreq/commit/a32207ef84057e042b69068fee2179b0a059cd51))
- *(tls)* Add ALPS use new endpoint extension ([#396](https://github.com/0x676e67/wreq/issues/396)) - ([20b988c](https://github.com/0x676e67/wreq/commit/20b988c04e4a8a334d702b74a54e46d149b9802a))
- *(websocket)* Added `read_buffer_size` optional config ([#457](https://github.com/0x676e67/wreq/issues/457)) - ([ccece59](https://github.com/0x676e67/wreq/commit/ccece597da6db3f085acf13718af93ea3acffab9))
- *(websocket)* Chain call wrapper `RequestBuilder` ([#432](https://github.com/0x676e67/wreq/issues/432)) - ([ea3dfe8](https://github.com/0x676e67/wreq/commit/ea3dfe88c7dbcf4b9f13a70ac29aa306f17fdf91))
- *(websocket)* Explicitly force the use of ws/wss protocol ([#383](https://github.com/0x676e67/wreq/issues/383)) - ([4fd10a9](https://github.com/0x676e67/wreq/commit/4fd10a951977580b74f60d5ede81833ae0f484cf))
- Removal of base url feature  ([#411](https://github.com/0x676e67/wreq/issues/411)) - ([16dac1d](https://github.com/0x676e67/wreq/commit/16dac1d122381d27ed3f5948766a1d9a13ca8d9d))
- Add optional clear method to `CookieStore` implementation ([#400](https://github.com/0x676e67/wreq/issues/400)) - ([a357c9e](https://github.com/0x676e67/wreq/commit/a357c9e1eed9c9d51fd10d3eb98109104928cef5))
- Serializing impersonate enums uses legacy naming conventions ([#385](https://github.com/0x676e67/wreq/issues/385)) - ([0e3ddb0](https://github.com/0x676e67/wreq/commit/0e3ddb06d3690661806d6f1dc8731e8d337ad4a0))
- Add `HTTP/2` support for `WebSocket` ([#373](https://github.com/0x676e67/wreq/issues/373)) - ([b46daa9](https://github.com/0x676e67/wreq/commit/b46daa90fd11e475b7b8238e1ab5d573b8a531b2))

### 🐛 Bug Fixes

- *(deps)* Fix alps use new endpoint negotiation ([#464](https://github.com/0x676e67/wreq/issues/464)) - ([21c6751](https://github.com/0x676e67/wreq/commit/21c675123e1f117633d604290c94e5aa333ec4ab))
- *(proxy)* Fix `no_proxy` on Windows ([#470](https://github.com/0x676e67/wreq/issues/470)) - ([16ec933](https://github.com/0x676e67/wreq/commit/16ec933045a707a244eebc98edb17ae1314766a6))
- Ignore Content-Length for methods without payload semantics ([#429](https://github.com/0x676e67/wreq/issues/429)) - ([bd5420c](https://github.com/0x676e67/wreq/commit/bd5420c4d526f05b4430bd7e60f5f5df27fffa11))
- Ensure HTTP version negotiation for non-TLS requests ([#397](https://github.com/0x676e67/wreq/issues/397)) - ([dd14d49](https://github.com/0x676e67/wreq/commit/dd14d49a2d579f9d36a49f38c5d9de373901d492))

### 🚜 Refactor

- *(client)* Simplify client reference handling by removing unnecessary operations ([#476](https://github.com/0x676e67/wreq/issues/476)) - ([529928b](https://github.com/0x676e67/wreq/commit/529928b4bae30b2ec4fadd2c91185f3417919ea8))
- *(client)* Refactor client `HTTP1`/`HTTP2` configuration API ([#371](https://github.com/0x676e67/wreq/issues/371)) - ([fac8d2d](https://github.com/0x676e67/wreq/commit/fac8d2d9cf6df102e101c4f8d9fda72bd2382935))
- *(tls)* Refactor TLS connector structure ([#421](https://github.com/0x676e67/wreq/issues/421)) - ([bdd3942](https://github.com/0x676e67/wreq/commit/bdd394210ffa26d0e2956c73606436685bc962da))
- *(websocket)* Refactor websocket implementation ([#380](https://github.com/0x676e67/wreq/issues/380)) - ([3b91be4](https://github.com/0x676e67/wreq/commit/3b91be4225aa060b43c00103af6fe5fa14a093dd))
- *(websocket)* Improve error handling, rename APIs, and update API signatures ([#372](https://github.com/0x676e67/wreq/issues/372)) - ([44ec8c6](https://github.com/0x676e67/wreq/commit/44ec8c600119c46112b182b268263aa272139b10))
- Move device fingerprinting to rquest-util maintenance ([#480](https://github.com/0x676e67/wreq/issues/480)) - ([5eb8684](https://github.com/0x676e67/wreq/commit/5eb868442018da9e7be15f9844392093ff5baa21))
- Reduce dependency on `futures-core` / `futures-util` ([#449](https://github.com/0x676e67/wreq/issues/449)) - ([5a4f2be](https://github.com/0x676e67/wreq/commit/5a4f2be065bb1edc3c1e39fe9fe2b8c993078260))
- Replace `HttpContext` with `EmulationProvider` for clarity and accuracy ([#436](https://github.com/0x676e67/wreq/issues/436)) - ([6a9d80a](https://github.com/0x676e67/wreq/commit/6a9d80a5cfa85b13b0a3b7bd08422ba0c563cf4a))
- Replace "impersonate" with "emulation" for clarity and accuracy ([#434](https://github.com/0x676e67/wreq/issues/434)) - ([e2bac75](https://github.com/0x676e67/wreq/commit/e2bac75805fdefd79c3cba32cadd65107060558b))
- Replace unsafe methods with safe methods for certificate handler ([#399](https://github.com/0x676e67/wreq/issues/399)) - ([bdf1fc5](https://github.com/0x676e67/wreq/commit/bdf1fc57d2150e7e471331abd1d745e7f786dbd7))
- Replace unsafe methods with safe methods in `ConnectConfiguration` ([#398](https://github.com/0x676e67/wreq/issues/398)) - ([dda0d42](https://github.com/0x676e67/wreq/commit/dda0d42388623c14838396624b2d56a8b572c2f7))
- Improve client API design and documentation ([#387](https://github.com/0x676e67/wreq/issues/387)) - ([7a63ba6](https://github.com/0x676e67/wreq/commit/7a63ba6e10734b233bbcce87c42a4978fccb7b25))
- Rename method to accept_key for clarity - ([c32dadd](https://github.com/0x676e67/wreq/commit/c32daddb394d5b35009fc445c1e0f247a5c48ba0))

### 📚 Documentation

- *(client)* Update client `cloned` method documentation ([#409](https://github.com/0x676e67/wreq/issues/409)) - ([7d10ce6](https://github.com/0x676e67/wreq/commit/7d10ce6be0b26d7b99f24a720e171f84c8b9e41c))
- Added backport reference docs ([#382](https://github.com/0x676e67/wreq/issues/382)) - ([7f57bd5](https://github.com/0x676e67/wreq/commit/7f57bd5876020cb827c2ac3161e4ef080e96718d))

### ⚡ Performance

- *(connect)* Delay connector layer initialization to improve performance ([#408](https://github.com/0x676e67/wreq/issues/408)) - ([4903458](https://github.com/0x676e67/wreq/commit/4903458b81b161aac51ded38a562f139e08d94c9))
- *(connector)* Optimize performance of switching TLS connector ([#406](https://github.com/0x676e67/wreq/issues/406)) - ([26f58e4](https://github.com/0x676e67/wreq/commit/26f58e4e39b1d9d0eb6525862a5ff146fff4ef5c))
- *(socks)* Socks connection process DNS uses non-blocking query ([#420](https://github.com/0x676e67/wreq/issues/420)) - ([0d40c75](https://github.com/0x676e67/wreq/commit/0d40c75b1edc117fa81431256ca7f6510618ea43))
- Always inline `into_tungstenite` ([#381](https://github.com/0x676e67/wreq/issues/381)) - ([b5e0b9f](https://github.com/0x676e67/wreq/commit/b5e0b9f0263248669940c702868c5afcdc01cc76))

### 🎨 Styling

- Fmt code - ([e3ac7a7](https://github.com/0x676e67/wreq/commit/e3ac7a76ccdb98a3b143607f8d3f8f7293421b4e))

### 🧪 Testing

- *(upgrade)* Add http2 upgrade test ([#384](https://github.com/0x676e67/wreq/issues/384)) - ([0724836](https://github.com/0x676e67/wreq/commit/0724836dbfae85bf118f4caf4de19ae3d878b60e))
- Add unit test for cookie getter and setter functionality ([#451](https://github.com/0x676e67/wreq/issues/451)) - ([b71032e](https://github.com/0x676e67/wreq/commit/b71032e0229aa86b737426b643fabfaf549a854b))
- Serialize tests that read/write the same environment variable ([#443](https://github.com/0x676e67/wreq/issues/443)) - ([b7560f9](https://github.com/0x676e67/wreq/commit/b7560f97998e4221472c32688ab7bea5df61edb6))

### ⚙️ Miscellaneous Tasks

- *(client)* Delete unnecessary clone - ([9793bcc](https://github.com/0x676e67/wreq/commit/9793bccbb2f4d6d45dfc90ec028222cdf065f29c))
- *(client)* Rename client builder http2 timer name from `timer` to `http2_timer` ([#407](https://github.com/0x676e67/wreq/issues/407)) - ([e06d9ce](https://github.com/0x676e67/wreq/commit/e06d9ce8dd4f9f1a5f89c0ff3372869275f526b5))
- *(connect)* Delete duplicate tls info acquisition logic - ([4b7877a](https://github.com/0x676e67/wreq/commit/4b7877a3805afb071931358e0a0f69c42e8b05c0))
- *(connect)* Delete connector unnecessary keepalive field - ([08b5904](https://github.com/0x676e67/wreq/commit/08b5904ffb0374f6c327442a314615e6893b6c63))
- *(example)* Update websocket example - ([2479972](https://github.com/0x676e67/wreq/commit/24799723f580badf92e81b3e972ad8cc2b0995f1))
- *(tls)* Move `conf` to `client/conf` module - ([988e679](https://github.com/0x676e67/wreq/commit/988e67949ca9162e6449d41700e5bbbccdb84d2d))
- *(tls)* Move `TlsConfig` to conf module - ([ffd1673](https://github.com/0x676e67/wreq/commit/ffd1673e3afa379086bc04b7a744e8733512388b))
- *(websocket)* Simplify error handling and improve code readability ([#418](https://github.com/0x676e67/wreq/issues/418)) - ([60fa74d](https://github.com/0x676e67/wreq/commit/60fa74dc0abba1862d23adc4965152b1896eb3e4))
- *(websocket)* Fmt code - ([a313ba0](https://github.com/0x676e67/wreq/commit/a313ba0f2707148e023f0126cc895788e3d42bfe))
- *(websocket)* Improved version protocol handler - ([81a0183](https://github.com/0x676e67/wreq/commit/81a0183b14dbe9596c6eb4466656247d92563e62))
- Update examples - ([7cc6b1e](https://github.com/0x676e67/wreq/commit/7cc6b1e5b3a836bcf0e33f9994bb5a162ed76ad2))
- Add Crates.io MSRV - ([cc8cc28](https://github.com/0x676e67/wreq/commit/cc8cc284e7e7b976622a47271b273fa03a33a82b))
- Update the compilation guide ([#466](https://github.com/0x676e67/wreq/issues/466)) - ([5ad4de9](https://github.com/0x676e67/wreq/commit/5ad4de96c5938c1d7c8ea399495b1f377ecf8f66))
- Update compilation-guide ([#456](https://github.com/0x676e67/wreq/issues/456)) - ([723e0c1](https://github.com/0x676e67/wreq/commit/723e0c16d6ac923b8cc51312b2c2424366c0d915))
- Merge v2 branch - ([8180cbc](https://github.com/0x676e67/wreq/commit/8180cbcc4f60d3ab6916ad07df8f1354e230c39f))
- Improve Debug implementation ([#422](https://github.com/0x676e67/wreq/issues/422)) - ([566a33b](https://github.com/0x676e67/wreq/commit/566a33b3102b546f7f7c36161f4f98ae78bf2cb7))
- Fmt code - ([8b3c8f6](https://github.com/0x676e67/wreq/commit/8b3c8f6b1f5e19400ae33fdce85e3169d98c80ba))
- Simplified error qualifier types ([#412](https://github.com/0x676e67/wreq/issues/412)) - ([35b4347](https://github.com/0x676e67/wreq/commit/35b4347a35453b531f8339a9efe62b80a0ecd164))
- Rename `Proxies` internal fields - ([dfe4a00](https://github.com/0x676e67/wreq/commit/dfe4a00c505dcd7ec5802b51dd685f25e6559831))
- Update docs - ([6eb42e8](https://github.com/0x676e67/wreq/commit/6eb42e83452aab5d7921c56d7c1120cad676d805))
- Move `http1`/`http2` config to `conf` mod - ([592038f](https://github.com/0x676e67/wreq/commit/592038ff1468ad0a59aff1057410c6cffc8d6e04))
- Update client docs - ([6a35a0a](https://github.com/0x676e67/wreq/commit/6a35a0aa8ea2ccd4483b160ee1a19f97b539c7c8))
- Fix `AlpnProtos` non upper case globals warning - ([265d938](https://github.com/0x676e67/wreq/commit/265d9388ae524fbed133136f114835f5175b9bd0))
- Fix non upper case globals name - ([af02660](https://github.com/0x676e67/wreq/commit/af02660acffa86d48f0246d75de3e291869e86f6))
- Remove dead code - ([00e939a](https://github.com/0x676e67/wreq/commit/00e939ac1a68950131713575d3eae60d1a1b621c))
- Fmt code - ([096eef0](https://github.com/0x676e67/wreq/commit/096eef07bea970ef4fff57073e456c8269b992a6))
- Fmt imports ([#388](https://github.com/0x676e67/wreq/issues/388)) - ([d73d1ac](https://github.com/0x676e67/wreq/commit/d73d1ac0dde1faeda4186aa17051849067e48c63))
- Fmt code - ([05a9d40](https://github.com/0x676e67/wreq/commit/05a9d406b6bf2beb8066994fcc7269a01f900183))
- Fmt code - ([ff3ad03](https://github.com/0x676e67/wreq/commit/ff3ad037e5ad4ca83d1928631a9d88d754ef1cb1))
- Clippy fix - ([895db54](https://github.com/0x676e67/wreq/commit/895db54492677791693f760b6498d4b1eb9b619b))
- Update websocket examples - ([4eefefd](https://github.com/0x676e67/wreq/commit/4eefefd464d4d0580651fdbe38c832d3f53b1e59))
- Improved WebSocket protocols handler ([#370](https://github.com/0x676e67/wreq/issues/370)) - ([2abe066](https://github.com/0x676e67/wreq/commit/2abe06620c5de829db87ce8e7589d9864aa6d2ec))

### Build

- *(deps)* Update windows-registry requirement from 0.4.0 to 0.5.0 ([#471](https://github.com/0x676e67/wreq/issues/471)) - ([288e33a](https://github.com/0x676e67/wreq/commit/288e33aac4cbf0b3d6b51df38eb88952778eb447))
- *(deps)* Update boring requirement from 4.15.7 to 4.15.8 ([#468](https://github.com/0x676e67/wreq/issues/468)) - ([3488f17](https://github.com/0x676e67/wreq/commit/3488f17e9019735af1ec934027c1ec7c8bd28780))
- *(deps)* Update boring requirement from 4.15.5 to 4.15.6 - ([04659bb](https://github.com/0x676e67/wreq/commit/04659bbae0f4ded2e4a0f45f69e69c23da2f7e8d))
- *(deps)* Update boring requirement from 4.15.3 to 4.15.5 ([#437](https://github.com/0x676e67/wreq/issues/437)) - ([b172177](https://github.com/0x676e67/wreq/commit/b1721771a8f1cfa5af7aa9006484b9bfd1c2fff2))
- *(deps)* Update boring requirement from 4.15.2 to 4.15.3 ([#425](https://github.com/0x676e67/wreq/issues/425)) - ([aff379e](https://github.com/0x676e67/wreq/commit/aff379e045dc1c8bda0eeec9d091c08e9f5db86b))
- *(deps)* Apple platform dependencies are minimized as much as possible ([#414](https://github.com/0x676e67/wreq/issues/414)) - ([858d911](https://github.com/0x676e67/wreq/commit/858d91196299e9a8f2851981d50b5421b530b580))
- *(deps)* MacOS platform dependency is minimized ([#413](https://github.com/0x676e67/wreq/issues/413)) - ([f85c7ee](https://github.com/0x676e67/wreq/commit/f85c7ee337a74ef2686a0cc01870cc05eee031fc))
- *(deps)* Update brotli requirement from 6.0.0 to 7.0.0 ([#401](https://github.com/0x676e67/wreq/issues/401)) - ([50614a7](https://github.com/0x676e67/wreq/commit/50614a74a02991124cf0a20ba09de993b79e1223))
- *(deps)* Update lru requirement from 0.12 to 0.13 ([#393](https://github.com/0x676e67/wreq/issues/393)) - ([b3cda7d](https://github.com/0x676e67/wreq/commit/b3cda7d7f9efd9b7c35a5cd0c5a8a8588bb54897))
- *(feature)* `apple-bindable-device` rename to `apple-network-device-binding` ([#426](https://github.com/0x676e67/wreq/issues/426)) - ([05a1adb](https://github.com/0x676e67/wreq/commit/05a1adb626a0614fd13a04fbeb7ae3d5304e4d8b))
- Fix no default feature build - ([8ed417d](https://github.com/0x676e67/wreq/commit/8ed417df8fbbb14ec9f319219d6ca750200bd192))
- Visualize macro conditional compilation ([#415](https://github.com/0x676e67/wreq/issues/415)) - ([01f1387](https://github.com/0x676e67/wreq/commit/01f138738785dd1391a06d1ff015ea7eacc727c1))
- Update compilation guide ([#395](https://github.com/0x676e67/wreq/issues/395)) - ([96c75a4](https://github.com/0x676e67/wreq/commit/96c75a4be224d2be0275d101d43eb219489d7494))

### Deps

- *(ipnet)* Bump version to v2.11.0 ([#390](https://github.com/0x676e67/wreq/issues/390)) - ([2022b25](https://github.com/0x676e67/wreq/commit/2022b256d1d88dd991a3ed48f7c4678eb0f60f7c))
- *(tokio)* Remove unused `rt` feature ([#389](https://github.com/0x676e67/wreq/issues/389)) - ([545e245](https://github.com/0x676e67/wreq/commit/545e2456db7353b2909c85d9b3186dbe6d8100e2))

### Workflow

- Update workflows check - ([321fba2](https://github.com/0x676e67/wreq/commit/321fba2939253f51637b5b18dd1dfc9990dc0d2d))

## New Contributors ❤️

* @tahmid-23 made their first contribution in [#423](https://github.com/0x676e67/wreq/pull/423)

## [2.0.3](https://github.com/0x676e67/wreq/compare/v2.0.2..v2.0.3) - 2025-01-25

### 📚 Documentation

- Enhance documentation for `ImpersonateBuilder` methods ([#367](https://github.com/0x676e67/wreq/issues/367)) - ([d0dd33f](https://github.com/0x676e67/wreq/commit/d0dd33f22325b16138d743b03a39674daf8d89c8))

### ⚙️ Miscellaneous Tasks

- Update examples ([#368](https://github.com/0x676e67/wreq/issues/368)) - ([477e864](https://github.com/0x676e67/wreq/commit/477e864673d5e684070b54f44b48896760a05ef5))


## [2.0.2](https://github.com/0x676e67/wreq/compare/v2.0.1..v2.0.2) - 2025-01-25

### ⛰️  Features

- Add implementations for `IntoCertCompressionAlgorithm` ([#363](https://github.com/0x676e67/wreq/issues/363)) - ([3e09a3f](https://github.com/0x676e67/wreq/commit/3e09a3f5fbea1f0a400ab3eaf9ca9832c4d595a4))
- Expose `ClientMut` as public API ([#362](https://github.com/0x676e67/wreq/issues/362)) - ([455cf51](https://github.com/0x676e67/wreq/commit/455cf51ba37c10a57f00ad6310f87aae8d3f2af3))

### 🚜 Refactor

- Simplify `IntoStreamDependency` implementations using macros ([#364](https://github.com/0x676e67/wreq/issues/364)) - ([9322f05](https://github.com/0x676e67/wreq/commit/9322f0594d0b1cf74bef110bdd113c7267ae1707))

### ⚙️ Miscellaneous Tasks

- Remove unnecessary type conversions - ([9d9bb4f](https://github.com/0x676e67/wreq/commit/9d9bb4fce39f3f6c7b6cbf24e06041a714ec1898))


## [2.0.1](https://github.com/0x676e67/wreq/compare/v2.0.0..v2.0.1) - 2025-01-24

### ⛰️  Features

- Implement `IntoStreamDependency` for tuple and `StreamDependency` ([#359](https://github.com/0x676e67/wreq/issues/359)) - ([d7724f7](https://github.com/0x676e67/wreq/commit/d7724f753e4375a68603ee781be0f010bb329de9))

### 📚 Documentation

- Update performance information - ([2cb8a46](https://github.com/0x676e67/wreq/commit/2cb8a4689422c8cddf51f09620d699f56e9d8111))

### ⚙️ Miscellaneous Tasks

- Update owner ([#358](https://github.com/0x676e67/wreq/issues/358)) - ([4ee1438](https://github.com/0x676e67/wreq/commit/4ee143824e5726a8bfaf1bcec14c2d59802ad71d))


## [2.0.0](https://github.com/0x676e67/wreq/compare/v2.0.0-rc.1..v2.0.0) - 2025-01-23

### 🧪 Testing

- *(badssl)* Update cipher list - ([6b01366](https://github.com/0x676e67/wreq/commit/6b0136632b5241fad5fcb9620c54eac98f237ee9))

### ⚙️ Miscellaneous Tasks

- *(tls)* Load and wrap the certificate into `RootCertStore` ([#356](https://github.com/0x676e67/wreq/issues/356)) - ([adddada](https://github.com/0x676e67/wreq/commit/adddada9037b09ccb38a6eeea67f7adac328a38c))
- *(tls)* Move `tls/ext/cert` to `tls/cert` ([#355](https://github.com/0x676e67/wreq/issues/355)) - ([eae2d93](https://github.com/0x676e67/wreq/commit/eae2d9364063ab5585b34e137eedb90fb5da18dd))
- Move macros to lib mod ([#354](https://github.com/0x676e67/wreq/issues/354)) - ([6209589](https://github.com/0x676e67/wreq/commit/6209589bdd23cf38227745100c43d744f0c030b8))


## [2.0.0-rc.1](https://github.com/0x676e67/wreq/compare/v1.5.0..v2.0.0-rc.1) - 2025-01-22

### ⛰️  Features

- *(mimic)* Added possibility to choose Client and OS to impersonate ([#290](https://github.com/0x676e67/wreq/issues/290)) - ([63cb5c5](https://github.com/0x676e67/wreq/commit/63cb5c53a735f172114afcab6c816762faedd934))
- Rename `RootCertsStore` to `RootCertStore` ([#353](https://github.com/0x676e67/wreq/issues/353)) - ([152142f](https://github.com/0x676e67/wreq/commit/152142f00caf25b6d9c198155f417a84a6eead90))
- `Impersonate`/`ImpersonateOS` impl serde ([#352](https://github.com/0x676e67/wreq/issues/352)) - ([98c61c8](https://github.com/0x676e67/wreq/commit/98c61c885478f1d0d1f81ae1f9cff75bbbe0e95e))
- Add tests for `3DES` and `DH2048` cipher support ([#351](https://github.com/0x676e67/wreq/issues/351)) - ([bd73ddc](https://github.com/0x676e67/wreq/commit/bd73ddcb58bcfb936297cd338c8be589d2ce8c95))
- Remove impersonate from str feature ([#350](https://github.com/0x676e67/wreq/issues/350)) - ([96387ec](https://github.com/0x676e67/wreq/commit/96387ec22c009883f1486e3c09586cbbc7f94477))
- Add `read_timeout` option with override support in Request ([#334](https://github.com/0x676e67/wreq/issues/334)) - ([5d115a5](https://github.com/0x676e67/wreq/commit/5d115a5b5145213d3ec9f8408d88609aa43bf00a))
- Disable boring module exports - ([bb63196](https://github.com/0x676e67/wreq/commit/bb631960f9326a1c60e3300fd7f2425af1faef4b))
- Disable boring module exports ([#319](https://github.com/0x676e67/wreq/issues/319)) - ([7d30324](https://github.com/0x676e67/wreq/commit/7d3032433b561c0452c7b22a6fc5d5ba2ca37e84))
- Remove internal headers cache ([#318](https://github.com/0x676e67/wreq/issues/318)) - ([846ad15](https://github.com/0x676e67/wreq/commit/846ad15348c5a7767a3c3c6d971a0a6e430b24e6))
- Send `json` to avoid repeated query of `CONTENT_TYPE` ([#311](https://github.com/0x676e67/wreq/issues/311)) - ([bd2c519](https://github.com/0x676e67/wreq/commit/bd2c519156c66482ddd34b8aa4bf50fd36d3a213))

### 🐛 Bug Fixes

- *(network)* Fix `NetworkScheme` debug format ([#332](https://github.com/0x676e67/wreq/issues/332)) - ([d0df934](https://github.com/0x676e67/wreq/commit/d0df93457dd100e75ffbf4fb8b61581cd24d79f6))

### 🚜 Refactor

- Refactor client and impersonate configurations ([#321](https://github.com/0x676e67/wreq/issues/321)) - ([513f196](https://github.com/0x676e67/wreq/commit/513f1962503c32cdfeb748780cca26d3965be840))
- Simplify client internal settings ([#320](https://github.com/0x676e67/wreq/issues/320)) - ([b7763cf](https://github.com/0x676e67/wreq/commit/b7763cf75e01b119cf96cd8cc02bb52888295052))

### 📚 Documentation

- *(websocket)* Update docs - ([5028926](https://github.com/0x676e67/wreq/commit/5028926e889c38ac72c36e1c4cad79926efc07cb))
- Update network scheme docs - ([2ae744c](https://github.com/0x676e67/wreq/commit/2ae744cb185c2fbb512b72ac1d607c4be11408b1))
- Update `Client` docs - ([8af9f1a](https://github.com/0x676e67/wreq/commit/8af9f1ad4e07ca62f9ea1bbf2c9e54d82869da0a))

### ⚡ Performance

- Improve network scheme to avoid unnecessary clone ([#333](https://github.com/0x676e67/wreq/issues/333)) - ([a1cb889](https://github.com/0x676e67/wreq/commit/a1cb88944ea6d537349f4d5d3af50f00bb6beaa6))

### 🎨 Styling

- Destructive updates, standard naming style ([#315](https://github.com/0x676e67/wreq/issues/315)) - ([247a26f](https://github.com/0x676e67/wreq/commit/247a26f1b883f4ebe95e4df1815e44472387b317))
- Format code style - ([bd1a837](https://github.com/0x676e67/wreq/commit/bd1a83742e35a88e83c1e7d05f8b74080e67025d))
- Format code style ([#314](https://github.com/0x676e67/wreq/issues/314)) - ([509977f](https://github.com/0x676e67/wreq/commit/509977f22846d8f22ad0b9588dbb1f4272121143))

### ⚙️ Miscellaneous Tasks

- *(http)* Fmt code - ([d66b156](https://github.com/0x676e67/wreq/commit/d66b156a2a21d29c4d4f1c02cd04fa8f44feb72c))
- *(rewin)* Inline hotspot code - ([23cc53b](https://github.com/0x676e67/wreq/commit/23cc53b04f1825d0a729aeedd9dc93bcaebe0561))
- *(rt)* Inline hotspot code - ([8cd9199](https://github.com/0x676e67/wreq/commit/8cd9199ea680c59bcbc4681cec8e8a962b37e37f))
- Optional enable http2 tracing ([#335](https://github.com/0x676e67/wreq/issues/335)) - ([83918e1](https://github.com/0x676e67/wreq/commit/83918e1dcc1922a1989b7a5f0070081b0efe3c49))
- Fmt code - ([2feee9c](https://github.com/0x676e67/wreq/commit/2feee9c1da1004530f563a30bfd6e43eb88bd7c0))
- Simplify dependency version settings - ([f4f1e76](https://github.com/0x676e67/wreq/commit/f4f1e761166887b12cc192a22c29d685eb4046eb))
- Update examples - ([dece4f0](https://github.com/0x676e67/wreq/commit/dece4f093c5842b5387f0ab2da9aa2bff27db699))
- Format code - ([85b6795](https://github.com/0x676e67/wreq/commit/85b67951cee90ad3a98a9fceafd5382728c3a98f))
- Fmt code - ([269d11d](https://github.com/0x676e67/wreq/commit/269d11dfe3356ac97ed73d31f4690417ad3f3a65))

### Deps

- *(boring2)* Pin 4.13.0 version ([#331](https://github.com/0x676e67/wreq/issues/331)) - ([9272524](https://github.com/0x676e67/wreq/commit/9272524fc73e6a32a682e00bec39ff1474ed1703))
- *(hyper2)* Pin 1.5.0 version ([#330](https://github.com/0x676e67/wreq/issues/330)) - ([a638cd3](https://github.com/0x676e67/wreq/commit/a638cd3a2c248f9bb3eb39f5a077da1b2610e7d9))
- *(tower)* Pin version v0.5.2 - ([0973fef](https://github.com/0x676e67/wreq/commit/0973fefe13bd2d8656a0d5ca66bba8f398eed0f9))
- *(tower-layer)* Remove unused deps ([#322](https://github.com/0x676e67/wreq/issues/322)) - ([e446b61](https://github.com/0x676e67/wreq/commit/e446b61015076209c8b882bb01b2d92eda54cc2e))

### Workflows

- *(linux)* Remove unused deps install - ([4fe26e8](https://github.com/0x676e67/wreq/commit/4fe26e8d7fcbf3dcbabae77d51f4ca37be15573e))
- Add `rc` version check - ([708e77b](https://github.com/0x676e67/wreq/commit/708e77b697b546bb59b8b777b51a65dc88c9da24))

## New Contributors ❤️

* @bkn9hs made their first contribution in [#328](https://github.com/0x676e67/wreq/pull/328)
* @UwUDev made their first contribution in [#290](https://github.com/0x676e67/wreq/pull/290)

## [1.5.0](https://github.com/0x676e67/wreq/compare/v1.3.6..v1.5.0) - 2025-01-11

### ⛰️  Features

- *(client)* Add chain settings of client - ([42b08a1](https://github.com/0x676e67/wreq/commit/42b08a15c669573b6e955967e9218b20ee869960))
- *(client)* Optional cross-origin redirect proxy authentication ([#304](https://github.com/0x676e67/wreq/issues/304)) - ([fcdac5d](https://github.com/0x676e67/wreq/commit/fcdac5d643e65e53597a9d7de6a21bffddb6032c))
- *(client)* Expose default headers as public API ([#296](https://github.com/0x676e67/wreq/issues/296)) - ([00e4199](https://github.com/0x676e67/wreq/commit/00e419908cc16376015be20ffc426a57ec327b40))
- *(multipart)* Expose a Form::into_stream() method on async multipart forms ([#303](https://github.com/0x676e67/wreq/issues/303)) - ([f46563f](https://github.com/0x676e67/wreq/commit/f46563f294239bd6924ca4d01ee9c3a07df8a515))
- *(proxy)* Remove system proxy cache ([#309](https://github.com/0x676e67/wreq/issues/309)) - ([7992c93](https://github.com/0x676e67/wreq/commit/7992c9321979d2f61bc96bbb54a84248a1bb566b))
- *(tls)* Optional disable SSL renegotiation ([#306](https://github.com/0x676e67/wreq/issues/306)) - ([c9c0dd3](https://github.com/0x676e67/wreq/commit/c9c0dd301301003e206ff9f3230532b879e2c994))

### 🐛 Bug Fixes

- Fix `Request` `try_clone` missing variables ([#301](https://github.com/0x676e67/wreq/issues/301)) - ([ca1c0fa](https://github.com/0x676e67/wreq/commit/ca1c0fa19c8d15b153e5e021f851e73c1489f23f))

### 🚜 Refactor

- *(websocket)* Change parameters to `Cow` types for improved flexibility ([#298](https://github.com/0x676e67/wreq/issues/298)) - ([aff5af9](https://github.com/0x676e67/wreq/commit/aff5af9a6ab7e64269d7b113fe42b1c40325282f))
- Rename mod `scheme` with `network` - ([dceb375](https://github.com/0x676e67/wreq/commit/dceb37573b65ac172d367b8a5bcd3dd891a34431))

### 📚 Documentation

- *(tls)* Update docs - ([f7b564b](https://github.com/0x676e67/wreq/commit/f7b564b4ed115a67a3db5c260a53f93bf27bcb48))

### ⚡ Performance

- *(pool)* Reduce lock scope to decrease contention ([#308](https://github.com/0x676e67/wreq/issues/308)) - ([6b0c27c](https://github.com/0x676e67/wreq/commit/6b0c27ce0b6d6bb123dde3fc114496b37ad3536f))

### ⚙️ Miscellaneous Tasks

- *(websocket)* Simplify URL scheme matching and error handling logic ([#302](https://github.com/0x676e67/wreq/issues/302)) - ([901b397](https://github.com/0x676e67/wreq/commit/901b397c87dfffaf80e250492d6c3b73022066f4))
- *(websocket)* Remove deprecated function ([#297](https://github.com/0x676e67/wreq/issues/297)) - ([427edf6](https://github.com/0x676e67/wreq/commit/427edf6e5dbaa0969239bf6073d4c5a4d56baf7a))
- Annotating default values ​​improves maintainability - ([a043290](https://github.com/0x676e67/wreq/commit/a043290c1e925a002cbbf4c6d2848a6e3073a909))
- Update websocket bad url handler - ([38eee48](https://github.com/0x676e67/wreq/commit/38eee48b0948c95cd1e3f24eb66284f787545ad0))
- Add `#[inline]` to `cookie_store_mut` - ([6fc11c5](https://github.com/0x676e67/wreq/commit/6fc11c5f4ad81ded8d37cff685e79476b603a888))
- Simplify template macro usage for platform-specific config ([#299](https://github.com/0x676e67/wreq/issues/299)) - ([675f198](https://github.com/0x676e67/wreq/commit/675f1985acf54eb27834393e80e3b0fa2c170aca))

### Build

- *(deps)* Update windows-registry requirement from 0.3.0 to 0.4.0 ([#295](https://github.com/0x676e67/wreq/issues/295)) - ([5a6fab4](https://github.com/0x676e67/wreq/commit/5a6fab4f3a50765afc155f1641cd2558af5c8693))
- *(deps)* Update env_logger requirement from 0.10.0 to 0.11.6 ([#294](https://github.com/0x676e67/wreq/issues/294)) - ([a483462](https://github.com/0x676e67/wreq/commit/a483462cd97e6ebf6a6df932b39c44578b48bfb8))
- Fix conditional compilation ([#307](https://github.com/0x676e67/wreq/issues/307)) - ([358a6ec](https://github.com/0x676e67/wreq/commit/358a6ecec2e59bb91ac962ffe7423041b1cb5ce4))


## [1.3.6](https://github.com/0x676e67/wreq/compare/v1.3.5..v1.3.6) - 2025-01-08

### ⛰️  Features

- *(websocket)* Add `with_builder` method to modify request builder before sending ([#288](https://github.com/0x676e67/wreq/issues/288)) - ([ff9e9f2](https://github.com/0x676e67/wreq/commit/ff9e9f2cb5f1817c6b0187aaa6095a87e386a3d2))
- Support `Apple` devices to bind device interface ([#293](https://github.com/0x676e67/wreq/issues/293)) - ([a71a460](https://github.com/0x676e67/wreq/commit/a71a46065b4f96200decc47891333ce699631b3f))

### 🐛 Bug Fixes

- *(test)* Resolve test failures due to invalid upstream certificate site - ([1897e3a](https://github.com/0x676e67/wreq/commit/1897e3aa51b38f032bf246f57e04df3e3aa5f434))

### ⚡ Performance

- *(pool)* Reduce `Dst` cloning overhead with `Arc` for `PoolKey` ([#289](https://github.com/0x676e67/wreq/issues/289)) - ([1946826](https://github.com/0x676e67/wreq/commit/194682691d448d1196cf37a34b3e89a3a4af76e9))

### 🧪 Testing

- *(connector-layer)* Sync upstream connector layers tests ([#285](https://github.com/0x676e67/wreq/issues/285)) - ([9d772f0](https://github.com/0x676e67/wreq/commit/9d772f03cac1c9679afe134fb8e5926df1db199b))

### ⚙️ Miscellaneous Tasks

- Remove unused crate path prefix - ([d0ca971](https://github.com/0x676e67/wreq/commit/d0ca971ca58b93c3d1a1f90174a7abd633404eda))
- Sync upstream `From<http::Response<T>> for Response` - ([954a807](https://github.com/0x676e67/wreq/commit/954a80789bc4fb69fefaa74a2db19767fe2f5bce))
- Fmt code - ([f3aeb61](https://github.com/0x676e67/wreq/commit/f3aeb61a72943abb33ce33bb1824d46545c3230b))
- Improved type convert ([#284](https://github.com/0x676e67/wreq/issues/284)) - ([7ab1f2f](https://github.com/0x676e67/wreq/commit/7ab1f2f25734b9af78607b66e0406d644c39fb49))

### ◀️ Revert

- Remove `From<http::Response<T>> for Response` ([#282](https://github.com/0x676e67/wreq/issues/282)) - ([1e69245](https://github.com/0x676e67/wreq/commit/1e69245677517daaa8ec10ca64d347457925cb38))

## New Contributors ❤️

* @honeyspoon made their first contribution in [#282](https://github.com/0x676e67/wreq/pull/282)

## [1.3.5](https://github.com/0x676e67/wreq/compare/v1.3.3..v1.3.5) - 2025-01-06

### ⛰️  Features

- *(multipart)* Sync upstream file multipart ([#278](https://github.com/0x676e67/wreq/issues/278)) - ([49a3f06](https://github.com/0x676e67/wreq/commit/49a3f06c40942c8b0a600058e769c21dc9d7200a))
- *(request)* Insert header differentiates between append and overwrite ([#274](https://github.com/0x676e67/wreq/issues/274)) - ([c0026ca](https://github.com/0x676e67/wreq/commit/c0026caaa69ead0d42efba051308c87be21f4ab7))
- *(request)* Add general HTTP authentication method ([#270](https://github.com/0x676e67/wreq/issues/270)) - ([5c3facb](https://github.com/0x676e67/wreq/commit/5c3facb9c575658b2171e154b8386d54921b0af6))

### 🐛 Bug Fixes

- *(redirect)* Fix redirect test - ([9f4bd3f](https://github.com/0x676e67/wreq/commit/9f4bd3fc241aaec158b4cd4e7377fb959459f9c6))
- *(test)* Fix proxy test - ([475752e](https://github.com/0x676e67/wreq/commit/475752e49e438ab3100c9e54082ea9b18bfdb33a))
- *(timeout)* Fix timeout test - ([0bf0422](https://github.com/0x676e67/wreq/commit/0bf0422a6b950e9c72ad642927a1781531f17e03))
- Fix migration hyper1 missing `TokioTimer` ([#275](https://github.com/0x676e67/wreq/issues/275)) - ([a2e8b47](https://github.com/0x676e67/wreq/commit/a2e8b47a80a3272bc621a7d83fd7c8262be6a6d1))

### 📚 Documentation

- Update `http2`/`network` docs ([#273](https://github.com/0x676e67/wreq/issues/273)) - ([5edaa93](https://github.com/0x676e67/wreq/commit/5edaa9311c255ceb1204c7bb6c90d2f716f4628b))

### 🧪 Testing

- *(timeout)* Ignore the test in Tunnel VPN environment ([#279](https://github.com/0x676e67/wreq/issues/279)) - ([156fd1b](https://github.com/0x676e67/wreq/commit/156fd1b6b4f2b8a495dc6b446bd612881bacf3a5))
- Ignore doc test ([#276](https://github.com/0x676e67/wreq/issues/276)) - ([5275c6b](https://github.com/0x676e67/wreq/commit/5275c6b1eee50108061682758d67524c7a40547f))
- Remove unused wasm test - ([25166c9](https://github.com/0x676e67/wreq/commit/25166c977aceb05e752d7b973af6ef3a72cbca4e))

### ⚙️ Miscellaneous Tasks

- *(cookie)* Use `RwLock` types that do not poison themselves ([#268](https://github.com/0x676e67/wreq/issues/268)) - ([dcbd79d](https://github.com/0x676e67/wreq/commit/dcbd79dd324483442ccb715ac277b7ec82be93d3))
- Add all features tests - ([138c43a](https://github.com/0x676e67/wreq/commit/138c43aacb7d753c1ebde15effa6a457a8260dd1))
- Sync upstream tests - ([b782282](https://github.com/0x676e67/wreq/commit/b78228289d86fb93c1e301bf5b367a0f698b15d8))
- Remove unused feature - ([668009d](https://github.com/0x676e67/wreq/commit/668009d641294f8ad227083318447455f3995c00))
- Cargo clippy fix all-features - ([1e45f60](https://github.com/0x676e67/wreq/commit/1e45f60d23d8d03a0567ba2c9bb0b1e414714b4e))
- Remove unused code - ([aa427f5](https://github.com/0x676e67/wreq/commit/aa427f5ecf01762c5cd45ae1690f6654eb20dc46))

### Build

- Fix linux build ([#277](https://github.com/0x676e67/wreq/issues/277)) - ([014e026](https://github.com/0x676e67/wreq/commit/014e02647a4c1f2264f7151576c7350425e59cb7))

### Deps

- Replace `futures_core` with `futures_util` ([#269](https://github.com/0x676e67/wreq/issues/269)) - ([ce9ac8d](https://github.com/0x676e67/wreq/commit/ce9ac8d36ba901b3271ddb879dc34bc65e1dd723))


## [1.3.3](https://github.com/0x676e67/wreq/compare/v1.3.2..v1.3.3) - 2025-01-05

### ⛰️  Features

- *(mimic)* Add Tor browser `Firefox 128` mimic ([#267](https://github.com/0x676e67/wreq/issues/267)) - ([f69f660](https://github.com/0x676e67/wreq/commit/f69f6605de49c13f44006355d31ad9abaac3e060))
- *(mimic)* Optional mimic http2 ([#262](https://github.com/0x676e67/wreq/issues/262)) - ([6e44e17](https://github.com/0x676e67/wreq/commit/6e44e17695f91336a19b69cd0ec12843d9a8ca7a))

### ⚙️ Miscellaneous Tasks

- Simplify http2 configuration - ([34700d1](https://github.com/0x676e67/wreq/commit/34700d1ccae4977f2a0a5b34cd4e9a10b68d6ecc))

### Deps

- *(pool)* Replace `futures_channel::mpsc` with `tokio::sync::mpsc` in Hyper ([#264](https://github.com/0x676e67/wreq/issues/264)) - ([f4895fb](https://github.com/0x676e67/wreq/commit/f4895fb8dbb47d7d10563259a500aae57fcf7bb6))


## [1.3.2](https://github.com/0x676e67/wreq/compare/v1.3.0..v1.3.2) - 2025-01-04

### ⚙️ Miscellaneous Tasks

- Fix typo - ([0a095ce](https://github.com/0x676e67/wreq/commit/0a095cef2ff9443898c11531be32aa18984a10e2))
- Rename and update access scope - ([607da50](https://github.com/0x676e67/wreq/commit/607da5005d9e2020582d961e0f0906b90b658681))


## [1.3.0](https://github.com/0x676e67/wreq/compare/v1.2.6..v1.3.0) - 2025-01-04

### 🚜 Refactor

- *(tls)* Refactor Application-layer protocol settings ([#260](https://github.com/0x676e67/wreq/issues/260)) - ([bc8b824](https://github.com/0x676e67/wreq/commit/bc8b8246779509209077506511ad2e8ccd580ba5))
- Rename `HttpVersionPref` to `AlpnProtos` ([#258](https://github.com/0x676e67/wreq/issues/258)) - ([e99ec7a](https://github.com/0x676e67/wreq/commit/e99ec7a8aaf8047a726293099cedf8919bf622ba))

### 📚 Documentation

- *(tls)* Update docs - ([db3ee6c](https://github.com/0x676e67/wreq/commit/db3ee6c8418afabc05659c76626f775931537369))
- *(tls)* Update docs - ([ad389e5](https://github.com/0x676e67/wreq/commit/ad389e5c92327e41eb4a3aa239c63d17bd51ec9d))
- *(tls)* Update docs ([#261](https://github.com/0x676e67/wreq/issues/261)) - ([309e62f](https://github.com/0x676e67/wreq/commit/309e62f47bdd68b5f89cb41bcfa8629517a00e79))

### ⚙️ Miscellaneous Tasks

- *(mimic)* Always inline settings module - ([630e28f](https://github.com/0x676e67/wreq/commit/630e28f529baa21a2d5bf780be2003c3dfac6618))
- *(tls)* Always inline alps proto len - ([5b33bc5](https://github.com/0x676e67/wreq/commit/5b33bc560cf394ef8022a14acd2602307a7f9535))
- *(tls)* Cleaner bind calls - ([3ddbb64](https://github.com/0x676e67/wreq/commit/3ddbb64d0f2c7492fc1a6a9a8ff81f23f4e152d1))
- *(tls)* Renaming cumbersome API names - ([1021cb1](https://github.com/0x676e67/wreq/commit/1021cb10eb0338685b313cb606a1576153ad07cf))
- Improve verbose certificate configuration ([#256](https://github.com/0x676e67/wreq/issues/256)) - ([67eb333](https://github.com/0x676e67/wreq/commit/67eb333f965724cf1fd40c6314c274aa1ab08c72))


## [1.2.6](https://github.com/0x676e67/wreq/compare/v1.2.5..v1.2.6) - 2025-01-03

### ⚙️ Miscellaneous Tasks

- *(tls/ext)* Clearer naming - ([a0f5e64](https://github.com/0x676e67/wreq/commit/a0f5e643dc55379b193e3d644038c79ef81c7a7b))
- Inline suggestions - ([978198d](https://github.com/0x676e67/wreq/commit/978198d4154c80052f7d889d99fbc6de2435a07b))
- Simplify method signatures - ([9bdc01d](https://github.com/0x676e67/wreq/commit/9bdc01d75cc8d767470cbacb09980792907d86f2))
- Internal request for redundant method boundary ([#253](https://github.com/0x676e67/wreq/issues/253)) - ([a252cd1](https://github.com/0x676e67/wreq/commit/a252cd1784c982b378da0afb32793684558326ac))

### Pref

- Build request failures return errors instead of panic ([#254](https://github.com/0x676e67/wreq/issues/254)) - ([1dbc67c](https://github.com/0x676e67/wreq/commit/1dbc67c1eed981da6c81f02f535df286f43c571a))


## [1.2.5](https://github.com/0x676e67/wreq/compare/v1.2.1..v1.2.5) - 2025-01-02

### ⛰️  Features

- *(client)* Improved set cookie operation ([#252](https://github.com/0x676e67/wreq/issues/252)) - ([e94d742](https://github.com/0x676e67/wreq/commit/e94d74253a3f2b603c82db95343ceca3ec8ff812))
- *(tls)* Expose `CertCompressionAlgorithm` as public API ([#247](https://github.com/0x676e67/wreq/issues/247)) - ([0a6cbc6](https://github.com/0x676e67/wreq/commit/0a6cbc6660d3b3321d3df219bc5d807c2652c553))
- *(tls)* Expose `TlsExtension` as public API ([#246](https://github.com/0x676e67/wreq/issues/246)) - ([98a18b3](https://github.com/0x676e67/wreq/commit/98a18b347568ff20db485e78a577ac812c9be38f))

### 🐛 Bug Fixes

- Align the cfg compilation with the socket2 ([#245](https://github.com/0x676e67/wreq/issues/245)) - ([3122a32](https://github.com/0x676e67/wreq/commit/3122a329f4bfc1acafd8b6b0ad323c6e23db29e5))
- Fix default TLS configuration hostname not set ([#244](https://github.com/0x676e67/wreq/issues/244)) - ([44b8216](https://github.com/0x676e67/wreq/commit/44b8216858fb1386ca1104b4d56234455e934e2d))

### 🚜 Refactor

- Rename verbose identifiers for clarity - ([f1ebb79](https://github.com/0x676e67/wreq/commit/f1ebb7906f3f81e7047ad6bbc1387c12ccfe5ef5))
- Responsibility-based module division - ([c3129ca](https://github.com/0x676e67/wreq/commit/c3129cad6b7405b2c52d4750e337060e4c1175c3))

### 📚 Documentation

- Update docs ([#243](https://github.com/0x676e67/wreq/issues/243)) - ([18d8934](https://github.com/0x676e67/wreq/commit/18d89342d4194ab37f5dfe00a3ba65509bc4ff7a))

### ⚡ Performance

- Improve HTTP request in HTTPS connector ([#242](https://github.com/0x676e67/wreq/issues/242)) - ([2a99fd4](https://github.com/0x676e67/wreq/commit/2a99fd4ed667a77a8f9fba9607372750202a5c70))

### ⚙️ Miscellaneous Tasks

- *(client)* Avoid explicit type declarations - ([44d22ef](https://github.com/0x676e67/wreq/commit/44d22ef2de58cbd92720505c216e7490498be36b))
- *(tls)* Simplify certificate loading configuration ([#249](https://github.com/0x676e67/wreq/issues/249)) - ([87275fc](https://github.com/0x676e67/wreq/commit/87275fc96d0cb6f7dee38f4945377a43d95ba377))
- Add build all features - ([1148155](https://github.com/0x676e67/wreq/commit/114815563c007d56f343d4d55e92005ce487f309))
- Some insignificant update - ([ad20677](https://github.com/0x676e67/wreq/commit/ad20677e88a0d13cec44f5e2690d0e0c9df506fa))
- Rename  to - ([a97be9f](https://github.com/0x676e67/wreq/commit/a97be9fdaaf708adb4fc165c1ec8ba5cb11f4a47))
- Fix closure capture ownership - ([e0c55f0](https://github.com/0x676e67/wreq/commit/e0c55f0bd11a1061dfe9f7f422fada7e87cc08d9))

## New Contributors ❤️

* @sudorf0 made their first contribution

## [1.2.1](https://github.com/0x676e67/wreq/compare/v1.2.0..v1.2.1) - 2024-12-31

### ⚙️ Miscellaneous Tasks

- Using normal array storage - ([3ce9040](https://github.com/0x676e67/wreq/commit/3ce9040e791ab31ea9a8992e9219c771e56863ca))

## New Contributors ❤️

* @coutureone made their first contribution
* @8176917 made their first contribution

## [1.2.0](https://github.com/0x676e67/wreq/compare/v1.1.2..v1.2.0) - 2024-12-31

### ⛰️  Features

- *(client)* Add HTTP2 `Priority` frame configuration ([#238](https://github.com/0x676e67/wreq/issues/238)) - ([8c75d75](https://github.com/0x676e67/wreq/commit/8c75d7507a35e6dd7ad7d045c7e5ae1e772598dd))
- Add `Firefox 117` impersonate ([#239](https://github.com/0x676e67/wreq/issues/239)) - ([cae2f6d](https://github.com/0x676e67/wreq/commit/cae2f6df217780ecaa4fd073ef12af597913e321))


## [1.1.2](https://github.com/0x676e67/wreq/compare/v1.1.1..v1.1.2) - 2024-12-31

### ⛰️  Features

- Add verify hostname configuration ([#237](https://github.com/0x676e67/wreq/issues/237)) - ([3478e11](https://github.com/0x676e67/wreq/commit/3478e1110bc5d4819eec4d66bf2a09369199ca29))

### ⚙️ Miscellaneous Tasks

- Update comment - ([2252652](https://github.com/0x676e67/wreq/commit/22526524f0ccf36763fd2bd90a439c5e95efafd3))


## [1.1.1](https://github.com/0x676e67/wreq/compare/v1.1.0..v1.1.1) - 2024-12-30

### 🐛 Bug Fixes

- *(decoder)* Fix decoding extra empty frame ([#234](https://github.com/0x676e67/wreq/issues/234)) - ([d8118bc](https://github.com/0x676e67/wreq/commit/d8118bc3d141726d2f5e7a8232c8a07f5865efa2))

### ⚡ Performance

- *(tls)* Use `Bytes` to optimize session key storage space ([#231](https://github.com/0x676e67/wreq/issues/231)) - ([1bd9db0](https://github.com/0x676e67/wreq/commit/1bd9db0d8aceb128a899ad5a0c0a651e10632b10))
- Improve unnecessary convert when setting cookies ([#233](https://github.com/0x676e67/wreq/issues/233)) - ([2720bc4](https://github.com/0x676e67/wreq/commit/2720bc4e231530825051faf945f67b4d6fe9bb06))
- `default_headers` will swap default headers ([#232](https://github.com/0x676e67/wreq/issues/232)) - ([3a737f0](https://github.com/0x676e67/wreq/commit/3a737f0eb5cdf40d178c72863a2148a2119b2cca))

### ⚙️ Miscellaneous Tasks

- Remove escape characters - ([0de340c](https://github.com/0x676e67/wreq/commit/0de340cbc495eacb733658e4f249797bda5f32b3))
- Remove unused import - ([ab0ea9c](https://github.com/0x676e67/wreq/commit/ab0ea9cffccaec71080898ed6fd8ad7432ad2dc3))
- Cargo clippy --fix - ([7c5369d](https://github.com/0x676e67/wreq/commit/7c5369dc4ee32cebaf7ecb77f946df541fa2eee9))
- Remove unused code - ([aa9c7d8](https://github.com/0x676e67/wreq/commit/aa9c7d872fff06e5abe3eb5ffbc98c80ca481930))


## [1.1.0](https://github.com/0x676e67/wreq/compare/v1.0.1..v1.1.0) - 2024-12-27

### ⛰️  Features

- *(request)* Insert when `json`/`form` does not have `CONTENT_TYPE` header ([#230](https://github.com/0x676e67/wreq/issues/230)) - ([80c338a](https://github.com/0x676e67/wreq/commit/80c338a835ed9b7015bc63415a44905aa64c61b2))
- Without compression enabled, no compression header is sent ([#229](https://github.com/0x676e67/wreq/issues/229)) - ([79355d7](https://github.com/0x676e67/wreq/commit/79355d752334955eb27994f8e2c2acef9e828d66))

### 🐛 Bug Fixes

- Username in URL plus basic_auth() results in two Authorization headers ([#228](https://github.com/0x676e67/wreq/issues/228)) - ([8398835](https://github.com/0x676e67/wreq/commit/8398835855dfd07fe162a8747b703a82aef4ee84))


## [1.0.1](https://github.com/0x676e67/wreq/compare/v1.0.0..v1.0.1) - 2024-12-27

### ⚙️ Miscellaneous Tasks

- Cargo clippy --fix - ([389e32a](https://github.com/0x676e67/wreq/commit/389e32a05f97f6dcdbecf8235049da5ce8e37914))
- Update alpn protocol order ([#226](https://github.com/0x676e67/wreq/issues/226)) - ([d920df3](https://github.com/0x676e67/wreq/commit/d920df3a9bbf02678664f90fab2b815f49c9c067))


## [1.0.0](https://github.com/0x676e67/wreq/compare/v1.0.0-rc.3..v1.0.0) - 2024-12-25

### ⛰️  Features

- *(client)* Add `no-keepalive` for `Client` ([#221](https://github.com/0x676e67/wreq/issues/221)) - ([20ac5bf](https://github.com/0x676e67/wreq/commit/20ac5bfc17712dc703e479c6e88ac071ae760bdd))
- Request specific `address`/`interface` override ([#223](https://github.com/0x676e67/wreq/issues/223)) - ([7ea06e1](https://github.com/0x676e67/wreq/commit/7ea06e1ac1b0073311596c643f1d92dbafeffa2b))

### ⚙️ Miscellaneous Tasks

- Argo clippy --fix - ([8d766f6](https://github.com/0x676e67/wreq/commit/8d766f6601503d7a2a2ad62e7d416c67ae6d46f8))


## [1.0.0-rc.3](https://github.com/0x676e67/wreq/compare/v1.0.0-rc.2..v1.0.0-rc.3) - 2024-12-25

### ⛰️  Features

- Optional to enable impersonate customization ([#217](https://github.com/0x676e67/wreq/issues/217)) - ([f68de0b](https://github.com/0x676e67/wreq/commit/f68de0b6d5048014b83d887005a5c838f5eb1d31))

### ⚡ Performance

- Avoiding Unnecessary Copies ([#219](https://github.com/0x676e67/wreq/issues/219)) - ([6f6c660](https://github.com/0x676e67/wreq/commit/6f6c6609aaf78d508d5e7184fd92ce99d6d0f70e))

### ⚙️ Miscellaneous Tasks

- *(util/clent)* Remove extra clones - ([72697ca](https://github.com/0x676e67/wreq/commit/72697ca2455487bf856ab256433b3b7779dea433))
- Fix clippy accidentally deleted code ([#220](https://github.com/0x676e67/wreq/issues/220)) - ([200e3f4](https://github.com/0x676e67/wreq/commit/200e3f4e487c8010a37c929c2ceefaf2dc61996d))
- Update macros ([#218](https://github.com/0x676e67/wreq/issues/218)) - ([2f977a1](https://github.com/0x676e67/wreq/commit/2f977a19196a67893b9dd4d74daf6b76632187fe))
- Remove unnecessary `Arc` wrapper from `redirect`/`base_url` ([#216](https://github.com/0x676e67/wreq/issues/216)) - ([3787346](https://github.com/0x676e67/wreq/commit/3787346539188082a8bf58536cf26baae32780e1))


## [1.0.0-rc.2](https://github.com/0x676e67/wreq/compare/v1.0.0-rc.1..v1.0.0-rc.2) - 2024-12-24

### ⛰️  Features

- Allow pluggable tower layers in connector service stack ([#214](https://github.com/0x676e67/wreq/issues/214)) - ([4b07f13](https://github.com/0x676e67/wreq/commit/4b07f139570e3f072b68c654bfd5b29a5ea47341))

### 🐛 Bug Fixes

- Propagate Body::size_hint when wrapping bodies ([#213](https://github.com/0x676e67/wreq/issues/213)) - ([e05a781](https://github.com/0x676e67/wreq/commit/e05a781a7b2be9a39cb6c9a8689c389e9a8f92ec))

### ⚙️ Miscellaneous Tasks

- Remove `clone` from `Dst` - ([9885d91](https://github.com/0x676e67/wreq/commit/9885d91c7cc199b4edfb1296581b27bda368b148))
- Remove `new` method for `InnerRequestBuilder` ([#212](https://github.com/0x676e67/wreq/issues/212)) - ([6b64a60](https://github.com/0x676e67/wreq/commit/6b64a6010c9ae3835427aace4c25ea25eaee4588))
- Cargo clippy --fix - ([908b284](https://github.com/0x676e67/wreq/commit/908b2842c27b3179f8f9509715c8a0ee46f0cb77))


## [1.0.0-rc.1](https://github.com/0x676e67/wreq/compare/v0.33.5..v1.0.0-rc.1) - 2024-12-24

### ⛰️  Features

- *(body)* Improve interop with hyper for `Body` type - ([ef73639](https://github.com/0x676e67/wreq/commit/ef7363920143efec31b5400d0ea408699f1053e7))
- *(client)* Request specific proxy override ([#211](https://github.com/0x676e67/wreq/issues/211)) - ([a547b0e](https://github.com/0x676e67/wreq/commit/a547b0e4c11bdd9ce990af891eaaed9d1c004ab1))
- *(client)* Add impl `Service<http::Request<Body>>` for `Client` ([#202](https://github.com/0x676e67/wreq/issues/202)) - ([88dcf59](https://github.com/0x676e67/wreq/commit/88dcf59056c16d8b6fc6bec3a082d1be1c4e3df7))
- *(client)* Export `http1`/`http2` Builder as public API - ([2ce96f6](https://github.com/0x676e67/wreq/commit/2ce96f6f61daa5a08a055ebfc05d4cf231126323))
- *(client)* Export `http1`/`http2` Builder as public API ([#199](https://github.com/0x676e67/wreq/issues/199)) - ([fb3d72b](https://github.com/0x676e67/wreq/commit/fb3d72b78deca6f51e201ab803a7e3644c9286a7))
- *(client)* Add the maximum safe retry count for HTTP/2 connections ([#196](https://github.com/0x676e67/wreq/issues/196)) - ([2f8ff8c](https://github.com/0x676e67/wreq/commit/2f8ff8ca783f1ef88950f391b29034aa03636cff))
- Support request setting HTTP override ALPN ([#188](https://github.com/0x676e67/wreq/issues/188)) - ([f3af980](https://github.com/0x676e67/wreq/commit/f3af9801761915ac2f031314e9d46ff31538050e))
- Hyper v1 upgrade ([#187](https://github.com/0x676e67/wreq/issues/187)) - ([3441ee7](https://github.com/0x676e67/wreq/commit/3441ee76640b3d9273e7b3617972ef683655cc3a))

### 🐛 Bug Fixes

- *(http2)* Fix http2 header frame initial `stream_id` settings ([#185](https://github.com/0x676e67/wreq/issues/185)) - ([2f773be](https://github.com/0x676e67/wreq/commit/2f773be0da6e963ca823ddbe0e2d9583a8b62aa7))
- Fix http protocol auto-negotiation ([#189](https://github.com/0x676e67/wreq/issues/189)) - ([d144b63](https://github.com/0x676e67/wreq/commit/d144b6356a01b561d50f774243fa3555ab9d7b52))

### ⚙️ Miscellaneous Tasks

- *(pool)* Use `Mutex` types that do not poison themselves ([#192](https://github.com/0x676e67/wreq/issues/192)) - ([dec4d82](https://github.com/0x676e67/wreq/commit/dec4d8265356a065ff8a406344898ebc19895e71))
- *(tls)* Disable custom TLS builder ([#208](https://github.com/0x676e67/wreq/issues/208)) - ([bb12473](https://github.com/0x676e67/wreq/commit/bb12473723a73139226c6b4845acc85815b543c7))
- *(tls)* Compile-time calculation of extended permutation ([#207](https://github.com/0x676e67/wreq/issues/207)) - ([871ab3b](https://github.com/0x676e67/wreq/commit/871ab3bc4838842d60c300291e1c6c4f83d1b58c))
- Refactor connect network request extension ([#210](https://github.com/0x676e67/wreq/issues/210)) - ([f4e67ef](https://github.com/0x676e67/wreq/commit/f4e67ef76340c6b5d21944385339b723829c697a))
- By default, impersonate from a string is disabled ([#206](https://github.com/0x676e67/wreq/issues/206)) - ([35f7f11](https://github.com/0x676e67/wreq/commit/35f7f11c67638af54e79565d679d55068f162f7a))
- Removed TLS config examples to prevent misconfigurations by inexperienced users ([#205](https://github.com/0x676e67/wreq/issues/205)) - ([48d1f5b](https://github.com/0x676e67/wreq/commit/48d1f5b86a885a86a3be2af1694d6328b360f1f9))
- Disable the exposure of internal connect dst API ([#203](https://github.com/0x676e67/wreq/issues/203)) - ([35994c2](https://github.com/0x676e67/wreq/commit/35994c25ded24cfcb57877cf4e1b859e39b989f7))
- Remove unused code - ([663e346](https://github.com/0x676e67/wreq/commit/663e346bce7bfd0090374f99df1b6152ca7eb644))
- Remove unused code - ([0d4f06f](https://github.com/0x676e67/wreq/commit/0d4f06f7ab5769aa80828004f7da74df6a63afe9))
- Deleted permutation storage - ([39e1ef6](https://github.com/0x676e67/wreq/commit/39e1ef6ccd2382c8b9a00873341092df4876df7f))
- Use shorter feature name - ([4246a0f](https://github.com/0x676e67/wreq/commit/4246a0fd6d72ee68d0441de57b3c84f2e9c5b879))
- Remove dead code - ([f516b0a](https://github.com/0x676e67/wreq/commit/f516b0a85e48edfd08848fa1be3af7451fd2a7fd))
- Refactor connect layer detail handle ([#198](https://github.com/0x676e67/wreq/issues/198)) - ([eff1fee](https://github.com/0x676e67/wreq/commit/eff1fee3489f01d47bd406f8632a303863dc1522))
- Refactor connect mod - ([7ecbd25](https://github.com/0x676e67/wreq/commit/7ecbd25f2611161a539bd57e8d6b4945f6ab433a))
- Remove unused code - ([4ef7db6](https://github.com/0x676e67/wreq/commit/4ef7db685884d91aad7221753a9280f6fd1e5891))
- Cleaned up some unnecessary code ([#194](https://github.com/0x676e67/wreq/issues/194)) - ([1304ec1](https://github.com/0x676e67/wreq/commit/1304ec14e003c96a3d9815a43502d0d886e0ca61))
- Simplified TLS TCP stream abstraction ([#193](https://github.com/0x676e67/wreq/issues/193)) - ([273ca6c](https://github.com/0x676e67/wreq/commit/273ca6cdc732419703162a178526fa899db9087c))
- Remove unused code ([#191](https://github.com/0x676e67/wreq/issues/191)) - ([d586d56](https://github.com/0x676e67/wreq/commit/d586d563add0343cd4172974afc035b563c1897a))
- Cargo fmt --all - ([6a114f9](https://github.com/0x676e67/wreq/commit/6a114f974593e95cb21b917f54716b779a4a41d3))
- Static calc extension permutation ([#184](https://github.com/0x676e67/wreq/issues/184)) - ([1da5d42](https://github.com/0x676e67/wreq/commit/1da5d42ebbcff2eaf304dacd58e90f9b6412023f))
- Macros simplify some debug implement ([#183](https://github.com/0x676e67/wreq/issues/183)) - ([5a92fa5](https://github.com/0x676e67/wreq/commit/5a92fa58714b635c4cbc53299b8b49b9b9d11155))
- Remove dead code ([#182](https://github.com/0x676e67/wreq/issues/182)) - ([65391fb](https://github.com/0x676e67/wreq/commit/65391fb83729bcfd39ef548ebd9d24218c86c4f3))

### Deps

- *(tokio-util)* V0.7.0 ([#190](https://github.com/0x676e67/wreq/issues/190)) - ([303abf6](https://github.com/0x676e67/wreq/commit/303abf64952d97aabd21243b9824c9d345c25343))

## New Contributors ❤️

* @invalid-email-address made their first contribution

## [0.33.5](https://github.com/0x676e67/wreq/compare/v0.33.3..v0.33.5) - 2024-12-19

### ⛰️  Features

- *(client)* Http1 sends lowercase request headers by default to improve performance ([#179](https://github.com/0x676e67/wreq/issues/179)) - ([b296e0e](https://github.com/0x676e67/wreq/commit/b296e0eab4b4213516830471cf1b42de2481049f))
- Add `firefox 133` impersonate ([#181](https://github.com/0x676e67/wreq/issues/181)) - ([6710421](https://github.com/0x676e67/wreq/commit/6710421bc53916f6762053e27f1103e7f54cdd06))


## [0.33.3](https://github.com/0x676e67/wreq/compare/v0.33.1..v0.33.3) - 2024-12-16

### 🐛 Bug Fixes

- *(proxy)* Fix `ws`/`wss` upgrade support for `http`/`https` proxy ([#176](https://github.com/0x676e67/wreq/issues/176)) - ([8c3881c](https://github.com/0x676e67/wreq/commit/8c3881c87a7cbfb91701f37eb697c04b2863649d))


## [0.33.1](https://github.com/0x676e67/wreq/compare/v0.33.0..v0.33.1) - 2024-12-16

### ⚙️ Miscellaneous Tasks

- Avoiding setup bloat when customizing your DNS resolver ([#174](https://github.com/0x676e67/wreq/issues/174)) - ([bc870c5](https://github.com/0x676e67/wreq/commit/bc870c542710ec548c2292ba3440490357b76e33))
- Show clear errors when TLS connector build fails ([#173](https://github.com/0x676e67/wreq/issues/173)) - ([f722ce6](https://github.com/0x676e67/wreq/commit/f722ce6578d872008a4a7c64fbbba8ddddb14db4))


## [0.33.0] - 2024-12-15

### ⛰️  Features

- *(async/client)* Add try get user agent - ([c72eed6](https://github.com/0x676e67/wreq/commit/c72eed679d380693e39155d63b63284f51bccc7a))
- *(client)* Request specific cookie store override ([#171](https://github.com/0x676e67/wreq/issues/171)) - ([1357a3c](https://github.com/0x676e67/wreq/commit/1357a3ccfd09b874c2937dde5c0988281a3747c9))
- *(client)* Add support for base URL parameter - ([6101905](https://github.com/0x676e67/wreq/commit/610190586a67b54ea5feb88d2cdbbc215bc8b9fa))
- *(client)* Add support for base URL parameter ([#159](https://github.com/0x676e67/wreq/issues/159)) - ([30530ce](https://github.com/0x676e67/wreq/commit/30530ce80149abb2da1c00d6ef8f752aea963d06))
- *(client)* Request specific redirect policy override ([#147](https://github.com/0x676e67/wreq/issues/147)) - ([cfedb58](https://github.com/0x676e67/wreq/commit/cfedb583f0df0f28c12799b2cc0e93ab2d86b10c))
- *(client)* Set `content-length` in advance for header sorting ([#144](https://github.com/0x676e67/wreq/issues/144)) - ([755cabd](https://github.com/0x676e67/wreq/commit/755cabde8c4edf91c7822ef4c08e7ce95bc2f3fe))
- *(client)* Add proxy management APIs: set, append, and clear proxies ([#132](https://github.com/0x676e67/wreq/issues/132)) - ([966fb0f](https://github.com/0x676e67/wreq/commit/966fb0f05c514b5c11c8ad18b158444a5b882f2e))
- *(client)* Add address/interface level connection pool ([#123](https://github.com/0x676e67/wreq/issues/123)) - ([877c30f](https://github.com/0x676e67/wreq/commit/877c30fc6c308fc116062622ea48f5e2568d9c19))
- *(client)* Support proxy-level connection pool ([#122](https://github.com/0x676e67/wreq/issues/122)) - ([6e4aff1](https://github.com/0x676e67/wreq/commit/6e4aff11a5268d9c39f91bd42585b610fe3f51db))
- *(client)* Limit number of connections in pool ([#118](https://github.com/0x676e67/wreq/issues/118)) - ([326d415](https://github.com/0x676e67/wreq/commit/326d41536b07592b2ba0b591b57aa7cd77e5108f))
- *(client)* Greatly improve the speed of creating clients ([#108](https://github.com/0x676e67/wreq/issues/108)) - ([27e8a55](https://github.com/0x676e67/wreq/commit/27e8a55f698fda9d0e4c42964f1bc5d580bd539b))
- *(client)* Added async client creation to reduce blocking of async runtime ([#105](https://github.com/0x676e67/wreq/issues/105)) - ([b7f36dd](https://github.com/0x676e67/wreq/commit/b7f36dd1961304bf332780b4ec04330cb9fcb975))
- *(client)* Optional configuration of Client TLS extension ([#78](https://github.com/0x676e67/wreq/issues/78)) - ([bab6cb6](https://github.com/0x676e67/wreq/commit/bab6cb6b766806096e083832c837f1353a22b99b))
- *(client)* Default send header names as title case (only http1) ([#61](https://github.com/0x676e67/wreq/issues/61)) - ([bf91fff](https://github.com/0x676e67/wreq/commit/bf91fffcbd91f4d92a53c5ad5bb1c5acf48606ee))
- *(client)* Adaptively select and upgrade the websocket connector ([#48](https://github.com/0x676e67/wreq/issues/48)) - ([b76070c](https://github.com/0x676e67/wreq/commit/b76070c4c3d0f48909a0be8e686ef7bd95093341))
- *(client)* Add `impersonate_with_headers` allows optionally setting request headers ([#128](https://github.com/0x676e67/wreq/issues/128)) - ([eca7cd4](https://github.com/0x676e67/wreq/commit/eca7cd4abbf030da57b92e5eb2dfa0b35ad153ee))
- *(client)* Suggest `inline` to the compiler ([#122](https://github.com/0x676e67/wreq/issues/122)) - ([532ca84](https://github.com/0x676e67/wreq/commit/532ca84a96f085ad04fc7706c310198317ad5ed0))
- *(client)* Simplify client configuration ([#110](https://github.com/0x676e67/wreq/issues/110)) - ([c12dce6](https://github.com/0x676e67/wreq/commit/c12dce66658ba610d670090744d0397ff0068c07))
- *(client)* Simplify the header configuration process - ([4a3f544](https://github.com/0x676e67/wreq/commit/4a3f54414892313eeabc5f3e602e844d1978c8aa))
- *(client)* Allow binding interface ([#92](https://github.com/0x676e67/wreq/issues/92)) - ([3156086](https://github.com/0x676e67/wreq/commit/31560869cc1d02323bc8c330b3415fe3f02ad389))
- *(client)* Add custom header order support ([#83](https://github.com/0x676e67/wreq/issues/83)) - ([4680b8a](https://github.com/0x676e67/wreq/commit/4680b8a69c7d9a33d07b13d44ddfa92a2df28c2a))
- *(client)* Add ability to set proxies/address after client has been initialised ([#34](https://github.com/0x676e67/wreq/issues/34)) - ([837266d](https://github.com/0x676e67/wreq/commit/837266dcb80a0b8b5670675b851b580206ae78a1))
- *(client)* Support client proxy settings ([#32](https://github.com/0x676e67/wreq/issues/32)) - ([30c0e2a](https://github.com/0x676e67/wreq/commit/30c0e2a6e4bfd1327b0ac1ad6f9e9c35e69dc632))
- *(client)* Support impersonate webSocket - ([d3c6dbf](https://github.com/0x676e67/wreq/commit/d3c6dbf272e7b6778b37b10f13cd71df67c1e791))
- *(client)* Optional enable permute_extensions - ([1aa849f](https://github.com/0x676e67/wreq/commit/1aa849fd4ad77c30815a9a9cd71838a0274f628f))
- *(client)* Optional enable_ech_grease, only effective for Chrome - ([335e038](https://github.com/0x676e67/wreq/commit/335e03848228292cfc74d3dc90695bc68db8a7d4))
- *(client)* Support configured IPv4 or IPv6 address (depending on host's preferences) before connection - ([b1f6203](https://github.com/0x676e67/wreq/commit/b1f620332640b57cc71a5cfbe718b1e81f93a1e5))
- *(connect)* Reduce unnecessary connection overhead ([#62](https://github.com/0x676e67/wreq/issues/62)) - ([225ffb9](https://github.com/0x676e67/wreq/commit/225ffb9ef3834e78570f53b62e62e9c6df451d34))
- *(connect)* Add PSK extension ([#52](https://github.com/0x676e67/wreq/issues/52)) - ([04a95ab](https://github.com/0x676e67/wreq/commit/04a95ab8d3f2feac429df28cb2ad258edd8ad45e))
- *(connector)* Using session cache to delay initialization of connector ([#78](https://github.com/0x676e67/wreq/issues/78)) - ([8bdb826](https://github.com/0x676e67/wreq/commit/8bdb8264d1fe039d3366e78880005470c3fb98fb))
- *(connector)* Enable encrypted client hello - ([4a577a1](https://github.com/0x676e67/wreq/commit/4a577a18a06b2fb930e1c2b13cd92ec0c6b05e24))
- *(dns)* Export dns resolver `HickoryDnsResolver` ([#55](https://github.com/0x676e67/wreq/issues/55)) - ([6907f48](https://github.com/0x676e67/wreq/commit/6907f48ae16f538164c3550802a9a269eeeca2d1))
- *(dns)* Optional `LookupIpStrategy` for `hickory_dns` ([#33](https://github.com/0x676e67/wreq/issues/33)) - ([7e6847a](https://github.com/0x676e67/wreq/commit/7e6847af02f8c8fb38ac0b38e80ca233b9b0d243))
- *(dns)* Enable happy eyeballs when using hickory-dns ([#115](https://github.com/0x676e67/wreq/issues/115)) - ([e300a2d](https://github.com/0x676e67/wreq/commit/e300a2d314364a8cf4a269891c065f01a9f2b99b))
- *(extension)* Set application protocol (ALPN) for http1 ([#104](https://github.com/0x676e67/wreq/issues/104)) - ([9ba260f](https://github.com/0x676e67/wreq/commit/9ba260f5dd0e818f9ec1acc176606ff4bd527d10))
- *(feature)* Optional enable websocket - ([28270bf](https://github.com/0x676e67/wreq/commit/28270bf02cb26513c36f927497ff5ef898d373a9))
- *(http2)* Exposing Http2Settings fields ([#75](https://github.com/0x676e67/wreq/issues/75)) - ([15ead8e](https://github.com/0x676e67/wreq/commit/15ead8ec5bd32e1bf47844bd6c87c463ace103db))
- *(http2)* Add `http2_max_frame_size` settings ([#73](https://github.com/0x676e67/wreq/issues/73)) - ([9a69087](https://github.com/0x676e67/wreq/commit/9a6908756613fdd00b65895958998bbb1e73e493))
- *(http2)* Add headers frame default priority ([#106](https://github.com/0x676e67/wreq/issues/106)) - ([e1927dc](https://github.com/0x676e67/wreq/commit/e1927dcb05af5db69221cf60b6f6156c25e5e97d))
- *(http2)* Optimize http2 frame order settings ([#80](https://github.com/0x676e67/wreq/issues/80)) - ([e381f66](https://github.com/0x676e67/wreq/commit/e381f66b4e4289a867d1dd9ce1b7981b32a07f21))
- *(impersonate)* Add Chrome 130 impersonate ([#65](https://github.com/0x676e67/wreq/issues/65)) - ([ebeba7d](https://github.com/0x676e67/wreq/commit/ebeba7de534dc1da6c772bafca3af0f208fc9c42))
- *(impersonate)* Add `Safari iPad 18` impersonate ([#10](https://github.com/0x676e67/wreq/issues/10)) - ([304b1bd](https://github.com/0x676e67/wreq/commit/304b1bd5f1d9561b190f283be89a7f15ef587f53))
- *(impersonate)* Add Safari 18 impersonate - ([acbcbf8](https://github.com/0x676e67/wreq/commit/acbcbf8c578fdb8aff077036ade0b12f403df2df))
- *(impersonate)* Add Chrome 128 impersonate ([#130](https://github.com/0x676e67/wreq/issues/130)) - ([c787890](https://github.com/0x676e67/wreq/commit/c78789056b64e7f383f3a73b6913398b3d9857c4))
- *(impersonate)* Add `Safari17_0` impersonate ([#71](https://github.com/0x676e67/wreq/issues/71)) - ([62f998e](https://github.com/0x676e67/wreq/commit/62f998e89766714def861e732308096dba8da1a4))
- *(impersonate)* Reuse Safari cipher list in groups ([#65](https://github.com/0x676e67/wreq/issues/65)) - ([06efa36](https://github.com/0x676e67/wreq/commit/06efa366832a579bc389378d5af955ab0f226eed))
- *(impersonate)* Export the Impersonate custom extension configuration ([#64](https://github.com/0x676e67/wreq/issues/64)) - ([9233546](https://github.com/0x676e67/wreq/commit/9233546c429ffa590e7e6143e07c7769cef45ef3))
- *(impersonate)* Optimize reuse of impersonate configuration ([#61](https://github.com/0x676e67/wreq/issues/61)) - ([f369748](https://github.com/0x676e67/wreq/commit/f3697488aa0896bb68a8da496dc52242f9a98aa5))
- *(impersonate)* Add Edge_127 impersonate ([#59](https://github.com/0x676e67/wreq/issues/59)) - ([c9f8861](https://github.com/0x676e67/wreq/commit/c9f8861d1e46e7526c6d8fac22126e74ed5987f0))
- *(impersonate)* Optimize TLS connector context handle ([#37](https://github.com/0x676e67/wreq/issues/37)) - ([dc3aadc](https://github.com/0x676e67/wreq/commit/dc3aadc2b897404569f2d2b3c34312788834acb2))
- *(impersonate)* Add Safari_17_5 impersonate - ([bb44019](https://github.com/0x676e67/wreq/commit/bb44019174143d9277c1743668f1a194d32e022e))
- *(impersonate)* Add Safari_17_5 impersonate ([#28](https://github.com/0x676e67/wreq/issues/28)) - ([aa975df](https://github.com/0x676e67/wreq/commit/aa975df80a7515d629471dea3da9c1b50bfe9448))
- *(impersonate)* Add Safari_IOS_17_4_1 impersonate - ([8be0f37](https://github.com/0x676e67/wreq/commit/8be0f37945360ef0e835afb351502a3385e03d39))
- *(impersonate)* Add Safari_IOS_16_5 impersonate - ([ebfb961](https://github.com/0x676e67/wreq/commit/ebfb9616b7b3f0e9d89b5e320f6997414853f383))
- *(impersonate)* Specification version number match - ([0c23082](https://github.com/0x676e67/wreq/commit/0c23082929fadf77dcc0dab6b668a541655c4994))
- *(impersonate)* Add Chrome124 impersonate - ([f63d081](https://github.com/0x676e67/wreq/commit/f63d081b24b6820e13e63b867f3306387780e181))
- *(impersonate)* Add Safari_17_4_1 impersonate - ([bd9f4c1](https://github.com/0x676e67/wreq/commit/bd9f4c129c24088261aff358943f74db1c27067a))
- *(impersonate)* Add Safari_IOS_17_2 impersonate - ([e84fb19](https://github.com/0x676e67/wreq/commit/e84fb1970565701d6b838c3e80b0e9288a98122c))
- *(impersonate)* Add Chrome123 impersonate - ([eb6744b](https://github.com/0x676e67/wreq/commit/eb6744b785424609cd1079d06164badf583199c8))
- *(impersonate)* Improve fingerprint OkHttp fingerprint UserAgent - ([4ce6850](https://github.com/0x676e67/wreq/commit/4ce68504b73b3c57388e2e818cc81fcd3525c06a))
- *(impersonate)* Optimize the overhead of parsing request headers at runtime - ([b0af7fa](https://github.com/0x676e67/wreq/commit/b0af7fa875310144a783298e39ad6c08a844efd2))
- *(impersonate)* Add Edge122 impersonate - ([2e73827](https://github.com/0x676e67/wreq/commit/2e73827ac1c935e423741f620874f1c997c2cf97))
- *(impersonate)* Optimize the overhead of parsing request headers at runtime - ([63b4dbf](https://github.com/0x676e67/wreq/commit/63b4dbf1b2db96476ab003077572c75321f01a40))
- *(impersonate)* Add Safari17_2_1 impersonate - ([44f5933](https://github.com/0x676e67/wreq/commit/44f593391b3097e07ef8c64382f33451a07e201d))
- *(impersonate)* Add Edge101 impersonate - ([5e66c0d](https://github.com/0x676e67/wreq/commit/5e66c0da426f21f73d42e2fbf79113bdbc039a8f))
- *(impersonate)* Add Edge99 impersonate - ([ea51acf](https://github.com/0x676e67/wreq/commit/ea51acf5cee796f50fce1c39f9d0b3d52fc197c5))
- *(impersonate)* Add Safari16_5 impersonate - ([9a919ff](https://github.com/0x676e67/wreq/commit/9a919ff72b6baf750949a35cf10e0eab961dee6b))
- *(impersonate)* Add Chrome117 impersonate - ([0d0ee83](https://github.com/0x676e67/wreq/commit/0d0ee83421269bb8d5948984e9a02cc9d5f7cb44))
- *(impersonate)* Improve safari fingerprint impersonate - ([0b62959](https://github.com/0x676e67/wreq/commit/0b62959fbf6ffd35d91d710e6ce8f3846bc6026d))
- *(impersonate)* Add Chrome101 impersonate - ([02a0a17](https://github.com/0x676e67/wreq/commit/02a0a1704e3e015c8884d70b8c0404c19858c42f))
- *(impersonate)* Add Chrome100 impersonate - ([2c1549b](https://github.com/0x676e67/wreq/commit/2c1549b1a5e6647fd9732c01ff4325616a6be941))
- *(impersonate)* Add Chrome120 impersonate - ([fe63a86](https://github.com/0x676e67/wreq/commit/fe63a86290e0d7b397e1789de805eb89dc91e2d0))
- *(impersonate)* Add Safari16 impersonate - ([4e4701f](https://github.com/0x676e67/wreq/commit/4e4701f3309fc34da40b1fbd65e9b4f944ee2a9f))
- *(impersonate)* Add Safari15_6_1 impersonate - ([86e17a0](https://github.com/0x676e67/wreq/commit/86e17a05097cdd82dbaa90c1c53d7c82a7042a5a))
- *(impersonate)* Add Safari 15_3/15_5 Impersonate - ([0af1670](https://github.com/0x676e67/wreq/commit/0af1670952a94b7fbd63222b89656e8ec1889e97))
- *(impersonate)* Add Chrome v116 Impersonate - ([13971bd](https://github.com/0x676e67/wreq/commit/13971bdaf3d9c0c5c6c6e7455c0bd51a82cbcffd))
- *(impersonate)* Add Chrome v119 Impersonate - ([1ce01d7](https://github.com/0x676e67/wreq/commit/1ce01d77263b478992a67aeb05245949386029fd))
- *(impersonate)* Use the default locations of trusted certificates for verification. - ([6b20712](https://github.com/0x676e67/wreq/commit/6b207127ead62ab81aba9984e9e62e8042504233))
- *(impersonate)* Remove max_concurrent_streams for v118 - ([fbcf65f](https://github.com/0x676e67/wreq/commit/fbcf65faa6277e6f9946f65145ce2c29581e3220))
- *(impersonate)* Add Chrome v118 Impersonate - ([f9a097d](https://github.com/0x676e67/wreq/commit/f9a097dd5d5c8a9b070fa6e2d7629a40d1dd791b))
- *(impersonate)* Add Safari 12 Impersonate - ([b5454f7](https://github.com/0x676e67/wreq/commit/b5454f7263849309544698eceefb2833419f669e))
- *(impersonate)* Support more OkHttp fingerprints - ([43e00ed](https://github.com/0x676e67/wreq/commit/43e00ed237c4aafb9a6abfe3f22d74c000343647))
- *(impersonate)* Add OkHttp5-alpha Impersonate - ([a172d90](https://github.com/0x676e67/wreq/commit/a172d90a1ac6952314403441b9d20f0e2eae748a))
- *(impersonate)* Add OkHttp3 Impersonate - ([754f58d](https://github.com/0x676e67/wreq/commit/754f58dedaf67502b7b0364b8554ab629b8e0c09))
- *(impersonate)* Support disable certs verification - ([cffe303](https://github.com/0x676e67/wreq/commit/cffe303cd1acfc99eab0ca43752c3c343d37a540))
- *(multipart)* Adds support for manually setting size - ([2ca0e26](https://github.com/0x676e67/wreq/commit/2ca0e26cfa0f7ffd6061a453fe71b06d490c3ea9))
- *(proxy)* Optional disable internal proxy cache ([#92](https://github.com/0x676e67/wreq/issues/92)) - ([45da58f](https://github.com/0x676e67/wreq/commit/45da58fcb047efebe583d736c8d5fed18742ec0f))
- *(proxy)* Add support for SOCKS4 ([#27](https://github.com/0x676e67/wreq/issues/27)) - ([533059a](https://github.com/0x676e67/wreq/commit/533059a2023fef19bb7276bcc6bf58323353b09d))
- *(proxy)* Use  instead of  for reading proxy settings on Windows ([#116](https://github.com/0x676e67/wreq/issues/116)) - ([4918e4d](https://github.com/0x676e67/wreq/commit/4918e4d6b813e4f9a7f2b9188a9a28d9a458e1f0))
- *(proxy)* Adds NO_PROXY environment variable support ([#877](https://github.com/0x676e67/wreq/issues/877)) - ([6914091](https://github.com/0x676e67/wreq/commit/691409158273505eb43353c3936759df0ddd7b28))
- *(redirect)* Expose method for accessing the previous and next request ([#148](https://github.com/0x676e67/wreq/issues/148)) - ([bdbc7f1](https://github.com/0x676e67/wreq/commit/bdbc7f1c40d0e3c64b946a3137f5e91530c2acf1))
- *(request)* Add `with_host_header` method for populating Host header ([#142](https://github.com/0x676e67/wreq/issues/142)) - ([33b7e21](https://github.com/0x676e67/wreq/commit/33b7e21e7f2683a6a65e3d92321e07516b52e5af))
- *(tls)* Dynamically configure WebSocket TLS connection alpn protos ([#104](https://github.com/0x676e67/wreq/issues/104)) - ([1918892](https://github.com/0x676e67/wreq/commit/1918892a1f9956274983a023c1572a80f1b514e6))
- *(tls)* No additional WebSocket connector is needed for HTTP/1 client ([#81](https://github.com/0x676e67/wreq/issues/81)) - ([a4ffa85](https://github.com/0x676e67/wreq/commit/a4ffa85e1f350126c7b5a7f8b954588e9c6b6f63))
- *(tls)* Update session ticket setting - ([0942894](https://github.com/0x676e67/wreq/commit/0942894ac9a9507d76150ec7c4a9800f2981be65))
- *(tls)* Implement Debug for TlsSettings ([#80](https://github.com/0x676e67/wreq/issues/80)) - ([a88712a](https://github.com/0x676e67/wreq/commit/a88712a4448d8dd72d5f678cce731b7b4d3dc67c))
- *(tls)* Add option `session_ticket` extension ([#79](https://github.com/0x676e67/wreq/issues/79)) - ([ea5c8f1](https://github.com/0x676e67/wreq/commit/ea5c8f1273abf6ff93f1aa5e3dc7869de29378b0))
- *(tls)* Expose more custom TL settings ([#76](https://github.com/0x676e67/wreq/issues/76)) - ([ef880a7](https://github.com/0x676e67/wreq/commit/ef880a7feb30c124ee5833b22ae2ee0e6cd4503a))
- *(tls)* Simplify TLS version settings ([#66](https://github.com/0x676e67/wreq/issues/66)) - ([c584368](https://github.com/0x676e67/wreq/commit/c58436853b2aeea690404ff95c389f7f37f8fc24))
- *(tls)* Optional webpki root certificates feature ([#40](https://github.com/0x676e67/wreq/issues/40)) - ([d0de915](https://github.com/0x676e67/wreq/commit/d0de91513332e7ff64c4ef4347d701ee5bda0576))
- *(tls)* Avoid repeated loading of native root CA ([#37](https://github.com/0x676e67/wreq/issues/37)) - ([2ad61c7](https://github.com/0x676e67/wreq/commit/2ad61c7619064b863e184f3bf18eb207ade1c1e7))
- *(tls)* Optional built-in root certificates feature ([#36](https://github.com/0x676e67/wreq/issues/36)) - ([016bb5d](https://github.com/0x676e67/wreq/commit/016bb5d20e95d27e25022cfc5396ebf4484f0d2f))
- *(tls)* Some `Chrome`/`Edge` versions have `ECH` enabled by default ([#9](https://github.com/0x676e67/wreq/issues/9)) - ([fecd878](https://github.com/0x676e67/wreq/commit/fecd87820d8014af9abad29befcb405a3ac8593f))
- *(tls)* Some `Chrome`/`Edge` versions have `ECH` enabled by default ([#8](https://github.com/0x676e67/wreq/issues/8)) - ([a68fa56](https://github.com/0x676e67/wreq/commit/a68fa56c75a2c28efcfca324488c1340889b6674))
- *(tls)* Enable permute extensions for `Chrome`/`Edge` 106 and above ([#6](https://github.com/0x676e67/wreq/issues/6)) - ([20e61f0](https://github.com/0x676e67/wreq/commit/20e61f081bbd8b6da9113714c7cec8aaf11aec22))
- *(tls)* Add preconfigured TLS settings ([#118](https://github.com/0x676e67/wreq/issues/118)) - ([440bbdf](https://github.com/0x676e67/wreq/commit/440bbdf2eed0f47ad781715d4c41d11c8d782e6d))
- *(tls)* Add option to configure TLS server name indication (SNI) ([#117](https://github.com/0x676e67/wreq/issues/117)) - ([9847c41](https://github.com/0x676e67/wreq/commit/9847c41e91a4d8cc229eba65df9fe83d98800d94))
- *(tls)* Optimize tls configuration process ([#113](https://github.com/0x676e67/wreq/issues/113)) - ([87219ca](https://github.com/0x676e67/wreq/commit/87219ca951cb620e10cf1a61bdb41d573dd3b285))
- *(tls)* Add `CA Certificate` settings ([#112](https://github.com/0x676e67/wreq/issues/112)) - ([0b39bb0](https://github.com/0x676e67/wreq/commit/0b39bb0c91ab403ab60ee32bd47c8b263c00cd17))
- *(tls)* Reuse https connector layer ([#107](https://github.com/0x676e67/wreq/issues/107)) - ([5c32b6d](https://github.com/0x676e67/wreq/commit/5c32b6d24bdecace26e07e1e6e45ed17ea3dcd1b))
- *(tls)* Add zstd support for chrome models and derivatives ([#93](https://github.com/0x676e67/wreq/issues/93)) - ([0204bb4](https://github.com/0x676e67/wreq/commit/0204bb4a25b3b56b6ef4f4b56a06e837873b4339))
- *(websocket)* Add websocket handshake with a specified websocket key ([#50](https://github.com/0x676e67/wreq/issues/50)) - ([cf46944](https://github.com/0x676e67/wreq/commit/cf469447eebab3ab112c965f722e9b20314b8d0e))
- *(websocket)* Improve websocket API usage ([#49](https://github.com/0x676e67/wreq/issues/49)) - ([72070aa](https://github.com/0x676e67/wreq/commit/72070aa29529d718ea19625fc8e43909dee1c5b7))
- *(websocket)* Improve websocket upgrade ([#73](https://github.com/0x676e67/wreq/issues/73)) - ([348f04c](https://github.com/0x676e67/wreq/commit/348f04cd634b1b17267c2f0ff75851768590b6a4))
- *(websocket)* Add upgrade with custom handshake key - ([b02396b](https://github.com/0x676e67/wreq/commit/b02396b64187cd770166c68a7556e56a2513ba06))
- *(websocket)* Export header method - ([4ab0b0a](https://github.com/0x676e67/wreq/commit/4ab0b0a1664fb7969e9089a7f658ef36b01cad0c))
- *(websocket)* Export header method - ([290d163](https://github.com/0x676e67/wreq/commit/290d16395fd3c9b1f9509bbec0e978655cb20b9f))
- *(websocket)* Export `UpgradedRequestBuilder` - ([fac7251](https://github.com/0x676e67/wreq/commit/fac7251e922e802042bc6984928fa7d3c798e685))
- *(websocket)* Support configuration websocket - ([319dd6a](https://github.com/0x676e67/wreq/commit/319dd6a9fc6f6f18295e276bcd21d6ed63c0c9ee))
- Add loading of dynamic root certificate store ([#170](https://github.com/0x676e67/wreq/issues/170)) - ([44a5784](https://github.com/0x676e67/wreq/commit/44a578440a23f2c4bebabe137564c009f62b9049))
- Add `Edge 131` impersonate ([#158](https://github.com/0x676e67/wreq/issues/158)) - ([9dd73ab](https://github.com/0x676e67/wreq/commit/9dd73ab6c9d9839f9ad1a6381f5f78d7ef400108))
- Add `Safari 18.1.1` impersonate ([#157](https://github.com/0x676e67/wreq/issues/157)) - ([2c23ab0](https://github.com/0x676e67/wreq/commit/2c23ab002466f93c4dfcebaa2c4c7658ff18a7e1))
- Add `Safari 18.2` impersonate ([#151](https://github.com/0x676e67/wreq/issues/151)) - ([638864c](https://github.com/0x676e67/wreq/commit/638864c78cdeff1c5d107ca12933a255f35cbedb))
- Impl `IntoUrl` for `&Url` ([#146](https://github.com/0x676e67/wreq/issues/146)) - ([a1c2343](https://github.com/0x676e67/wreq/commit/a1c2343c76c811c55f6e54a81e7bbea8884c0e0e))
- Implement IntoUrl for Cow<'a, str> ([#145](https://github.com/0x676e67/wreq/issues/145)) - ([6c0b14c](https://github.com/0x676e67/wreq/commit/6c0b14ca224c42ed3d57bfe1acf21017dfbb3acf))
- Support changing cookie provider after initialization ([#114](https://github.com/0x676e67/wreq/issues/114)) - ([f1c5a07](https://github.com/0x676e67/wreq/commit/f1c5a07f2943ef0c4fc418d2e73ff558eafb7df1))
- Support changing interface after initialization - ([61ed45a](https://github.com/0x676e67/wreq/commit/61ed45a8acfaf1a2a47b09937b79b45364c1d0b1))
- Support changing interface after initialization ([#103](https://github.com/0x676e67/wreq/issues/103)) - ([81d79da](https://github.com/0x676e67/wreq/commit/81d79da1ef340386c5c10811a07b42b68af79d52))
- Support changing redirect policy after initialization ([#102](https://github.com/0x676e67/wreq/issues/102)) - ([1c4bc66](https://github.com/0x676e67/wreq/commit/1c4bc6634e5a9ff12a6e6dc4a240c5e056882f29))
- Support changing header order after initialization ([#101](https://github.com/0x676e67/wreq/issues/101)) - ([d5dd02b](https://github.com/0x676e67/wreq/commit/d5dd02bf96707cc83874cd25271ac94df9adfbf1))
- Support changing impersonate fingerprint after initialization ([#100](https://github.com/0x676e67/wreq/issues/100)) - ([50393ee](https://github.com/0x676e67/wreq/commit/50393ee3051af81f971a0215ce841498bef6ff29))
- Changing request headers after client initialization ([#97](https://github.com/0x676e67/wreq/issues/97)) - ([9954095](https://github.com/0x676e67/wreq/commit/99540955a55e9c89a2eb5bfc2cdd1cd64b5fc466))
- Add `Chrome 131` impersonate ([#94](https://github.com/0x676e67/wreq/issues/94)) - ([a425faf](https://github.com/0x676e67/wreq/commit/a425faf4c7fc6251b0bd4720621d50bd4321e7b3))
- Expose `hickory-resolver` as public API ([#93](https://github.com/0x676e67/wreq/issues/93)) - ([4bd5636](https://github.com/0x676e67/wreq/commit/4bd5636ab961023ee7d1d0acb3e359e3c665c733))
- Expose `tokio-boring` as public API ([#88](https://github.com/0x676e67/wreq/issues/88)) - ([5b28f91](https://github.com/0x676e67/wreq/commit/5b28f91857480ed1536891003b14998c404f5b82))
- Optionl BoringSSL PQ experimental feature ([#84](https://github.com/0x676e67/wreq/issues/84)) - ([3be7f0f](https://github.com/0x676e67/wreq/commit/3be7f0f10d3ca392734f201f24a3b0c901930a44))
- Improve unnecessary header sorting storage overhead ([#44](https://github.com/0x676e67/wreq/issues/44)) - ([8e8f88e](https://github.com/0x676e67/wreq/commit/8e8f88e2426a190a92ad438ec6a1240126eb38ef))
- Improve header sort ([#43](https://github.com/0x676e67/wreq/issues/43)) - ([d547d73](https://github.com/0x676e67/wreq/commit/d547d73f70784ccfd330f20f9f6c7486cb1752db))
- Add file function to async::multipart ([#32](https://github.com/0x676e67/wreq/issues/32)) - ([432e44e](https://github.com/0x676e67/wreq/commit/432e44eb78adc2e38c33bd55c072bd88f8bdd0fd))
- Add zstd support - ([d087d5c](https://github.com/0x676e67/wreq/commit/d087d5c02e1fdf8ce3022d2734880ec319e880d5))
- Update safari impersonate - ([ee38133](https://github.com/0x676e67/wreq/commit/ee38133de5b91e9f82e6e860f4bf0ccc6095a908))
- Enable client to be a service without ownership ([#1556](https://github.com/0x676e67/wreq/issues/1556)) - ([7a11d39](https://github.com/0x676e67/wreq/commit/7a11d397eb5990dc2346cf95ae0f186231d38388))
- Add Response::text() - ([2fbc201](https://github.com/0x676e67/wreq/commit/2fbc20167d6656850069c6496c73969c78b0a8d2))
- Set default headers - ([f4437ea](https://github.com/0x676e67/wreq/commit/f4437ea7b1c2a208fe07d17184d473b32b176ce4))

### 🐛 Bug Fixes

- *(client)* Return an error instead of panic when parsing invalid URL ([#164](https://github.com/0x676e67/wreq/issues/164)) - ([0daacd1](https://github.com/0x676e67/wreq/commit/0daacd1d7c6fcd1e44aee84dfbdbf4d384acc948))
- *(client)* Fix retry request via connection pool extension ([#138](https://github.com/0x676e67/wreq/issues/138)) - ([2971538](https://github.com/0x676e67/wreq/commit/2971538ebaaf0005ebc4b9d336d8243e7a613b23))
- *(client)* Fix redirect via connection pool extension ([#137](https://github.com/0x676e67/wreq/issues/137)) - ([6c3a0cb](https://github.com/0x676e67/wreq/commit/6c3a0cbd45a539ebc17b38c0841d25be3ef00307))
- *(client)* Fix redirect header sorting ([#135](https://github.com/0x676e67/wreq/issues/135)) - ([275baf6](https://github.com/0x676e67/wreq/commit/275baf63cecf609701bebd1d08c51cb1a27510cb))
- *(client)* Fix http redirect via proxy ([#134](https://github.com/0x676e67/wreq/issues/134)) - ([c71dd91](https://github.com/0x676e67/wreq/commit/c71dd915511b2b354d3f795f2c29779aec8e237d))
- *(client)* Fix `ClientBuilder` not `Send` + `Sync` ([#51](https://github.com/0x676e67/wreq/issues/51)) - ([c6312fc](https://github.com/0x676e67/wreq/commit/c6312fc6c8cbe6a11a67399e73d203b4f7091f8b))
- *(client)* Optional setting of default accept ([#133](https://github.com/0x676e67/wreq/issues/133)) - ([fc4df7c](https://github.com/0x676e67/wreq/commit/fc4df7ced3d564d1f4b1475cfc9a68e808be342a))
- *(client)* Fix the header sending order, set accept before request ([#131](https://github.com/0x676e67/wreq/issues/131)) - ([2beae56](https://github.com/0x676e67/wreq/commit/2beae56c0a0e9119e270864ca4efbbc0d557a917))
- *(client)* Fix http version setting order ([#120](https://github.com/0x676e67/wreq/issues/120)) - ([60f3521](https://github.com/0x676e67/wreq/commit/60f352157a3483104170d10bc0f1367110b24d34))
- *(client)* `headers_order` error - ([1801359](https://github.com/0x676e67/wreq/commit/1801359894ac277c9cb6fd4c48f1c459b3adab2f))
- *(connect)* Unnecessarily panic when parsing invalid URI ([#166](https://github.com/0x676e67/wreq/issues/166)) - ([b42559b](https://github.com/0x676e67/wreq/commit/b42559beed13ab5fcfe881dc2cae36f932b54f14))
- *(connector)* Initialize pool key extension when creating a client ([#126](https://github.com/0x676e67/wreq/issues/126)) - ([d6e3878](https://github.com/0x676e67/wreq/commit/d6e38788498a56e0f89162bb15210d3bd82e7ab1))
- *(connector)* Fix TLS session failure when changing address ([#55](https://github.com/0x676e67/wreq/issues/55)) - ([ed39758](https://github.com/0x676e67/wreq/commit/ed39758a9155652b4f7fd63900c4eaf60590c92c))
- *(extension)* Fix configure chrome new curves ([#67](https://github.com/0x676e67/wreq/issues/67)) - ([bd872e4](https://github.com/0x676e67/wreq/commit/bd872e4d221938f88d1a42b5816d62c8834f8427))
- *(hickory-dns)* Fix initialization when `/etc/resolv.conf` is missing ([#163](https://github.com/0x676e67/wreq/issues/163)) - ([97ed7d6](https://github.com/0x676e67/wreq/commit/97ed7d63773f411e4bdea66aa6dfea6f536ac2c1))
- *(http)* Compatible with some CDN servers, Http1 retains case by default when sending headers([#56](https://github.com/0x676e67/wreq/issues/56)) - ([f653f9c](https://github.com/0x676e67/wreq/commit/f653f9c6563d28abf4ebf96ce3882daaa03c84ed))
- *(impersonate)* Fix safari header order ([#72](https://github.com/0x676e67/wreq/issues/72)) - ([f9be4a4](https://github.com/0x676e67/wreq/commit/f9be4a482c5fa63664f6b23a8f8139a48fa80c5d))
- *(impersonate)* Fix `safari15_3`/`safari15_5` http2 fingerprint ([#70](https://github.com/0x676e67/wreq/issues/70)) - ([63ef44e](https://github.com/0x676e67/wreq/commit/63ef44e86ddad718547000e1352898fdaa7697c6))
- *(impersonate)* Add Safari17_5 from string - ([1ce9a61](https://github.com/0x676e67/wreq/commit/1ce9a610df3afd35a235fde333aed0ded34dabb9))
- *(impersonate)* Fix v116 impersonate - ([427f6a2](https://github.com/0x676e67/wreq/commit/427f6a22025934ae0e759840b5d7c16b4015d2fe))
- *(proxy)* Make HTTP(S)_PROXY variables take precedence over ALL_PROXY ([#87](https://github.com/0x676e67/wreq/issues/87)) - ([e28b30a](https://github.com/0x676e67/wreq/commit/e28b30a3da8e4fcb075c07da6e677ffbb80ed681))
- *(response)* `copy_to()` and `text()` return `reqwest::Result` - ([2c60511](https://github.com/0x676e67/wreq/commit/2c60511bcee3c633467b6be46f3d1e27af5f0905))
- *(tls)* Fix SNI verification ([#87](https://github.com/0x676e67/wreq/issues/87)) - ([0cfb181](https://github.com/0x676e67/wreq/commit/0cfb181a895bbd32f8ad48b1eeb376172a077232))
- *(tls)* Fix unsafe code block warnings ([#52](https://github.com/0x676e67/wreq/issues/52)) - ([127a1a9](https://github.com/0x676e67/wreq/commit/127a1a923b2203e31de41d171acd37e14aa5fb9f))
- *(tls)* Fix CA certificate conditional compilation ([#41](https://github.com/0x676e67/wreq/issues/41)) - ([27b4119](https://github.com/0x676e67/wreq/commit/27b411915be3314338427186fac5760a615c4f11))
- *(tls)* Fix default tls configuration to use websocket ([#30](https://github.com/0x676e67/wreq/issues/30)) - ([889867c](https://github.com/0x676e67/wreq/commit/889867c6194a7fb812d1a3ec957e30f0757bfcc1))
- *(tls)* Fix default TLS SNI context configuration conflict ([#13](https://github.com/0x676e67/wreq/issues/13)) - ([94db0fc](https://github.com/0x676e67/wreq/commit/94db0fca006ca65d0d13f04eb23237512113937b))
- *(tls)* Fix setting config TLS version - ([6544c11](https://github.com/0x676e67/wreq/commit/6544c111048bcf0513cd7a6ba8ba148f65502ac9))
- *(tls)* Fix optional config TLS size version - ([bb16145](https://github.com/0x676e67/wreq/commit/bb16145fa799f3b078ed50a695cbd27a02f0457e))
- *(websocket)* Fix websocket upgrade builder ([#134](https://github.com/0x676e67/wreq/issues/134)) - ([111d928](https://github.com/0x676e67/wreq/commit/111d92877982dded4dd2b5c63318dff43631c967))
- Improve TLS connector creation, fix client creation taking too long ([#107](https://github.com/0x676e67/wreq/issues/107)) - ([26f254c](https://github.com/0x676e67/wreq/commit/26f254c5b805ddaf6cf423b55aad5e74760796da))
- Fix decompressing deflate with zlib specific wrapper fails ([#99](https://github.com/0x676e67/wreq/issues/99)) - ([c865b9c](https://github.com/0x676e67/wreq/commit/c865b9cf5dad766c9da35e85757a0a26e2f3efbf))
- Update Chrome version from 129 to 130 ([#68](https://github.com/0x676e67/wreq/issues/68)) - ([f27704a](https://github.com/0x676e67/wreq/commit/f27704a876dd28b929a534e212b53218141a789e))
- Fix incorrect Accept-Encoding header combinations in Accepts::as_str ([#89](https://github.com/0x676e67/wreq/issues/89)) - ([1373a01](https://github.com/0x676e67/wreq/commit/1373a018b3c374a28e37aed8a3da9fd563a8f665))
- Set nodelay correctly to handle when a tls feature is enabled but connection is to an http server ([#2062](https://github.com/0x676e67/wreq/issues/2062)) - ([1485ce6](https://github.com/0x676e67/wreq/commit/1485ce6f754413a81a9673252349f953c1d86e82))
- Split connect timeout for multiple IPs ([#1940](https://github.com/0x676e67/wreq/issues/1940)) - ([2a881fb](https://github.com/0x676e67/wreq/commit/2a881fb50489b21aa6c879eea0cb339755240fb5))
- Strip BOM in `Response::text_with_charset` ([#1898](https://github.com/0x676e67/wreq/issues/1898)) - ([3abcc7c](https://github.com/0x676e67/wreq/commit/3abcc7c4f537c16ad9937f8cc60fb23cb506ac85))
- Strip BOM in Response::text_with_charset - ([d820ad2](https://github.com/0x676e67/wreq/commit/d820ad237feade4527743067c8f6fc3e19972c7b))
- Wasm client: pass response header to builder by reference ([#1350](https://github.com/0x676e67/wreq/issues/1350)) - ([c9217d8](https://github.com/0x676e67/wreq/commit/c9217d8d1bc6c65605ad4909cb45a1cb72b778a0))
- Respect https_only option when redirecting ([#1313](https://github.com/0x676e67/wreq/issues/1313)) - ([bdc57be](https://github.com/0x676e67/wreq/commit/bdc57beabbf3fe77c2196d17ef3f7640d37b81cf))
- Upgrade to http2 if the server reports that it supports it ([#1166](https://github.com/0x676e67/wreq/issues/1166)) - ([2940740](https://github.com/0x676e67/wreq/commit/2940740493ce55e8baee44a47fd759d9e3aa3187))
- Tests::support::server - ([07d6bca](https://github.com/0x676e67/wreq/commit/07d6bca08f0ef8deb752eb17e87ecca1e2c441ae))

### 🚜 Refactor

- *(client)* Removed confusing way to enable `hickory-dns` ([#34](https://github.com/0x676e67/wreq/issues/34)) - ([769d797](https://github.com/0x676e67/wreq/commit/769d7979f583ac435d808a8831c806638e009c7a))
- *(client)* Turn off default redirect ([#4](https://github.com/0x676e67/wreq/issues/4)) - ([2b80121](https://github.com/0x676e67/wreq/commit/2b80121e69cb15f74885516429406df457eb1c56))
- *(client)* Simplify Headers Frame priority settings ([#126](https://github.com/0x676e67/wreq/issues/126)) - ([3449c2f](https://github.com/0x676e67/wreq/commit/3449c2f54ed4fcc9d94bfc484b2b739dd892e474))
- *(client)* Set_proxies accepts an slice of references ([#119](https://github.com/0x676e67/wreq/issues/119)) - ([a25ada0](https://github.com/0x676e67/wreq/commit/a25ada0a0cf297ab43b48fd7915d3c24f740028d))
- *(hickory-dns)* Async `new_resolver` ([#84](https://github.com/0x676e67/wreq/issues/84)) - ([73ff128](https://github.com/0x676e67/wreq/commit/73ff1286ac383372f84f5a37e653c237032c2192))
- *(impersonate)* Simplify Impersonate enum parsing with macro ([#71](https://github.com/0x676e67/wreq/issues/71)) - ([b3efecf](https://github.com/0x676e67/wreq/commit/b3efecf6221510b6ac9d55a0b651f321d0557635))
- *(impersonate)* Reuse code - ([dbc6d66](https://github.com/0x676e67/wreq/commit/dbc6d662b2feb33231c1e37b780c6645761d23bb))
- *(impersonate)* Refactor unnecessary settings - ([716a190](https://github.com/0x676e67/wreq/commit/716a190617dbe73b6fd771e05748179221cdaac6))
- *(impersonate)* Revert to SslVerifyMode::NONE - ([f921d58](https://github.com/0x676e67/wreq/commit/f921d5814ac12027fdf5c05af0ebe5518348ff60))
- *(impersonate)* Update SSL verify mode - ([3ca497c](https://github.com/0x676e67/wreq/commit/3ca497cc74f7f846e7ca25068dbcf049e523c31e))
- *(proxy)* Remove internal proxy sys cache ([#26](https://github.com/0x676e67/wreq/issues/26)) - ([714b48f](https://github.com/0x676e67/wreq/commit/714b48fbe3d070126054ef96b58f8b85b208db7f))
- *(tls)* Simplified TLS version mappr ([#70](https://github.com/0x676e67/wreq/issues/70)) - ([2e2ebf9](https://github.com/0x676e67/wreq/commit/2e2ebf9a7bec8492de1d01d2b19bc5526e4164ac))
- *(tls)* Refactor internal `TLS`/`HTTP2` module ([#69](https://github.com/0x676e67/wreq/issues/69)) - ([7f10e51](https://github.com/0x676e67/wreq/commit/7f10e519f1ae74cca2a59bb88b6bba312fea029f))
- *(tls)* Simplify TLS custom settings ([#46](https://github.com/0x676e67/wreq/issues/46)) - ([499fe4a](https://github.com/0x676e67/wreq/commit/499fe4aa3486d9dcc4292b5cf9153b1c987dd2f4))
- *(tls)* Public and reuse tls/http2 templates ([#42](https://github.com/0x676e67/wreq/issues/42)) - ([e082581](https://github.com/0x676e67/wreq/commit/e08258124fba80dc9d6f2a1f4d1804c9685a9fb6))
- *(tls)* Simplify TLS/HTTP2 configuration ([#7](https://github.com/0x676e67/wreq/issues/7)) - ([c44d01f](https://github.com/0x676e67/wreq/commit/c44d01f42350e0bb736a7e360147fb4763559551))
- *(tls)* Simplify TLS configuration ([#5](https://github.com/0x676e67/wreq/issues/5)) - ([56840ab](https://github.com/0x676e67/wreq/commit/56840ab4652f809a429325919aeedec9d5010634))
- *(tls)* Refactored changes and refactored TLS build - ([c1b1e09](https://github.com/0x676e67/wreq/commit/c1b1e097f6e690000a35df16eb537029f1253c57))
- *(tls)* Refactor TLS connection layer configuration ([#111](https://github.com/0x676e67/wreq/issues/111)) - ([db4e566](https://github.com/0x676e67/wreq/commit/db4e566f9c494c7905b8e9022b68426d0b96e4ae))
- *(tls)* Simplify TLS connector configuration ([#103](https://github.com/0x676e67/wreq/issues/103)) - ([322d030](https://github.com/0x676e67/wreq/commit/322d030968a0106220be5c0e6c4641680ddba3cd))
- *(tls)* Major module changes ([#91](https://github.com/0x676e67/wreq/issues/91)) - ([76114b0](https://github.com/0x676e67/wreq/commit/76114b0a6674b0afd2d8cb5927fe2d6f58705458))
- *(websocket)* Major changes, abstract WebSocket message structure ([#94](https://github.com/0x676e67/wreq/issues/94)) - ([266f0cb](https://github.com/0x676e67/wreq/commit/266f0cbf72c40262912be32c0a144a185fcac50e))
- Unified naming API ([#150](https://github.com/0x676e67/wreq/issues/150)) - ([da5e052](https://github.com/0x676e67/wreq/commit/da5e052c9f31fb908c30c21953ee01c6344b68fe))
- Do not create default request headers unless necessary ([#120](https://github.com/0x676e67/wreq/issues/120)) - ([1d40d7e](https://github.com/0x676e67/wreq/commit/1d40d7e576eb796ce9d74815ab9937ca1cb17640))
- Reduce `unsafe` scope for improved safety and readability ([#115](https://github.com/0x676e67/wreq/issues/115)) - ([79e6cb8](https://github.com/0x676e67/wreq/commit/79e6cb8b055d71b35d630ef11908b3fb8707e2e7))
- Delete unnecessary clone ([#98](https://github.com/0x676e67/wreq/issues/98)) - ([c5c6004](https://github.com/0x676e67/wreq/commit/c5c6004785c1c14721c6643af67fcdc728757f68))
- Integrate tls/http2 unified configuration module ([#77](https://github.com/0x676e67/wreq/issues/77)) - ([cef5650](https://github.com/0x676e67/wreq/commit/cef5650fa3fe208a97fddf8fd27715893770a020))
- Normalize DNS module exports ([#64](https://github.com/0x676e67/wreq/issues/64)) - ([b0a1ba6](https://github.com/0x676e67/wreq/commit/b0a1ba6f6de1964c31145a3a23ec8175cf195925))
- Refactor custom root CA certificate loading source ([#38](https://github.com/0x676e67/wreq/issues/38)) - ([cfd3603](https://github.com/0x676e67/wreq/commit/cfd36030927c617c38d0bfd0fd6e09c4112d4a45))
- Rename the `client` module to `http` - ([5568b31](https://github.com/0x676e67/wreq/commit/5568b31cb3df741bb1f8f507f2b7858b00395263))
- Enabled `accept-encoding` will be determined by the `feature` ([#95](https://github.com/0x676e67/wreq/issues/95)) - ([85de77b](https://github.com/0x676e67/wreq/commit/85de77b1eca6272dfba13d61f8392563b561c835))
- Enabling `accept-encoding` will be determined by the feature - ([4bf9465](https://github.com/0x676e67/wreq/commit/4bf94652db2b776a0df366d9f2e3c8d44daf7c52))
- Blocking feature doesn't need multi-threaded tokio runtime ([#90](https://github.com/0x676e67/wreq/issues/90)) - ([7ab0c67](https://github.com/0x676e67/wreq/commit/7ab0c678d7ffc6f23b4b039db702e380492f4df8))
- Change Debug of Error to output url as str ([#88](https://github.com/0x676e67/wreq/issues/88)) - ([b9b684b](https://github.com/0x676e67/wreq/commit/b9b684b2212878ef84a5c18da3f5122bcd74ecab))
- Remove unused crates - ([9fb269e](https://github.com/0x676e67/wreq/commit/9fb269e5f38a0e200000db2ac0a3786d859575f2))
- Remove unused crates ([#54](https://github.com/0x676e67/wreq/issues/54)) - ([c0c273d](https://github.com/0x676e67/wreq/commit/c0c273d4e648a0441ab9efee63927ff263e9f27a))
- Migrate trust-dns to hickory-dns - ([ae7d775](https://github.com/0x676e67/wreq/commit/ae7d7753f005120182e9a00486beb7f196b8c5fd))
- Migrate trust-dns to hickory-dns - ([712600a](https://github.com/0x676e67/wreq/commit/712600a2e11cf21e850183391d1e77caedc297bd))
- Disable ssl verify - ([5680bb0](https://github.com/0x676e67/wreq/commit/5680bb0a290d6556ba2f358293dca31824c68af8))

### 📚 Documentation

- Improve `TLS`/`HTTP2` custom configuration documentation ([#67](https://github.com/0x676e67/wreq/issues/67)) - ([8a72439](https://github.com/0x676e67/wreq/commit/8a72439a3c9aa2c8c06492d8928330bac518d6e3))
- Update docs ([#54](https://github.com/0x676e67/wreq/issues/54)) - ([a010145](https://github.com/0x676e67/wreq/commit/a01014519b499621fec2fb03a7e9d3c333c1855d))
- Update docs ([#82](https://github.com/0x676e67/wreq/issues/82)) - ([41816f8](https://github.com/0x676e67/wreq/commit/41816f8b26e42be0166c8df9cb6492c71be77056))
- Fix docs build ([#81](https://github.com/0x676e67/wreq/issues/81)) - ([2045cea](https://github.com/0x676e67/wreq/commit/2045cea5e05abcfeb7c91d94a1e0497eb22bfe19))
- Add cfg notes about http3 builder methods ([#2070](https://github.com/0x676e67/wreq/issues/2070)) - ([c65dd7f](https://github.com/0x676e67/wreq/commit/c65dd7f783d8aae8ee47e751353d1befeb9dea20))
- Remove redundant link targets ([#2019](https://github.com/0x676e67/wreq/issues/2019)) - ([50dbaf3](https://github.com/0x676e67/wreq/commit/50dbaf391087cfa951accc765126b4f5d017d8a3))
- Fix building on docs.rs ([#1789](https://github.com/0x676e67/wreq/issues/1789)) - ([7fdd014](https://github.com/0x676e67/wreq/commit/7fdd014d46d9bf07555a2321166f3029e9a25ac8))
- Fix wording on main docs page ([#1765](https://github.com/0x676e67/wreq/issues/1765)) - ([673449a](https://github.com/0x676e67/wreq/commit/673449aa823394d224815b8cc168e059e4c4ebe1))
- Fix some typos ([#1562](https://github.com/0x676e67/wreq/issues/1562)) - ([81fc85a](https://github.com/0x676e67/wreq/commit/81fc85a68949bd0ff73cfd9f292393b5c5ed42ed))
- Fix broken doc comment example. ([#1584](https://github.com/0x676e67/wreq/issues/1584)) - ([e9ba0a9](https://github.com/0x676e67/wreq/commit/e9ba0a9dc79f63c3655f334df23b50b9a841e326))
- Fix some typos ([#1531](https://github.com/0x676e67/wreq/issues/1531)) - ([6ca5f3e](https://github.com/0x676e67/wreq/commit/6ca5f3e50c979909b786a4f1e2c73611164254c7))
- Provide basic auth example ([#1362](https://github.com/0x676e67/wreq/issues/1362)) - ([be8ab7b](https://github.com/0x676e67/wreq/commit/be8ab7b951610cbc85764198943ab053e8608454))
- Fix some typos ([#1346](https://github.com/0x676e67/wreq/issues/1346)) - ([597833d](https://github.com/0x676e67/wreq/commit/597833d906f2453a6976e6ed6ed71af91c534382))
- Adds amplifying note about private key formats ([#1335](https://github.com/0x676e67/wreq/issues/1335)) - ([eb9e343](https://github.com/0x676e67/wreq/commit/eb9e343142b7fe7392408141dab7145cb4a30ba2))
- Build wasm32-unknown-unknown docs ([#998](https://github.com/0x676e67/wreq/issues/998)) - ([cff487f](https://github.com/0x676e67/wreq/commit/cff487ff58630cf0ac59f3e46cbf20cf50a28b3f))
- Make encoding_rs link clickable ([#674](https://github.com/0x676e67/wreq/issues/674)) - ([a9dd94a](https://github.com/0x676e67/wreq/commit/a9dd94a99fdb30a77992ea0afa552f266efbd8a3))

### 🎨 Styling

- *(connect)* Replace all non-refutable if let patterns with let statements ([#44](https://github.com/0x676e67/wreq/issues/44)) - ([ec598d8](https://github.com/0x676e67/wreq/commit/ec598d8b9262680b570ac15fff1623a0e050edb8))
- *(impersonate)* Remove dead code ([#51](https://github.com/0x676e67/wreq/issues/51)) - ([61c6055](https://github.com/0x676e67/wreq/commit/61c605531881215c8ab95f8eda557969c7d6d6fb))
- *(tls)* Remove unused closure - ([a39ba21](https://github.com/0x676e67/wreq/commit/a39ba2198e5a7144b60567f9cb815c1fc7d85d2e))

### 🧪 Testing

- Fix test_badssl_no_built_in_roots - ([427ff74](https://github.com/0x676e67/wreq/commit/427ff74adf2266413413b2ab4da6c5669efadf33))
- Add more badssl tests for rustls - ([8027a28](https://github.com/0x676e67/wreq/commit/8027a2894af496ce25c7f2a035e265cc8bf9bf59))
- Response::text() - ([33c7ce4](https://github.com/0x676e67/wreq/commit/33c7ce4ce2f65587ea60c011151a5605887e97f3))
- Add tests for setting default headers - ([2bd558d](https://github.com/0x676e67/wreq/commit/2bd558d8c74a03622dbb02d194440aa13c0a9048))
- Use verbose output - ([f5b4dd4](https://github.com/0x676e67/wreq/commit/f5b4dd4123f4f2098895be3833e81cdf9b5a8460))
- Fixed up issue with reading a Body and finished RequestBuilder tests - ([59ba7cf](https://github.com/0x676e67/wreq/commit/59ba7cf23b48c94c7223cf0f2047e9e7b1e0a275))
- Added some trivial tests for the RequestBuilder - ([980488f](https://github.com/0x676e67/wreq/commit/980488f918a70f24a859f3776f4b4dd947c3758e))

### ⚙️ Miscellaneous Tasks

- *(client)* Client `set_redirect_policy` rename to `set_redirect` ([#149](https://github.com/0x676e67/wreq/issues/149)) - ([0ed4a76](https://github.com/0x676e67/wreq/commit/0ed4a76067b87568a33a110be6d742b946875ede))
- *(client)* Accept request header is appended by default ([#125](https://github.com/0x676e67/wreq/issues/125)) - ([06ccdc7](https://github.com/0x676e67/wreq/commit/06ccdc70c685ef5a8817fcbef177566ec7be50b4))
- *(client)* Impersonate does not clone request headers unless necessary - ([2043388](https://github.com/0x676e67/wreq/commit/204338837c20ac0bffd585b4f7238b5b58650254))
- *(docs)* Fix missing link for 'blocking' - ([4574019](https://github.com/0x676e67/wreq/commit/457401904596260c712c0b9f4f27e6d47b4a2141))
- *(request)* Avoid panic when adding host header - ([80e4871](https://github.com/0x676e67/wreq/commit/80e48718e634dd6696688d415e858c46acffbc81))
- *(request)* Delete WASM legacy API ([#141](https://github.com/0x676e67/wreq/issues/141)) - ([ddcd980](https://github.com/0x676e67/wreq/commit/ddcd9806d49dbcf47e55389bf5dc97871d566377))
- *(tls)* Rename `http_version_pref` to `alpn_protos` ([#131](https://github.com/0x676e67/wreq/issues/131)) - ([4b7edba](https://github.com/0x676e67/wreq/commit/4b7edba4a792504382567d18451074a249b0a2bc))
- *(tls)* Export extension as public API - ([05a6a6f](https://github.com/0x676e67/wreq/commit/05a6a6fec7390736d71d818c1b8aa20f96d3e95f))
- *(tls)* Remove redundant settings ([#109](https://github.com/0x676e67/wreq/issues/109)) - ([ecda80c](https://github.com/0x676e67/wreq/commit/ecda80cf576de73e854ed7e5efca3843fdb6d062))
- Move `ImpersonateSettings` to implement location - ([99ea68b](https://github.com/0x676e67/wreq/commit/99ea68b161ed7ac8e3b384464cb270034b831bce))
- Simplify root certificate load ([#169](https://github.com/0x676e67/wreq/issues/169)) - ([68e9f26](https://github.com/0x676e67/wreq/commit/68e9f26a946c781bd1c06fd67dbfb3c13894350d))
- Simplify root certificate load - ([566f2fb](https://github.com/0x676e67/wreq/commit/566f2fb7a4a0e5cb7d1899db5257e509d5d9f142))
- To avoid ambiguity, `ca_cert_store` is renamed to `root_certs_store` ([#162](https://github.com/0x676e67/wreq/issues/162)) - ([b76ef15](https://github.com/0x676e67/wreq/commit/b76ef15e2fdc206cd949fd44e7a147ee52e91ac3))
- Update macro export scope - ([3115132](https://github.com/0x676e67/wreq/commit/3115132eee19a7e303adaadce87c8740a222f167))
- Update impersonate template - ([82d7b93](https://github.com/0x676e67/wreq/commit/82d7b9331ddc24d546115a54ac594f84dc49f137))
- Macro static creation of impersonate template ([#156](https://github.com/0x676e67/wreq/issues/156)) - ([7383d66](https://github.com/0x676e67/wreq/commit/7383d6630a20dd104825bdb6a9fed80482ee3450))
- Do not pre-append `content-length` in non-header sorting state ([#152](https://github.com/0x676e67/wreq/issues/152)) - ([075f973](https://github.com/0x676e67/wreq/commit/075f97304ffb8f3889dee5a22c4220818afecbb4))
- Simplify the impersonate template - ([92f52d1](https://github.com/0x676e67/wreq/commit/92f52d1e596d69f6b8690704ab74ac2def7740b3))
- Fix typo - ([650256c](https://github.com/0x676e67/wreq/commit/650256c42aa6cf9582e83e8d750bb1b50ca5d134))
- Introduce macro for conditional header initialization ([#127](https://github.com/0x676e67/wreq/issues/127)) - ([b8a2e48](https://github.com/0x676e67/wreq/commit/b8a2e488796c509901f90f32c4549c78c3bcdc49))
- Refactor struct fields to use Cow<'static, T> for better efficiency ([#124](https://github.com/0x676e67/wreq/issues/124)) - ([8b79c5b](https://github.com/0x676e67/wreq/commit/8b79c5b4182e6e4e861b37b6db76f3a9c4a4a81b))
- Cache template request headers ([#121](https://github.com/0x676e67/wreq/issues/121)) - ([3b65d8f](https://github.com/0x676e67/wreq/commit/3b65d8faca44fc6d241e59140db92238c6eef49b))
- Update - ([7d1bbbc](https://github.com/0x676e67/wreq/commit/7d1bbbc8c97247be5d43957ed68438465f311388))
- Simplify impersonate template - ([871a7af](https://github.com/0x676e67/wreq/commit/871a7af7074b7dbe1bfffa93445d98da3a3fc08e))
- Simplify pre-configured TLS settings - ([2ca512e](https://github.com/0x676e67/wreq/commit/2ca512ee0b793ffcce22927c2e3fbb91e36ec05a))
- Remove tunnel proxy user agent setting ([#116](https://github.com/0x676e67/wreq/issues/116)) - ([04fa9fa](https://github.com/0x676e67/wreq/commit/04fa9fafb5b6bc6401fe738109e58f7e0473fc11))
- Reuse redirect policies whenever possible - ([49bb717](https://github.com/0x676e67/wreq/commit/49bb7174a2b84d88855805d1dcea5966e6133cdb))
- Inline some hot code - ([a07cf10](https://github.com/0x676e67/wreq/commit/a07cf105fb84a97264d4af71fd7f5962790b6f48))
- Use custom connector builder - ([6c51bd1](https://github.com/0x676e67/wreq/commit/6c51bd1d4b8592181a2fa59164d054b96fbe41d6))
- Disable dynamic distribution loading of connector builder ([#113](https://github.com/0x676e67/wreq/issues/113)) - ([6814489](https://github.com/0x676e67/wreq/commit/6814489773f67c84cc83f316e98ab6da38913b5b))
- Disable dynamic distribution loading of certificates ([#112](https://github.com/0x676e67/wreq/issues/112)) - ([75095ba](https://github.com/0x676e67/wreq/commit/75095ba8d3085bfd52bb92e581ec76ec7b923bb2))
- Undo the dynamic distribution configuration headers ([#111](https://github.com/0x676e67/wreq/issues/111)) - ([a7c9376](https://github.com/0x676e67/wreq/commit/a7c937603966bae1b811d3cb9b67f3958279e579))
- Cargo clippy --fix ([#106](https://github.com/0x676e67/wreq/issues/106)) - ([065f294](https://github.com/0x676e67/wreq/commit/065f294a1b67ac9bb979966f955500e4f93a4098))
- Remove unnecessary tls feature - ([7f70c48](https://github.com/0x676e67/wreq/commit/7f70c48f63d27409b509dc620b4451e061548ef2))
- 1.80 as MSRV ([#74](https://github.com/0x676e67/wreq/issues/74)) - ([9814951](https://github.com/0x676e67/wreq/commit/98149512c90cc51d51d14cf3e0cfe8d26899b49d))
- 1.70 as MSRV - ([34bc71d](https://github.com/0x676e67/wreq/commit/34bc71d13ccab181869ae377ff0d3c8ae0779f64))
- 1.70 as MSRV ([#53](https://github.com/0x676e67/wreq/issues/53)) - ([29adc92](https://github.com/0x676e67/wreq/commit/29adc923bd197f8d92cf03d964d689c7b01e27de))
- A few simple cleanups/lints ([#1849](https://github.com/0x676e67/wreq/issues/1849)) - ([280af15](https://github.com/0x676e67/wreq/commit/280af156459845a6b4535aa9045979861b67c310))
- Update changelog for 0.11.15 - ([bf7ff55](https://github.com/0x676e67/wreq/commit/bf7ff556494bc5e35164c325faad49e1cdd3c8e9))
- Fix appveyor build for backtrace-sys dependency ([#526](https://github.com/0x676e67/wreq/issues/526)) - ([2a64140](https://github.com/0x676e67/wreq/commit/2a64140de82d93ca2b3a804c07f16e7a5bf66fa1))
- Update gitignore - ([3bc907f](https://github.com/0x676e67/wreq/commit/3bc907f7deaeff0a9f9e02c7c3f9e4c4495aeafe))

### ◀️ Revert

- *(client)* Remove use of unused TLS Server Name Indication - ([a935f99](https://github.com/0x676e67/wreq/commit/a935f992194542b3dd4b6204963eeb3b53d5f8d0))
- *(impersonate)* Revert Edge122 configure new curves ([#66](https://github.com/0x676e67/wreq/issues/66)) - ([ba5cd48](https://github.com/0x676e67/wreq/commit/ba5cd48a3982b370924c06c82bf26e93191a146b))
- *(impersonate)* Remove chrome99 impersonate ([#38](https://github.com/0x676e67/wreq/issues/38)) - ([8f9ebdd](https://github.com/0x676e67/wreq/commit/8f9ebdd608ac4f8a21bcc59fce6c8710dd03d757))
- *(tls)* Revert tls_built_in_root_certs option ([#105](https://github.com/0x676e67/wreq/issues/105)) - ([d0cda0b](https://github.com/0x676e67/wreq/commit/d0cda0be402797c265e209a7b9fee55db89a2faa))
- Remove `proxies_maybe_http_auth` state - ([52791a6](https://github.com/0x676e67/wreq/commit/52791a69dba7d61620257c0736c809683e1b3626))

### Body

- Don't call poll_ready on tx when 0 bytes remaining. ([#479](https://github.com/0x676e67/wreq/issues/479)) - ([d62f8c2](https://github.com/0x676e67/wreq/commit/d62f8c2bbd39d6cf5562c2f3c0aad32bad81d331))

### CI

- Enable dependabot for GitHub Action Workflow ([#1831](https://github.com/0x676e67/wreq/issues/1831)) - ([eca2a2f](https://github.com/0x676e67/wreq/commit/eca2a2f23f97409e6828e171b13d0eb3bc34465c))
- Make a single final job that depends on all others ([#1291](https://github.com/0x676e67/wreq/issues/1291)) - ([b9cf2db](https://github.com/0x676e67/wreq/commit/b9cf2db69756cde5e3091cc6a06cff1deb2e3764))
- Check documentation ([#1246](https://github.com/0x676e67/wreq/issues/1246)) - ([9293cd2](https://github.com/0x676e67/wreq/commit/9293cd206143d48bb68033b7de835ca2c6cdeea3))

### Doc

- `stream` feature is needed for `wrap_stream` and `From<File>` for `Body` ([#1456](https://github.com/0x676e67/wreq/issues/1456)) - ([9339c54](https://github.com/0x676e67/wreq/commit/9339c543235ca09664e388284811746020350b4b))

### Error

- Add functions to check more error types. ([#945](https://github.com/0x676e67/wreq/issues/945)) - ([668e89b](https://github.com/0x676e67/wreq/commit/668e89b78ae1e7a0e88fb7f99649b7c907d2f0da))

### Examples

- Allow passing URL via CLI - ([7388b67](https://github.com/0x676e67/wreq/commit/7388b676df8431b63edc337ce8dc3032953fe07e))

### Feature

- Auto detect MacOS proxy settings ([#1955](https://github.com/0x676e67/wreq/issues/1955)) - ([70d100c](https://github.com/0x676e67/wreq/commit/70d100c1b81dc8856e7cfb7b31b682c2028ca877))

### From<http

- :Response> for Response ([#360](https://github.com/0x676e67/wreq/issues/360)) - ([4857a59](https://github.com/0x676e67/wreq/commit/4857a5917dd5445a3f5ed04edcff01b95eda7823))

### Impersonate

- Bugfix `chrome_123`, `chrome_124` headers - ([429bb1d](https://github.com/0x676e67/wreq/commit/429bb1d763d5a4c37a0104efe7c03ecdc6434071))

### Lint

- Fix unused `Identity` if only using `default-tls` ([#1164](https://github.com/0x676e67/wreq/issues/1164)) - ([287a6d1](https://github.com/0x676e67/wreq/commit/287a6d18528418381dbb28e7bd6728b1ac24b5d3))

### Response.copy_to

- Fix docs markup - ([4aa34bb](https://github.com/0x676e67/wreq/commit/4aa34bb5916a70e8216e5198cea278d42967d74b))

### WASM

- Add `try_clone` implementations to `Request` and `RequestBuilder` ([#1286](https://github.com/0x676e67/wreq/issues/1286)) - ([c4388fc](https://github.com/0x676e67/wreq/commit/c4388fcff9401d23169c6731901457e89039bf53))
- Set RequestCredentials to None by default ([#1249](https://github.com/0x676e67/wreq/issues/1249)) - ([42b3160](https://github.com/0x676e67/wreq/commit/42b31600c30609cb8df90c799fbfbd0c305e422d))

### [#1095]

- Implement `basic_auth` for WASM - ([28840af](https://github.com/0x676e67/wreq/commit/28840afd46fe3b81b7c77dde4537ad702826c7f7))

### Actions

- Remove --all flag from rustfmt ([#795](https://github.com/0x676e67/wreq/issues/795)) - ([b3d5f78](https://github.com/0x676e67/wreq/commit/b3d5f78b8f3ddd36a4fc6568e8a091f947dd0ff5))

### Async

- Add conversions from static slices to Body - ([87f03e1](https://github.com/0x676e67/wreq/commit/87f03e167c0deba25f1ca40376a5b69d598cb88f))

### Async/client

- Return a impl Future on execute() - ([4fba983](https://github.com/0x676e67/wreq/commit/4fba983e5e6722a457a10988e20e5277faf01e4c))

### Async/reponse

- Return a impl Future on json() - ([5e38b41](https://github.com/0x676e67/wreq/commit/5e38b419f00d6526e67078b8dd52054859a5ede5))

### Async/request

- Add methods to split and reassemble a RequestBuilder ([#1770](https://github.com/0x676e67/wreq/issues/1770)) - ([119366e](https://github.com/0x676e67/wreq/commit/119366e95720aa1b35e5bf79cd91255d6050e360))
- Add a basic example for send() - ([0c84e6b](https://github.com/0x676e67/wreq/commit/0c84e6b9e9a7f48edc3b591bf7e28caa4f246ecd))
- Return a impl Future on send() - ([8b62f47](https://github.com/0x676e67/wreq/commit/8b62f47ac3f5de43fbbe0445d0958eb8710f9174))

### Blocking

- Add tcp_keepalive option ([#1100](https://github.com/0x676e67/wreq/issues/1100)) - ([a2133ae](https://github.com/0x676e67/wreq/commit/a2133aec3b313bb370c0cf88173de33ce7cba465))
- Opt-out CPUs auto-detection in debug mode ([#807](https://github.com/0x676e67/wreq/issues/807)) - ([7622c75](https://github.com/0x676e67/wreq/commit/7622c750648fe5453e83f7fa57e73732eb699638))

### Boring

- Upgrade latest version - ([ec7f212](https://github.com/0x676e67/wreq/commit/ec7f212a554044c0a407e779f1db7343e6be392a))

### Boringssl

- Add SSL_set_permute_extensions - ([29538bc](https://github.com/0x676e67/wreq/commit/29538bc02e88866e5b8016539bbce1e41b4c6883))

### Bug

- Fix custom content-type overidden by json method ([#1833](https://github.com/0x676e67/wreq/issues/1833)) - ([b13ca4b](https://github.com/0x676e67/wreq/commit/b13ca4b3399b42e7bbdafc374a129ea09bf33b17))
- Fix custom content-type overidden by json method - ([2364364](https://github.com/0x676e67/wreq/commit/23643640ac72e26061314b15c1f6372df4117413))

### Build

- *(deps)* Bump actions/checkout from 3 to 4 ([#35](https://github.com/0x676e67/wreq/issues/35)) - ([07e700d](https://github.com/0x676e67/wreq/commit/07e700d41482eeb7b3e571608439241b43f96bec))
- *(deps)* Bump softprops/action-gh-release from 1 to 2 ([#36](https://github.com/0x676e67/wreq/issues/36)) - ([ff76de9](https://github.com/0x676e67/wreq/commit/ff76de993a07df45b4b8be690ce725fc2e344e89))
- Fix `android`/`fuchsia`/`linux` --no-default-features build ([#110](https://github.com/0x676e67/wreq/issues/110)) - ([40e2b8a](https://github.com/0x676e67/wreq/commit/40e2b8a10748b3b32ea9076c4ca69d14d9596324))
- Fix `--no-default-features` build - ([0d0fef0](https://github.com/0x676e67/wreq/commit/0d0fef05250bdfc915671e9cf86cd229621964be))

### Cargo

- Update to rustls 0.16 - ([3033f11](https://github.com/0x676e67/wreq/commit/3033f11639c2ef0eab86286083b40586079d2662))

### Client

- Add convenience method for DELETE - ([a3983f3](https://github.com/0x676e67/wreq/commit/a3983f3122b2d1495ea36bb5a8fd019a7605ae56))

### Dep

- Upgrade trust-dns-resolver from v0.22 to v0.23 ([#1965](https://github.com/0x676e67/wreq/issues/1965)) - ([0292486](https://github.com/0x676e67/wreq/commit/0292486abab25914c046b71ab6d6da24206614d3))

### Dependencies

- Upgrade base64 to latest version ([#692](https://github.com/0x676e67/wreq/issues/692)) - ([3090a68](https://github.com/0x676e67/wreq/commit/3090a68d5383c572deba077d37d44e1c0424ac11))

### Deps

- *(async-tungstenite)* Downgrade `async-tungstenite` to `0.27.0` ([#161](https://github.com/0x676e67/wreq/issues/161)) - ([f26f8c4](https://github.com/0x676e67/wreq/commit/f26f8c4eccde38c91cb0ee9e55825b26429680a4))
- *(async-tungstenite)* 0.28.0 ([#24](https://github.com/0x676e67/wreq/issues/24)) - ([a924df3](https://github.com/0x676e67/wreq/commit/a924df32110b68ec020e04d20a21f3c032bd087a))
- *(base64)* Bump version to v0.22.x ([#46](https://github.com/0x676e67/wreq/issues/46)) - ([65e5b6d](https://github.com/0x676e67/wreq/commit/65e5b6d775c6cf252a96b06febd82317067057e1))
- *(boring)* V4.x ([#76](https://github.com/0x676e67/wreq/issues/76)) - ([8eb0bf4](https://github.com/0x676e67/wreq/commit/8eb0bf45f9a7333f79d882dca935cbbc3c52e8dc))
- *(boring-sys)* Bump version to v2.0.6 - ([1f4fcc6](https://github.com/0x676e67/wreq/commit/1f4fcc6dd7fe4a35616f7c7f6a9480c1a9411a9f))
- *(boring-sys)* Bump version to v2.0.5 - ([e62c99d](https://github.com/0x676e67/wreq/commit/e62c99df8b33174d7b2616406786b341cc7e8add))
- *(boring-sys)* Bump version to v2.0.4 - ([fa9b28c](https://github.com/0x676e67/wreq/commit/fa9b28c1679c02f0cfcffadb7ace9bdb753a623f))
- *(boring-sys)* Bump version to v2.0.3 - ([1a79070](https://github.com/0x676e67/wreq/commit/1a7907054e33cda15bd89cccf49aa06938525f98))
- *(boring/hyper/h2)* Migration patch crate name ([#109](https://github.com/0x676e67/wreq/issues/109)) - ([676d7b3](https://github.com/0x676e67/wreq/commit/676d7b3038cc12499b5dac4befaf5c1448ca6684))
- *(brotli)* 7.0.0 ([#22](https://github.com/0x676e67/wreq/issues/22)) - ([94e2fdd](https://github.com/0x676e67/wreq/commit/94e2fdd605f969a185bc104d62e8e3e7b6f44b78))
- *(chore)* Update to the latest rustls ([#969](https://github.com/0x676e67/wreq/issues/969)) - ([1a2c102](https://github.com/0x676e67/wreq/commit/1a2c10256a924ff8753f683c4200b8b4d05a2cdd))
- *(cookie_store)* Bump version to v0.21.x ([#47](https://github.com/0x676e67/wreq/issues/47)) - ([fbf0bdc](https://github.com/0x676e67/wreq/commit/fbf0bdcee4b9a58d565b1083fb7c61fc29ef64c7))
- *(h2)* Use h2 dependencies export by hyper ([#63](https://github.com/0x676e67/wreq/issues/63)) - ([6effc9d](https://github.com/0x676e67/wreq/commit/6effc9d2445fdeefb63d271441b65b163a6f4ee1))
- *(hyper)* Bump version to v0.14.60 ([#74](https://github.com/0x676e67/wreq/issues/74)) - ([6842220](https://github.com/0x676e67/wreq/commit/6842220dc1bf28eeee2834b3952c48a8a2bbc1d8))
- *(hyper)* Bump version to v0.14.50 ([#45](https://github.com/0x676e67/wreq/issues/45)) - ([c0cbf29](https://github.com/0x676e67/wreq/commit/c0cbf294ec1c86d63b13b8592b3ef32e121dc1e6))
- *(hyper)* Bump version to v0.14.33 - ([b7fa5f3](https://github.com/0x676e67/wreq/commit/b7fa5f344b0b8b9957b197df7ad79309e3acc593))
- *(hyper)* Bump version to v0.14.28 - ([bdcbe40](https://github.com/0x676e67/wreq/commit/bdcbe40a74357630cf96398af1994d950acb2bc6))
- *(hyper_imp)* Bump version to v0.14.30 - ([4ba5b00](https://github.com/0x676e67/wreq/commit/4ba5b0059956761b6774f55e181a05b806425b26))
- *(ipnet)* 2.10.0 ([#15](https://github.com/0x676e67/wreq/issues/15)) - ([f708a86](https://github.com/0x676e67/wreq/commit/f708a86a4ece4598a1788750a5c6a3a3fa6ab1e5))
- *(ipnet)* V2.9.0 ([#56](https://github.com/0x676e67/wreq/issues/56)) - ([b14d428](https://github.com/0x676e67/wreq/commit/b14d4284028b0ee551716d2000a6a305c3d59a95))
- *(mime)* V0.3.17 ([#57](https://github.com/0x676e67/wreq/issues/57)) - ([1f76f27](https://github.com/0x676e67/wreq/commit/1f76f2788d8779a7e29baca4acf4b3a124b1b25d))
- *(percent-encoding)* V2.3 ([#75](https://github.com/0x676e67/wreq/issues/75)) - ([31ce45c](https://github.com/0x676e67/wreq/commit/31ce45cfb7691ff0e0684a92eef78dad6feda652))
- *(system-configuration)* V0.6.0 - ([8f68af5](https://github.com/0x676e67/wreq/commit/8f68af567683dc449df4b014bc6d7771f3065727))
- *(tokio-socks)* 0.5.2 ([#23](https://github.com/0x676e67/wreq/issues/23)) - ([d05a3f5](https://github.com/0x676e67/wreq/commit/d05a3f552b2ded4eeaa7f65d8b96f8ec96e570c7))
- *(tungstenite)* Backport dependencies - ([1c9da5b](https://github.com/0x676e67/wreq/commit/1c9da5be63e837284ba49870c160a9e8dcccad59))
- *(url)* V2.5 ([#58](https://github.com/0x676e67/wreq/issues/58)) - ([5d71c95](https://github.com/0x676e67/wreq/commit/5d71c95816ef018fd113280e6626dbd408d0d2d2))
- *(windows-registry)* 0.3.0 ([#25](https://github.com/0x676e67/wreq/issues/25)) - ([cb9cf99](https://github.com/0x676e67/wreq/commit/cb9cf99ed1cc2d7904be6455e178cb6ef8f618ef))
- *(winreg)* V0.52.0 - ([74144c2](https://github.com/0x676e67/wreq/commit/74144c25e220b85b51e4f635a4a25fd7c086fc2f))
- Remove unnecessary libc dependencies ([#53](https://github.com/0x676e67/wreq/issues/53)) - ([6a24c13](https://github.com/0x676e67/wreq/commit/6a24c13ab7ee0d1e448654993daa9ddb36e4c87a))
- Update winrege 0.10 -> 0.50 ([#1869](https://github.com/0x676e67/wreq/issues/1869)) - ([e02df1f](https://github.com/0x676e67/wreq/commit/e02df1f448d845fe01e6ea82c76ec89a59e5d568))
- Update rustls v0.20.1 -> v0.21.0 ([#1791](https://github.com/0x676e67/wreq/issues/1791)) - ([a0b5ea5](https://github.com/0x676e67/wreq/commit/a0b5ea5d7179778ce3e02117863b23b452b84d48))
- Update async-compression v0.3.13 => v0.4.0 ([#1828](https://github.com/0x676e67/wreq/issues/1828)) - ([7e7b116](https://github.com/0x676e67/wreq/commit/7e7b116a134cc0d6d646ab316dd83976369d5298))

### Dpes

- *(typed-builder)* V0.20.0 ([#16](https://github.com/0x676e67/wreq/issues/16)) - ([ea70d90](https://github.com/0x676e67/wreq/commit/ea70d902c68bf785c45c255c61ed48276f005e14))

### Example

- Update usage doc for blocking example ([#1112](https://github.com/0x676e67/wreq/issues/1112)) - ([1f425a0](https://github.com/0x676e67/wreq/commit/1f425a0244bcd7b4565dceb9076450d951f2ec03))

### Fmt

- Wasm body ([#1359](https://github.com/0x676e67/wreq/issues/1359)) - ([bd4e0c6](https://github.com/0x676e67/wreq/commit/bd4e0c663c243b584dca114c1d376f67b1967f64))

### Http3

- Upgrade dependencies ([#2028](https://github.com/0x676e67/wreq/issues/2028)) - ([52190df](https://github.com/0x676e67/wreq/commit/52190df64fb56edbfb9cb7c054662b1cfedad476))
- Enable `runtime-tokio` for `quinn` ([#1846](https://github.com/0x676e67/wreq/issues/1846)) - ([06c8e5b](https://github.com/0x676e67/wreq/commit/06c8e5b0b008afee8114fb979b85cd8b73415391))
- Don't force `webpki` when experiemental `http3` is enabled ([#1845](https://github.com/0x676e67/wreq/issues/1845)) - ([c9f0c28](https://github.com/0x676e67/wreq/commit/c9f0c28e4c6e2b9d09544df832c41deef3847505))

### Impersonate

- Add `chrome_126` - ([808e23a](https://github.com/0x676e67/wreq/commit/808e23a935439ac8a0d41c9aa6ab1661070761d7))
- Chrome_123, chrome_125 - add `zstd` to Accept-Encoding header - ([f17d07e](https://github.com/0x676e67/wreq/commit/f17d07e1d0c3aa8036dcbd785508a43f25bf21cd))

### Msrv

- Bump to 1.63 ([#1947](https://github.com/0x676e67/wreq/issues/1947)) - ([4aa8516](https://github.com/0x676e67/wreq/commit/4aa8516770eb96c66e753621660275e65e269213))

### Multipart

- Force a CRLF at the end of request - ([a525209](https://github.com/0x676e67/wreq/commit/a52520941f518ade756a73797e875722d1ba344b))

### Native-tls

- Add Identiy::from_pkcs8_pem ([#1655](https://github.com/0x676e67/wreq/issues/1655)) - ([231b18f](https://github.com/0x676e67/wreq/commit/231b18f83572836c674404b33cb1ca8b35ca3e36))

### Proxy

- Add support for proxy authentication with user-specified header values ([#2053](https://github.com/0x676e67/wreq/issues/2053)) - ([c09c5e6](https://github.com/0x676e67/wreq/commit/c09c5e6bbcf79b3984cd4c2cf2f2f5d9e2a4a6af))
- Refactor a collapsible_match ([#1214](https://github.com/0x676e67/wreq/issues/1214)) - ([544282a](https://github.com/0x676e67/wreq/commit/544282a0b49d6ba2ac78b844c23415c0bf62a304))

### Refractor

- *(tls/settings)* Generate configuration using builder mode ([#121](https://github.com/0x676e67/wreq/issues/121)) - ([a370f18](https://github.com/0x676e67/wreq/commit/a370f18774eced8c2c62ed2d4d9f9db72639eaba))

### Remove

- *(client)* Remove blocking client support ([#123](https://github.com/0x676e67/wreq/issues/123)) ([#124](https://github.com/0x676e67/wreq/issues/124)) ([#125](https://github.com/0x676e67/wreq/issues/125)) - ([5091f9a](https://github.com/0x676e67/wreq/commit/5091f9ae4f8394ec5e5a6dbf138c598c8d5b2295))

### Request

- Test adding duplicate headers to the request ([#519](https://github.com/0x676e67/wreq/issues/519)) - ([1bdc3fa](https://github.com/0x676e67/wreq/commit/1bdc3fa3c8dd3c4038efc566b7ccdbc86e38cfa3))

### Tmp

- Use upstream git repo for hyper-native-tls - ([d12d604](https://github.com/0x676e67/wreq/commit/d12d604e380b8f1ee8cc9e22fd218ce3d283aa4e))

### Wasm

- Add method `user_agent` to `ClientBuilder`. ([#2018](https://github.com/0x676e67/wreq/issues/2018)) - ([a9b960f](https://github.com/0x676e67/wreq/commit/a9b960fc24455c3c5c7e35b54dbcc6512cc86d2b))
- Blob url support ([#1797](https://github.com/0x676e67/wreq/issues/1797)) - ([2fa69ad](https://github.com/0x676e67/wreq/commit/2fa69ad384ceb9a0f718ceb45b092341a5285dd4))
- Fix premature abort for streaming bodies ([#1782](https://github.com/0x676e67/wreq/issues/1782)) - ([df2b3ba](https://github.com/0x676e67/wreq/commit/df2b3baadc1eade54b1c22415792b778442673a4))
- Fix standalone/multipart body conversion to JsValue ([#1364](https://github.com/0x676e67/wreq/issues/1364)) - ([0ef1a2e](https://github.com/0x676e67/wreq/commit/0ef1a2ea78eaa5aeb280fd1dbbbabb83abc45c30))
- Don't send request body as plain uint8 array ([#1358](https://github.com/0x676e67/wreq/issues/1358)) - ([bb3d102](https://github.com/0x676e67/wreq/commit/bb3d102108493da9adf9081b4d0badbff4a2bd91))
- Add missing `as_bytes` method to `Body` implementation ([#1270](https://github.com/0x676e67/wreq/issues/1270)) - ([d40276c](https://github.com/0x676e67/wreq/commit/d40276c0f081c2cc1ebc8b63ad6075daf0f6dff0))
- Avoid dependency on serde-serialize feature ([#1337](https://github.com/0x676e67/wreq/issues/1337)) - ([cfa301c](https://github.com/0x676e67/wreq/commit/cfa301c7fa0f83330f57b312f4e762a3e47ff2cb))
- Omit request body if it's empty ([#1012](https://github.com/0x676e67/wreq/issues/1012)) - ([d42385e](https://github.com/0x676e67/wreq/commit/d42385e7f2cc364efa5e16a7154e7e0cebdd1b57))
- Impl TryFrom<HttpRequest<T>> for Request ([#997](https://github.com/0x676e67/wreq/issues/997)) - ([dd8441f](https://github.com/0x676e67/wreq/commit/dd8441fd23dae6ffb79b4cea2862e5bca0c59743))
- Add error_for_status to wasm response ([#779](https://github.com/0x676e67/wreq/issues/779)) - ([1478313](https://github.com/0x676e67/wreq/commit/147831375613a5e508487b2d85a99104ae1505af))
- Add url function to wasm response ([#777](https://github.com/0x676e67/wreq/issues/777)) - ([fd88e0c](https://github.com/0x676e67/wreq/commit/fd88e0c648e6632f3f92ed119b1a93aefd66ed64))
- Add request body in the form of Bytes ([#696](https://github.com/0x676e67/wreq/issues/696)) - ([f6f81f9](https://github.com/0x676e67/wreq/commit/f6f81f9cc1ab84a007fe4203822de08d72c07f57))
- Add bytes method to wasm response ([#694](https://github.com/0x676e67/wreq/issues/694)) - ([b24b0be](https://github.com/0x676e67/wreq/commit/b24b0be461ed39a96335e40561d07a35f2c3eb36))
- Translate over response headers ([#689](https://github.com/0x676e67/wreq/issues/689)) - ([dd65fc7](https://github.com/0x676e67/wreq/commit/dd65fc7c3ad037e6674e8bac8c46f4bdeca6c4ca))

## New Contributors ❤️

* @0x676e67 made their first contribution
* @dairoot made their first contribution in [#68](https://github.com/0x676e67/wreq/pull/68)
* @AliaSabur made their first contribution in [#31](https://github.com/0x676e67/wreq/pull/31)
* @deedy5 made their first contribution
* @dependabot[bot] made their first contribution
* @seanmonstar made their first contribution
* @jan-auer made their first contribution
* @lorepozo made their first contribution
* @abls made their first contribution
* @Noah-Kennedy made their first contribution
* @tshepang made their first contribution
* @bitfl0wer made their first contribution
* @FirelightFlagboy made their first contribution
* @tnull made their first contribution
* @conradludgate made their first contribution
* @droe made their first contribution
* @NobodyXu made their first contribution
* @jefflloyd made their first contribution
* @brian030128 made their first contribution
* @eric-seppanen made their first contribution
* @T-Sujeeban made their first contribution
* @cipherbrain made their first contribution
* @bouzuya made their first contribution
* @VivekPanyam made their first contribution
* @paolobarbolini made their first contribution
* @ollyswanson made their first contribution
* @daxpedda made their first contribution
* @attila-lin made their first contribution
* @smndtrl made their first contribution
* @nyurik made their first contribution
* @complexspaces made their first contribution
* @cpu made their first contribution
* @hulin32 made their first contribution
* @skyf0l made their first contribution
* @nickelc made their first contribution
* @jneem made their first contribution
* @kckeiks made their first contribution
* @lucab made their first contribution
* @j7nw4r made their first contribution
* @TurnOfACard made their first contribution
* @anhcuky made their first contribution
* @lstrojny made their first contribution
* @dmeijboom made their first contribution
* @4JX made their first contribution
* @link2xt made their first contribution
* @beeb made their first contribution
* @Khoulaiz made their first contribution
* @BlackDex made their first contribution
* @Austaras made their first contribution
* @kianmeng made their first contribution
* @Alvenix made their first contribution
* @irrelevelephant made their first contribution
* @mirecl made their first contribution
* @lpraneis made their first contribution
* @luqmana made their first contribution
* @vidhanio made their first contribution
* @futursolo made their first contribution
* @neoeinstein made their first contribution
* @ctron made their first contribution
* @ made their first contribution
* @cuishuang made their first contribution
* @Mathspy made their first contribution
* @eyalsatori made their first contribution
* @flavio made their first contribution
* @MisileLab made their first contribution
* @jqnatividad made their first contribution
* @ducaale made their first contribution
* @biluohc made their first contribution
* @nihaals made their first contribution
* @ViddeM made their first contribution
* @edmorley made their first contribution
* @sugar700 made their first contribution
* @kraktus made their first contribution
* @TjeuKayim made their first contribution
* @ecclarke42 made their first contribution
* @nikstur made their first contribution
* @vsaase made their first contribution
* @BiagioFesta made their first contribution
* @niuhuan made their first contribution
* @nwolber made their first contribution
* @fredr made their first contribution
* @jeschkies made their first contribution
* @pfernie made their first contribution
* @crapStone made their first contribution
* @6543 made their first contribution
* @striezel made their first contribution
* @victoryaskevich made their first contribution
* @abatkin made their first contribution
* @skystar-p made their first contribution
* @silvioprog made their first contribution
* @jmgilman made their first contribution
* @Dr-Emann made their first contribution
* @jplatte made their first contribution
* @blyxxyz made their first contribution
* @dlesl made their first contribution
* @Saruniks made their first contribution
* @campbellC made their first contribution
* @kjvalencik made their first contribution
* @mlodato517 made their first contribution
* @bensadiku made their first contribution
* @marcoieni made their first contribution
* @ctjhoa made their first contribution
* @jonhoo made their first contribution
* @Septias made their first contribution
* @kotborealis made their first contribution
* @bishtpawan made their first contribution
* @Gottox made their first contribution
* @CfirTsabari made their first contribution
* @ibraheemdev made their first contribution
* @svenstaro made their first contribution
* @kornelski made their first contribution
* @meldron made their first contribution
* @webern made their first contribution
* @rakshith-ravi made their first contribution
* @Marwes made their first contribution
* @glyphpoch made their first contribution
* @markhildreth made their first contribution
* @wchargin made their first contribution
* @amousset made their first contribution
* @baoyachi made their first contribution
* @messense made their first contribution
* @ranile made their first contribution
* @varoonp123 made their first contribution
* @Martichou made their first contribution
* @frewsxcv made their first contribution
* @zicklag made their first contribution
* @thomastaylor312 made their first contribution
* @fiag made their first contribution
* @est31 made their first contribution
* @stevelr made their first contribution
* @taiki-e made their first contribution
* @federico-terzi made their first contribution
* @XyLyXyRR made their first contribution
* @pluehne made their first contribution
* @sdroege made their first contribution
* @Snarpix made their first contribution
* @fabricedesre made their first contribution
* @shuoli84 made their first contribution
* @JOE1994 made their first contribution
* @Jasonoro made their first contribution
* @zacps made their first contribution
* @fuyumatsuri made their first contribution
* @707090 made their first contribution
* @snejugal made their first contribution
* @TaKO8Ki made their first contribution
* @vorner made their first contribution
* @alex made their first contribution
* @LionsAd made their first contribution
* @davidpdrsn made their first contribution
* @alianse777 made their first contribution
* @tasn made their first contribution
* @jsha made their first contribution
* @bryanburgers made their first contribution
* @dcuenot made their first contribution
* @slonopotamus made their first contribution
* @hecrj made their first contribution
* @x1957 made their first contribution
* @cuviper made their first contribution
* @x448 made their first contribution
* @Luro02 made their first contribution
* @eugene-babichenko made their first contribution
* @kentfredric made their first contribution
* @Diggsey made their first contribution
* @nicklan made their first contribution
* @tesuji made their first contribution
* @metajack made their first contribution
* @manyuanrong made their first contribution
* @WindSoilder made their first contribution
* @r-arias made their first contribution
* @rhysd made their first contribution
* @kodieg made their first contribution
* @rodoufu made their first contribution
* @Lucretiel made their first contribution
* @mbrobbel made their first contribution
* @tobdub made their first contribution
* @jgall made their first contribution
* @cbourjau made their first contribution
* @gathuku made their first contribution
* @vorot93 made their first contribution
* @khuey made their first contribution
* @SOF3 made their first contribution
* @benesch made their first contribution
* @danieleades made their first contribution
* @basdebue made their first contribution
* @vigneshsarma made their first contribution
* @travier-anssi made their first contribution
* @ancwrd1 made their first contribution
* @nirasan made their first contribution
* @prfss made their first contribution
* @repi made their first contribution
* @mathstuf made their first contribution
* @GuillaumeGomez made their first contribution
* @bluejekyll made their first contribution
* @Liby99 made their first contribution
* @quininer made their first contribution
* @aaneto made their first contribution
* @chenl made their first contribution
* @jeromegn made their first contribution
* @theduke made their first contribution
* @arnodb made their first contribution
* @CJP10 made their first contribution
* @fbenkstein made their first contribution
* @ismith made their first contribution
* @antoinecarton made their first contribution
* @mavax made their first contribution
* @gbonnema made their first contribution
* @emschwartz made their first contribution
* @puffybsd made their first contribution
* @sudo-ben made their first contribution
* @shouya made their first contribution
* @martin-t made their first contribution
* @kevinwilson541 made their first contribution
* @polyfloyd made their first contribution
* @Eijebong made their first contribution
* @illicitonion made their first contribution
* @dbrgn made their first contribution
* @davidwilemski made their first contribution
* @KNnut made their first contribution
* @MarkDDR made their first contribution
* @yageek made their first contribution
* @JoshMcguigan made their first contribution
* @frol made their first contribution
* @spk made their first contribution
* @rukai made their first contribution
* @jcaesar made their first contribution
* @andy128k made their first contribution
* @bhansconnect made their first contribution
* @scottschroeder made their first contribution
* @DoumanAsh made their first contribution
* @kennytm made their first contribution
* @cakey made their first contribution
* @mattias-p made their first contribution
* @Siilwyn made their first contribution
* @Sh4pe made their first contribution
* @Dylan-DPC made their first contribution
* @csirkeee made their first contribution
* @is made their first contribution
* @oli-obk made their first contribution
* @sbstp made their first contribution
* @shepmaster made their first contribution
* @tafia made their first contribution
* @knight42 made their first contribution
* @Henning-K made their first contribution
* @osa1 made their first contribution
* @marmistrz made their first contribution
* @kamalmarhubi made their first contribution
* @chrisvittal made their first contribution
* @e00E made their first contribution
* @KodrAus made their first contribution
* @Roguelazer made their first contribution
* @bhendo made their first contribution
* @tomprince made their first contribution
* @AndyGauge made their first contribution
* @jaemk made their first contribution
* @budziq made their first contribution
* @steverob made their first contribution
* @rap2hpoutre made their first contribution
* @TedDriggs made their first contribution
* @imp made their first contribution
* @gsquire made their first contribution
* @rylio made their first contribution
* @emk made their first contribution
* @Keruspe made their first contribution
* @quodlibetor made their first contribution
* @sfackler made their first contribution
* @sebasgarcep made their first contribution
* @saghm made their first contribution
* @nelsonjchen made their first contribution
* @badboy made their first contribution
* @brycefisher made their first contribution
* @aidanhs made their first contribution
* @Michael-F-Bryan made their first contribution

<!-- generated by git-cliff -->
