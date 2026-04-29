# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [6.0.0-rc.29](https://github.com/0x676e67/wreq/compare/v6.0.0-rc.28...v6.0.0-rc.29) - 2026-04-29

### Added

- *(request)* expose Extensions for tower middleware compatibility ([#1119](https://github.com/0x676e67/wreq/pull/1119))
- *(request)* introduce `Group` for explicit request differentiation ([#1117](https://github.com/0x676e67/wreq/pull/1117))
- *(multipart)* use `WebKit` style boundary generation by default ([#1118](https://github.com/0x676e67/wreq/pull/1118))
- *(ws)* expose underlying stream via `WebSocket::into_inner` ([#1114](https://github.com/0x676e67/wreq/pull/1114))
- *(response)* allow forbidding connection recycling via `Response::forbid_recycle` ([#1110](https://github.com/0x676e67/wreq/pull/1110))
- *(cookie)* RFC 9113 compliant cookie handling ([#1106](https://github.com/0x676e67/wreq/pull/1106))
- *(tls)* allow pluggable TLS session cache ([#1101](https://github.com/0x676e67/wreq/pull/1101))
- *(multipart)* add Form::set_boundary for custom boundaries ([#1094](https://github.com/0x676e67/wreq/pull/1094))
- *(cookie)* fill missing domain/path in `get_all` from stored scope ([#1082](https://github.com/0x676e67/wreq/pull/1082))

### Fixed

- *(http1)* fix possibly short reads when decoding a large body ([#1157](https://github.com/0x676e67/wreq/pull/1157))
- *(http1)* fix rare missed write wakeup on connections ([#1153](https://github.com/0x676e67/wreq/pull/1153))
- *(http1)* send error when dispatcher is dropped mid-body ([#1155](https://github.com/0x676e67/wreq/pull/1155))
- *(http2)* reading trailers shouldn't propagate NO_ERROR from early response ([#1156](https://github.com/0x676e67/wreq/pull/1156))
- *(tcp)* ensure socket bind options is not accidentally cleared ([#1131](https://github.com/0x676e67/wreq/pull/1131))
- *(http2)* cancel pipe_task and send `RST_STREAM` on response future drop ([#1116](https://github.com/0x676e67/wreq/pull/1116))
- *(http1)* allow keep-alive for chunked requests with trailers ([#1112](https://github.com/0x676e67/wreq/pull/1112))
- *(tcp)* restore the missing TCP nodelay setting ([#1102](https://github.com/0x676e67/wreq/pull/1102))
- *(bench)* fix CPU sysinfo reading in benchmark ([#1080](https://github.com/0x676e67/wreq/pull/1080))
- fix build
- disable Nagle's algorithm to resolve HTTP/2 performance dip ([#1074](https://github.com/0x676e67/wreq/pull/1074))
- *(http2)* prevent panic when calling to_str on non-UTF8 headers ([#1070](https://github.com/0x676e67/wreq/pull/1070))
- fix build
- *(rt)* support fake time in legacy client and TokioTimer ([#1064](https://github.com/0x676e67/wreq/pull/1064))

### Other

- release-plz.yml
- *(core)* migrate core module to `wreq-proto` ([#1160](https://github.com/0x676e67/wreq/pull/1160))
- *(timer)* implement reset for `Sleep`, drop unsafe downcast ([#1159](https://github.com/0x676e67/wreq/pull/1159))
- *(deps)* update `lru` dependency version to 0.18.0 ([#1158](https://github.com/0x676e67/wreq/pull/1158))
- optimal network chunk sizes with usage scenarios
- revert
- *(tcp)* reduce dependency on `futures-util` ([#1154](https://github.com/0x676e67/wreq/pull/1154))
- *(deps)* update dependencies to latest versions
- fmt
- *(deps)* update http dependency version to 1.4.0 ([#1152](https://github.com/0x676e67/wreq/pull/1152))
- #[inline]
- *(deps)* update hickory-resolver requirement from 0.25 to 0.26 ([#1149](https://github.com/0x676e67/wreq/pull/1149))
- *(deps)* reduce dependency on `futures-channel` ([#1127](https://github.com/0x676e67/wreq/pull/1127))
- *(tls)* expose certificate compression APIs ([#1151](https://github.com/0x676e67/wreq/pull/1151))
- move
- fmt
- reduce benchmark noise interference
- Update Cargo.toml
- *(style)* fix clippy warnings for Rust 1.95.0 ([#1147](https://github.com/0x676e67/wreq/pull/1147))
- *(deps)* replace `serde_html_form` with `serde_urlencoded` ([#1146](https://github.com/0x676e67/wreq/pull/1146))
- *(deps)* update lru dependency version to 0.17.0 ([#1145](https://github.com/0x676e67/wreq/pull/1145))
- Update README.md
- *(http1/encode)* Add `inline` annotations to Encoder methods ([#1144](https://github.com/0x676e67/wreq/pull/1144))
- Change static to const for ALPHA_NUMERIC_ENCODING_MAP
- Update ci.yml
- *(cookie)* add subdomain cookie scoping tests for `Jar` ([#1143](https://github.com/0x676e67/wreq/pull/1143))
- *(tunnel)* standardize zero-copy parsing ([#1142](https://github.com/0x676e67/wreq/pull/1142))
- *(client)* Add 1 KB body case for benchmark
- *(deps)* bump softprops/action-gh-release from 2 to 3 ([#1140](https://github.com/0x676e67/wreq/pull/1140))
- *(http1/io)* leverage `tokio_util::io` to reduce vectorized write overhead ([#1141](https://github.com/0x676e67/wreq/pull/1141))
- update
- *(ws)* replace `force_http2` with `version` for HTTP version selection ([#1139](https://github.com/0x676e67/wreq/pull/1139))
- *(core)* fmt import ([#1138](https://github.com/0x676e67/wreq/pull/1138))
- *(sync)* fmt export ([#1136](https://github.com/0x676e67/wreq/pull/1136))
- *(deps)* optional `parking_lot` support ([#1126](https://github.com/0x676e67/wreq/pull/1126))
- *(layer)* add documentation comment
- *(deps)* update `http2` dependency version to 0.5.16 ([#1134](https://github.com/0x676e67/wreq/pull/1134))
- update examples
- *(group)* fmt code ([#1133](https://github.com/0x676e67/wreq/pull/1133))
- *(lib)* format exported http1 and http2 modules ([#1129](https://github.com/0x676e67/wreq/pull/1129))
- *(incoming)* fmt code
- *(bench/client)* fmt code
- Revert "bench: fmt code"
- *(deps)* remove implicit feature ([#1123](https://github.com/0x676e67/wreq/pull/1123))
- *(http2)* fmt code ([#1124](https://github.com/0x676e67/wreq/pull/1124))
- fmt code
- *(ws)* rewrite `sec-websocket-protocol` handling ([#1121](https://github.com/0x676e67/wreq/pull/1121))
- *(deps)* update `http2` dependency version to 0.5.15 ([#1122](https://github.com/0x676e67/wreq/pull/1122))
- *(ws)* "feat(request): introduce `Group` for explicit request differentiation" ([#1120](https://github.com/0x676e67/wreq/pull/1120))
- update SOCKS proxy support description in Cargo.toml
- Add Discord badge to README
- *(deps)* update `tokio-tungstenite` to version 0.29.0 ([#1113](https://github.com/0x676e67/wreq/pull/1113))
- *(response)* replace chunk usage with BodyExt::frame ([#1111](https://github.com/0x676e67/wreq/pull/1111))
- *(http2)* remove unstable APIs ([#1109](https://github.com/0x676e67/wreq/pull/1109))
- *(conn)* Fix comment for proxy handling in `Conn`
- Update RELEASE
- *(conn)* optimize `ConnectionId` cloning ([#1108](https://github.com/0x676e67/wreq/pull/1108))
- *(tcp)* prune redundant local address handling ([#1107](https://github.com/0x676e67/wreq/pull/1107))
- fmt code
- *(tls)* decouple TLS backend logic into sub-modules ([#1105](https://github.com/0x676e67/wreq/pull/1105))
- *(tls)* expose certificate compression APIs ([#1085](https://github.com/0x676e67/wreq/pull/1085))
- *(pool)* redesign emulation and pool ID strategy ([#1103](https://github.com/0x676e67/wreq/pull/1103))
- fmt import
- Fix cfg attribute formatting for set_tcp_user_timeout
- *(conn)* modular connector component ([#1100](https://github.com/0x676e67/wreq/pull/1100))
- update comments for compression support dependencies
- *(multipart)* streamline legacy Form implementation
- *(multipart)* Improve memory layout of `multipart::Form` ([#1095](https://github.com/0x676e67/wreq/pull/1095))
- *(buf)* make `BufList::remaining` O(1) by caching length ([#1091](https://github.com/0x676e67/wreq/pull/1091))
- *(deps)* bump btls from 0.5.3 to 0.5.4 ([#1090](https://github.com/0x676e67/wreq/pull/1090))
- Update README.md
- *(http1)* eliminate `ParserConfig` clones on the HTTP/1.1 request hot path ([#1088](https://github.com/0x676e67/wreq/pull/1088))
- *(bench)* update mod benchmark comment
- *(bench)* fmt code
- *(bench)* format expected error annotations
- Update README.md
- *(deps)* replace `ahash` with `foldhash` in `lru` cache ([#1084](https://github.com/0x676e67/wreq/pull/1084))
- *(deps)* migrate from `boring2` to `btls` ([#1083](https://github.com/0x676e67/wreq/pull/1083))
- *(request)* fmt imports for request.rs file
- Update README.md
- add missing `TokioTimer` to http1 server builder ([#1081](https://github.com/0x676e67/wreq/pull/1081))
- *(client)* fmt code
- *(deps)* replace `raw-cpuid` with `sysinfo` implementation ([#1077](https://github.com/0x676e67/wreq/pull/1077))
- *(hash)* simplify documentation for `HashMemo` creation ([#1076](https://github.com/0x676e67/wreq/pull/1076))
- format benchmark group labels
- improve benchmark test coverage ([#1075](https://github.com/0x676e67/wreq/pull/1075))
- fmt
- refactor `Cargo.toml` for clarity and organization
- remove deprecated doc_cfg feature conditionally
- simplify grouped benchmarks
- *(bench)* optimize benchmark server ([#1073](https://github.com/0x676e67/wreq/pull/1073))
- *(deps)* bump nttld/setup-ndk from 1.5.0 to 1.6.0 ([#1072](https://github.com/0x676e67/wreq/pull/1072))
- lint core ([#1071](https://github.com/0x676e67/wreq/pull/1071))
- include TLS-encrypted scenarios for HTTP/1 and HTTP/2
- Add benchmarks for full and streaming bodies ([#1069](https://github.com/0x676e67/wreq/pull/1069))
- clarify symbol conflict with OpenSSL ([#1068](https://github.com/0x676e67/wreq/pull/1068))
- Update hash.rs
- *(deps)* replace `schnellru` with `lru`  implementation ([#1066](https://github.com/0x676e67/wreq/pull/1066))
- Update git-cliff changelog
- Update CHANGELOG.md
- Update cliff.toml
- *(core)* clear code
- fix clippy
- add benchmarks for HTTP/1.1 and HTTP/2 ([#1065](https://github.com/0x676e67/wreq/pull/1065))
- *(http2)* backport and apply hyper client's H2 configuration ([#1063](https://github.com/0x676e67/wreq/pull/1063))
- *(response)* hint compiler to inline trivial response-handling functions ([#1062](https://github.com/0x676e67/wreq/pull/1062))
- *(error)* hint compiler to inline trivial error-handling functions ([#1061](https://github.com/0x676e67/wreq/pull/1061))
- *(request)* static init for common content-type header ([#1060](https://github.com/0x676e67/wreq/pull/1060))
