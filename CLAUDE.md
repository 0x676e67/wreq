# wreq HTTP/3 分支工作记录

记录 `demo/brave-galileo-ac7w3r`（HTTP/3 集成分支）的重构上下文：流程、约定、现状、进度和待办。
改动合入后同步更新对应小节；状态只写已核实的事实，设想单独标明。

最后更新：2026-11-12，集成分支 `53dd968a`，进行中的 PR 是 #1393。

## 1. 分支与流程

- 集成分支 `demo/brave-galileo-ac7w3r` 领先 main（`7812c308`）122 个提交。其中前 65 个是
  `refactor/connection-pool-strategies-9-1`，即向 main 的 #1274；HTTP/3 的 57 个提交叠在它上面，还没有向 main 提 PR。
- 每项改动开 `demo/<主题>` 分支，PR 合入集成分支：正文留空，Squash 合并，标题用 `type(scope): ...`。
- CI（`.github/workflows/ci.yml`）只在 pull_request 触发；只改 `*.md`、`docs/**`、`.github/**` 时不触发。
- Rust 2024，MSRV 1.98，格式化用 nightly rustfmt。
- 提交前的本地检查，按影响范围取舍：
  - `cargo +nightly fmt --all -- --check`
  - `cargo clippy --all-targets <features> -- -D warnings`，8 组：`--all-features`、默认、
    `--features hickory-dns`、`--no-default-features --features tokio-rt,webpki-roots`、`--features http3`、
    `--no-default-features --features tokio-rt,webpki-roots,http3`、
    `--no-default-features --features compio-rt,webpki-roots`、
    `--no-default-features --features webpki-roots,http2,http3,socks`
  - 改了 cfg 代码时，对 CI 测试矩阵的每一行跑 `cargo check --lib`
  - `cargo nextest run --workspace --all-features -E 'not binary_id(wreq::emulate)'`（emulate 需要公网）
  - `RUSTDOCFLAGS=-Dwarnings cargo doc --no-deps --document-private-items --all-features`

## 2. 上游依赖

`Cargo.toml` 的 `[patch.crates-io]` 目前 pin 在各 fork 的分支提交上：

| crate | rev | 说明 |
|---|---|---|
| http3、http3-datagram、http3-quic | `5bd394f3` | 0x676e67/http3#170：客户端握手不再等待对端，控制流和 QPACK 流由连接驱动打开 |
| netty | `0e1e53c0` | 分支 `demo/connection-is-idle`：H2/H3 的 `SendRequest::is_idle`，并跟进上面的 http3 |
| quic | `b3d74044` | |
| http2 | `ce505e52` | |
| btls、btls-sys、tokio-btls | `5ec1c113` | |

- netty 这次跟进去掉了之前依赖的 http3#161（RFC 9218 `PriorityUpdate`，未合并）。
- **待办**：上游合并后，netty 和 wreq 统一 re-pin 到各自主分支的提交，再做一次全量验证。

## 3. 约定

**命名**
- `*Config` 是客户端级设置，构建时固定；`*Options` 可按请求覆盖。
- 同类配置统一叫 `Config`，模块外带前缀访问：`tls::Config`、`tcp::Config`、`conn::Config`、`pool::Config`；
  模块内部直接写 `Config`。
- 同一对象沿传递链保持同名：`DynRuntime` 的字段叫 `runtime`，`Connected` 叫 `connected`，netty 句柄叫 `connection`。

**tower 组件**
- 中间件成对出现：`FooLayer` 加 `Foo<S>`，被包住的服务字段叫 `inner`；`layer()` 和转发的 `poll_ready` 标
  `#[inline(always)]`。
- 自定义 future 叫 `ResponseFuture`，用 `pin_project!`；只有握手这类本来就装箱的地方用 `BoxFuture`。
- 连接器、连接池、协议服务的 `Error` 是 `BoxError`。
- 只为真正的横切逻辑引入抽象；不加只实例化一次的泛型参数；有两个以上实现者时才加 trait。

**排版（rustfmt 不管的部分）**
- cfg 门控的导入合并成 `#[cfg(...)] use { ... };` 块，放在同组无条件导入之后。
- 私有 `mod` 写在 `pub(crate)` / `pub(super)` 的 `mod` 之前。
- 相邻的带文档的项之间空一行；`cfg_select!` 的分支和名字已自解释的私有别名不写文档。

**测试**
- 行为由测试固定后再重构；能由编译保证的内容不写运行时测试。
- 回归测试要先在未修复的代码上确认会失败。

## 4. 连接层现状

组装集中在 `Connector::new`（`src/conn.rs`）。#1393 合入后是：

```rust
let stream = ServiceBuilder::new()
    .layer(VerboseLayer::new(config.verbose))
    .layer(TlsLayer::new(config.tls.stream(config_set)?))
    .service(StreamRouter::new(dialer, proxies));
// Connector = Deadline<Either<Builtin { stream, quic }, 用户自定义层的装箱栈>>
```

| 模块 | 内容 |
|---|---|
| `conn.rs` | 对外契约类型（`Conn`、`Transport`、`Unnameable`、`Boxed*`）、`Config`、`Builtin`（按协议选 stream 或 quic）、组装 |
| `conn/layer/` | 中间件：`deadline`（连接超时）、`tls`（目标站 TLS 和连接元数据）、`verbose`（IO 日志）。后两个随 #1393 |
| `conn/stream.rs` | 流路径选路：直连、CONNECT 隧道、正向代理、SOCKS4/5、Unix |
| `conn/quic.rs`、`conn/quic/` | QUIC 路径：`endpoint`（端点、token、拨号）、`masque`、`socks` |
| `conn/dialer.rs`、`dialer/tcp.rs` | 叶子：DNS、地址竞速、本地绑定、TCP/Unix 流、QUIC 用的 UDP 套接字 |
| `conn/{request, config, connected}.rs` | 数据：`ConnectRequest`、`ConfigSet`、连接元数据 |

**已固定的行为**
- 连接超时只有一个：`Deadline` 算出到期时刻，写进请求；拨号（DNS 加 TCP，MASQUE 是到代理的 QUIC）在同一时刻自己失败。
  所以超时发生在解析或拨号代理时报代理错误，发生在代理握手或目标站握手时报普通连接错误（#1391）。
- HTTP/3 握手不等待对端，`connect_timeout` 之外没有第二个建连超时。
- 连接池把仍有请求在跑的 H2/H3 连接排除在空闲过期和 LRU 淘汰之外（依赖 netty 的 `is_idle`）。
- HTTP/3 只接受 `quic://`（MASQUE）和 `socks5`/`socks5h`（UDP）代理，其他代理报配置错误。
- 本地配置错误不算代理失败，也不应先付出一次代理握手。

## 5. 进度

### 已完成（都在集成分支上）

- **结构重构**（基线 `3a59d793` 起）：共享 H3 测试夹具 `a34a980a`；TCP/QUIC 共用 ClientHello 设置 `dea0164a`；
  连接池和分发的 body 类型 `1814a750`；请求检查和版本协调 `eb2dd2fc`、`d598e8fe`；`proto::mux` `46ea5a4e`；
  `MuxEntry` `8e387ef5`；显式的 `Transport` 枚举 `c2fa6508`；单一建连超时 `bac4762d`；`DynRuntime` `cfc24c1b`；
  QUIC 按路径选传输配置并缓存 TLS 上下文 `96e05866`；绑定选项和池键 `942dcec0`；拆分 pool 和 dispatch `1be84b22`；
  消融 `ClientDefaults` 等过渡类型 `431351b2`。
- **修复**：重定向的延迟决策检查 `5699bded`；WebSocket 走池化的 H3 连接（RFC 9220）`e1a4c8ad`；
  握手被拒后停止地址竞速 `e009ef4f`；忙碌的 H2/H3 连接不参与空闲过期 `587a7841`；
  TCP 连接选项用于 QUIC 和 SOCKS-UDP 拨号 `ea18ba84`。
- **连接器重设计**：设置按归属存放、`Connector::new` 一次建成 `b56a7730`；按传输路径分模块 `12e9ace1`；
  元数据只构建一次 `969f3c5e`；建连超时归连接器 `10029bb8`。
- **#1391** 代理拨号超时归类为代理错误 `18d50047`。
- **#1392** 配置类型统一叫 `Config`，`tls/config.rs` 并入 `tls.rs` `53dd968a`。

### 进行中：连接层分层（2026-11-12 定）

目标是让 tower 各层职责单一，组装方式和 `client.rs` 一致。已定的三点：

1. `conn/layer/` 只放中间件（包住一个内层服务、只加一件事、不关心路由），和 `client/layer` 一致；
   终端服务和选路按路径放。
2. 目标站 TLS 和 IO 日志做成 Layer，每种路由做成独立 Service，选路服务只负责选。
   选路本身不做成 Layer 链，因为走哪条路由取决于每个请求匹配到的代理。
3. `ConnectRequest` 拆成"连接池身份"和"单次建连状态"（`route_uri`、`deadline`）。

| 步骤 | 内容 | 状态 |
|---|---|---|
| 1 | 建立 `conn/layer/`；`Tls`、`Verbose` 做成 Layer；`StreamRouter` 只建到目标的字节流 | PR #1393，待合并 |
| 2 | 流路径五种路由拆成独立 Service；HTTPS 代理那一跳的 TLS 从 `tls` 模块挪出 | 未开始 |
| 3 | QUIC 路径对齐：选路服务加各路由 Service | 未开始 |
| 4 | 拆 `ConnectRequest` | 未开始 |

#1393 带来的边缘行为变化：TLS 上下文改在选路之前选定。请求的 TLS 选项编译失败时，经正向代理的 HTTP 目标不再报成
代理错误，SOCKS 路由在连代理之前就失败。这几种情况没有专门的测试。

### 待办

- 上游 re-pin（见第 2 节）。
- `AsyncConn` 和 `rt::Connection` 是否重复定义，能否合并（提出后暂时搁置）。
- 默认 feature 加 `--document-private-items` 时有 7 个文档链接解析失败（`src/sync.rs` 等），全 feature 构建不受影响。
- 已合并 PR 的远端分支可以删除。

### 决定不做

- **不把连接超时按"阶段标记"分类**：#1391 试过在请求上挂标记，由 `Deadline` 到期时读取。能工作，但不是常见的错误标记
  方式，改用共享到期时刻。
- **不原样恢复 main 的内层 TCP 计时器**：内外两个同样时长的计时器靠赛跑决定分类，实测代理是主机名且 DNS 超过几毫秒时
  总是分错。
- **不为个别代理商的 SOCKS5 UDP 中继行为做兼容**：有一家在 socks5h 下对特定域名的 UDP 完全没有回包，已确认是中继侧
  问题。wreq 不加"用回包地址固定目标 IP"的逻辑，也不做 socks5h 到 socks5 的自动回退；调用方可以显式用 socks5。
- **不提前校验 HTTP/3 选项**（`a580536b`）：和 HTTP/2 一致，非法选项在握手时报错。

## 6. 性能基线

规则：
- 读写路径：建好的流不得新增动态分发或枚举分支。直连 HTTPS 是 `SslStream<BoxConnection>`；verbose 模式例外。
- 建连路径：每层最多装箱一次 future；每次建连只选一次 TLS 上下文；除引用计数外不新增克隆。

测量方法：明文 HTTP/1，本机回环，服务端每个响应带 `connection: close`，客户端 `http1_only()` 加
`pool_max_idle_per_host(0)`，所以每个请求新建连接。用按线程计数的全局分配器只统计客户端线程，release 构建，每轮 2 万次
请求。基准程序不在仓库里。

| 版本 | 每请求分配次数 | 每请求分配字节 | 每请求耗时 |
|---|---|---|---|
| `53dd968a` | 49 | 44066 | 84–91 µs |
| #1393 | 50 | 44698 | 84–92 µs |

#1393 多出的一次分配来自 `Tls` 层的 future。计划在步骤 2 让直连路由不再装箱，回到不高于 49 次。

## 7. 已知限制

以下是之前决定只写文档或暂不处理的问题，状态以 2026-11-07 的核对为准，之后没有重新核实：

- 共享的 QUIC 端点注册在首个 HTTP/3 请求的运行时上；那个运行时还在但没人驱动时，其他运行时的新握手会卡住。
- `.interface()` 只在创建共享 QUIC 端点时绑定；网卡删除重建后，HTTP/3 握手会挂起到重建 `Client`。
- 公开的 `Runtime::udp_socket` 返回 `quic` 的类型，而 wreq 没有重导出它。
- 公开类型 `Conn` 没有实现 `AsyncRead`/`AsyncWrite`，在已建立的流上做 I/O 的用户连接层会失效。
- 每条走 MASQUE 隧道的 HTTP/3 连接都单独建一条到代理的外层 QUIC 连接，不复用。
