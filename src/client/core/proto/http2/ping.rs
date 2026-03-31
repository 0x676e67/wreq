//! HTTP2 Ping usage
//!
//! core uses HTTP2 pings for two purposes:
//!
//! 1. Adaptive flow control using BDP
//! 2. Connection keep-alive
//!
//! Both cases are optional.
//!
//! # BDP Algorithm
//!
//! 1. When receiving a DATA frame, if a BDP ping isn't outstanding: 1a. Record current time. 1b.
//!    Send a BDP ping.
//! 2. Increment the number of received bytes.
//! 3. When the BDP ping ack is received: 3a. Record duration from sent time. 3b. Merge RTT with a
//!    running average. 3c. Calculate bdp as bytes/rtt. 3d. If bdp is over 2/3 max, set new max to
//!    bdp and update windows.

use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{self, Poll},
    time::{Duration, Instant},
};

use http2::{Ping, PingPong};

use crate::{
    client::core::{
        self,
        error::{Error, Kind, TimedOut},
        rt::{Sleep, Time, Timer},
    },
    sync::Mutex,
};

type WindowSize = u32;

pub(super) fn channel(ping_pong: PingPong, config: Config, timer: Time) -> (Recorder, Ponger) {
    debug_assert!(
        config.is_enabled(),
        "ping channel requires bdp or keep-alive config",
    );

    let bdp = config.bdp_initial_window.map(|wnd| Bdp {
        bdp: wnd,
        max_bandwidth: 0.0,
        rtt: 0.0,
        ping_delay: Duration::from_millis(100),
        stable_count: 0,
    });

    let now = timer.now();
    let bdp_enabled = bdp.is_some();
    let keep_alive_enabled = config.keep_alive_interval.is_some();
    let next_bdp_at = bdp_enabled.then_some(now);

    let keep_alive = config.keep_alive_interval.map(|interval| KeepAlive {
        interval,
        timeout: config.keep_alive_timeout,
        while_idle: config.keep_alive_while_idle,
        sleep: timer.sleep(interval),
        state: KeepAliveState::Init,
        timer: timer.clone(),
    });

    let shared = Arc::new(Shared {
        bytes: AtomicU64::new(0),
        last_read_at: AtomicU64::new(0),
        is_keep_alive_timed_out: AtomicBool::new(false),
        bdp_enabled,
        keep_alive_enabled,
        start: now,
        timer: timer.clone(),
        inner: Mutex::new(PingInner {
            ping_pong,
            ping_sent_at: None,
            next_bdp_at,
        }),
    });

    (
        Recorder {
            shared: Some(shared.clone()),
        },
        Ponger {
            bdp,
            keep_alive,
            shared,
        },
    )
}

#[derive(Debug, Clone)]
pub(crate) struct Config {
    bdp_initial_window: Option<WindowSize>,
    /// If no frames are received in this amount of time, a PING frame is sent.
    keep_alive_interval: Option<Duration>,
    /// After sending a keepalive PING, the connection will be closed if
    /// a pong is not received in this amount of time.
    keep_alive_timeout: Duration,
    /// If true, sends pings even when there are no active streams.
    keep_alive_while_idle: bool,
}

#[derive(Clone)]
pub(crate) struct Recorder {
    shared: Option<Arc<Shared>>,
}

pub(super) struct Ponger {
    bdp: Option<Bdp>,
    keep_alive: Option<KeepAlive>,
    shared: Arc<Shared>,
}

struct Shared {
    // bdp
    /// If `Some`, bdp is enabled, and this tracks how many bytes have been
    /// read during the current sample.
    bytes: AtomicU64,
    // keep-alive
    /// If `Some`, keep-alive is enabled, and the Instant is how long ago
    /// the connection read the last frame.
    last_read_at: AtomicU64,
    is_keep_alive_timed_out: AtomicBool,
    bdp_enabled: bool,
    keep_alive_enabled: bool,
    start: Instant,
    timer: Time,
    inner: Mutex<PingInner>,
}

struct PingInner {
    ping_pong: PingPong,
    ping_sent_at: Option<Instant>,
    /// We delay a variable amount of time between BDP pings. This allows us
    /// to send less pings as the bandwidth stabilizes.
    next_bdp_at: Option<Instant>,
}

struct Bdp {
    /// Current BDP in bytes
    bdp: u32,
    /// Largest bandwidth we've seen so far.
    max_bandwidth: f64,
    /// Round trip time in seconds
    rtt: f64,
    /// Delay the next ping by this amount.
    ///
    /// This will change depending on how stable the current bandwidth is.
    ping_delay: Duration,
    /// The count of ping round trips where BDP has stayed the same.
    stable_count: u32,
}

struct KeepAlive {
    /// If no frames are received in this amount of time, a PING frame is sent.
    interval: Duration,
    /// After sending a keepalive PING, the connection will be closed if
    /// a pong is not received in this amount of time.
    timeout: Duration,
    /// If true, sends pings even when there are no active streams.
    while_idle: bool,
    state: KeepAliveState,
    sleep: Pin<Box<dyn Sleep>>,
    timer: Time,
}

enum KeepAliveState {
    Init,
    Scheduled(Instant),
    PingSent,
}

pub(super) enum Ponged {
    SizeUpdate(WindowSize),
    KeepAliveTimedOut,
}

#[derive(Debug)]
pub(super) struct KeepAliveTimedOut;

// ===== impl Config =====

impl Config {
    /// Creates a new `Config` with the specified parameters.
    pub(crate) fn new(
        adaptive_window: bool,
        initial_window_size: u32,
        keep_alive_interval: Option<Duration>,
        keep_alive_timeout: Duration,
        keep_alive_while_idle: bool,
    ) -> Self {
        Config {
            bdp_initial_window: if adaptive_window {
                Some(initial_window_size)
            } else {
                None
            },
            keep_alive_interval,
            keep_alive_timeout,
            keep_alive_while_idle,
        }
    }

    #[inline]
    pub(super) fn is_enabled(&self) -> bool {
        self.bdp_initial_window.is_some() || self.keep_alive_interval.is_some()
    }
}

// ===== impl Recorder =====

impl Recorder {
    #[inline]
    pub(super) fn disabled() -> Recorder {
        Recorder { shared: None }
    }

    pub(crate) fn record_data(&self, len: usize) {
        let Some(ref shared) = self.shared else {
            return;
        };

        let now = shared.timer.now();
        shared.update_last_read_at(now);

        // are we ready to send another bdp ping?
        // if not, we don't need to record bytes either

        if !shared.bdp_enabled {
            return;
        }

        let mut inner = shared.inner.lock();
        if let Some(next_bdp_at) = inner.next_bdp_at {
            if now < next_bdp_at {
                return;
            }
            inner.next_bdp_at = None;
        }

        shared.bytes.fetch_add(len as u64, Ordering::Relaxed);

        if !inner.is_ping_sent() {
            inner.send_ping(&shared.timer);
        }
    }

    pub(crate) fn record_non_data(&self) {
        let Some(ref shared) = self.shared else {
            return;
        };

        let now = shared.timer.now();
        shared.update_last_read_at(now);
    }

    /// If the incoming stream is already closed, convert self into
    /// a disabled reporter.
    pub(super) fn for_stream(self, stream: &http2::RecvStream) -> Self {
        if stream.is_end_stream() {
            Recorder::disabled()
        } else {
            self
        }
    }

    pub(super) fn ensure_not_timed_out(&self) -> core::Result<()> {
        if let Some(ref shared) = self.shared {
            if shared.is_keep_alive_timed_out.load(Ordering::Acquire) {
                return Err(KeepAliveTimedOut.crate_error());
            }
        }

        Ok(())
    }
}

// ===== impl Ponger =====

impl Future for Ponger {
    type Output = Ponged;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut().get_mut();

        // hoping this is fine to move within the lock
        let now = this.shared.timer.now();

        let is_idle = this.is_idle();
        let mut inner = this.shared.inner.lock();

        if let Some(ref mut ka) = this.keep_alive {
            ka.maybe_schedule(is_idle, &this.shared, &inner);
            ka.maybe_ping(cx, is_idle, &this.shared, &mut inner);
        }

        if !inner.is_ping_sent() {
            // XXX: this doesn't register a waker...?
            return Poll::Pending;
        }

        match inner.ping_pong.poll_pong(cx) {
            Poll::Ready(Ok(_pong)) => {
                let start = inner
                    .ping_sent_at
                    .take()
                    .expect("pong received implies ping_sent_at");
                let rtt = now - start;
                trace!("recv pong");

                if let Some(ref mut ka) = this.keep_alive {
                    let now = this.shared.timer.now();
                    this.shared.update_last_read_at(now);
                    ka.maybe_schedule(is_idle, &this.shared, &inner);
                    ka.maybe_ping(cx, is_idle, &this.shared, &mut inner);
                }

                if let Some(ref mut bdp) = this.bdp {
                    let bytes = this.shared.bytes.swap(0, Ordering::AcqRel) as usize;
                    trace!("received BDP ack; bytes = {}, rtt = {:?}", bytes, rtt);

                    let update = bdp.calculate(bytes, rtt);
                    inner.next_bdp_at = Some(now + bdp.ping_delay);
                    if let Some(update) = update {
                        return Poll::Ready(Ponged::SizeUpdate(update));
                    }
                }
            }
            Poll::Ready(Err(_e)) => {
                debug!("pong error: {}", _e);
            }
            Poll::Pending => {
                if let Some(ref mut ka) = this.keep_alive {
                    if let Err(KeepAliveTimedOut) = ka.maybe_timeout(cx) {
                        this.keep_alive = None;
                        this.shared
                            .is_keep_alive_timed_out
                            .store(true, Ordering::Release);
                        return Poll::Ready(Ponged::KeepAliveTimedOut);
                    }
                }
            }
        }

        // XXX: this doesn't register a waker...?
        Poll::Pending
    }
}

impl Ponger {
    #[inline]
    fn is_idle(&self) -> bool {
        // If there are no active streams, we consider the connection idle.
        // This is a bit of a hack, but it allows us to avoid adding extra
        // state to track idleness.
        Arc::strong_count(&self.shared) <= 2
    }
}

// ===== impl Shared =====

impl Shared {
    #[inline]
    fn update_last_read_at(&self, now: Instant) {
        if self.keep_alive_enabled {
            let nanos = now.duration_since(self.start).as_nanos() as u64;
            self.last_read_at.store(nanos, Ordering::Release);
        }
    }

    #[inline]
    fn last_read_at(&self) -> Instant {
        let nanos = self.last_read_at.load(Ordering::Acquire);
        self.start + Duration::from_nanos(nanos)
    }
}

// ===== impl PingInner =====

impl PingInner {
    fn send_ping(&mut self, timer: &Time) {
        match self.ping_pong.send_ping(Ping::opaque()) {
            Ok(()) => {
                self.ping_sent_at = Some(timer.now());
                trace!("sent ping");
            }
            Err(_err) => {
                debug!("error sending ping: {}", _err);
            }
        }
    }

    #[inline]
    fn is_ping_sent(&self) -> bool {
        self.ping_sent_at.is_some()
    }
}

// ===== impl Bdp =====

/// Any higher than this likely will be hitting the TCP flow control.
const BDP_LIMIT: usize = 1024 * 1024 * 16;

impl Bdp {
    fn calculate(&mut self, bytes: usize, rtt: Duration) -> Option<WindowSize> {
        // No need to do any math if we're at the limit.
        if self.bdp as usize == BDP_LIMIT {
            self.stabilize_delay();
            return None;
        }

        // average the rtt
        let rtt = seconds(rtt);
        if self.rtt == 0.0 {
            // First sample means rtt is first rtt.
            self.rtt = rtt;
        } else {
            // Weigh this rtt as 1/8 for a moving average.
            self.rtt += (rtt - self.rtt) * 0.125;
        }

        // calculate the current bandwidth
        let bw = (bytes as f64) / (self.rtt * 1.5);
        trace!("current bandwidth = {:.1}B/s", bw);

        if bw < self.max_bandwidth {
            // not a faster bandwidth, so don't update
            self.stabilize_delay();
            return None;
        } else {
            self.max_bandwidth = bw;
        }

        // if the current `bytes` sample is at least 2/3 the previous
        // bdp, increase to double the current sample.
        if bytes >= self.bdp as usize * 2 / 3 {
            self.bdp = (bytes * 2).min(BDP_LIMIT) as WindowSize;
            trace!("BDP increased to {}", self.bdp);

            self.stable_count = 0;
            self.ping_delay /= 2;
            Some(self.bdp)
        } else {
            self.stabilize_delay();
            None
        }
    }

    fn stabilize_delay(&mut self) {
        if self.ping_delay < Duration::from_secs(10) {
            self.stable_count += 1;

            if self.stable_count >= 2 {
                self.ping_delay *= 4;
                self.stable_count = 0;
            }
        }
    }
}

#[inline]
fn seconds(dur: Duration) -> f64 {
    const NANOS_PER_SEC: f64 = 1_000_000_000.0;
    let secs = dur.as_secs() as f64;
    secs + (dur.subsec_nanos() as f64) / NANOS_PER_SEC
}

// ===== impl KeepAlive =====

impl KeepAlive {
    fn maybe_schedule(&mut self, is_idle: bool, shared: &Shared, inner: &PingInner) {
        match self.state {
            KeepAliveState::Init => {
                if !self.while_idle && is_idle {
                    return;
                }

                self.schedule(shared);
            }
            KeepAliveState::PingSent => {
                if inner.is_ping_sent() {
                    return;
                }
                self.schedule(shared);
            }
            KeepAliveState::Scheduled(..) => (),
        }
    }

    fn schedule(&mut self, shared: &Shared) {
        let interval = shared.last_read_at() + self.interval;
        self.state = KeepAliveState::Scheduled(interval);
        self.timer.reset(&mut self.sleep, interval);
    }

    fn maybe_ping(
        &mut self,
        cx: &mut task::Context<'_>,
        is_idle: bool,
        shared: &Shared,
        inner: &mut PingInner,
    ) {
        match self.state {
            KeepAliveState::Scheduled(at) => {
                if Pin::new(&mut self.sleep).poll(cx).is_pending() {
                    return;
                }
                // check if we've received a frame while we were scheduled
                if shared.last_read_at() + self.interval > at {
                    self.state = KeepAliveState::Init;
                    cx.waker().wake_by_ref(); // schedule us again
                    return;
                }
                if !self.while_idle && is_idle {
                    trace!("keep-alive no need to ping when idle and while_idle=false");
                    return;
                }
                trace!("keep-alive interval ({:?}) reached", self.interval);
                inner.send_ping(&shared.timer);
                self.state = KeepAliveState::PingSent;
                let timeout = self.timer.now() + self.timeout;
                self.timer.reset(&mut self.sleep, timeout);
            }
            KeepAliveState::Init | KeepAliveState::PingSent => (),
        }
    }

    fn maybe_timeout(&mut self, cx: &mut task::Context<'_>) -> Result<(), KeepAliveTimedOut> {
        match self.state {
            KeepAliveState::PingSent => {
                if Pin::new(&mut self.sleep).poll(cx).is_pending() {
                    return Ok(());
                }
                trace!("keep-alive timeout ({:?}) reached", self.timeout);
                Err(KeepAliveTimedOut)
            }
            KeepAliveState::Init | KeepAliveState::Scheduled(..) => Ok(()),
        }
    }
}

// ===== impl KeepAliveTimedOut =====

impl KeepAliveTimedOut {
    pub(super) fn crate_error(self) -> Error {
        Error::new(Kind::Http2).with(self)
    }
}

impl fmt::Display for KeepAliveTimedOut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("keep-alive timed out")
    }
}

impl std::error::Error for KeepAliveTimedOut {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&TimedOut)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, mpsc};

    use tokio::{io::duplex, runtime::Builder as RuntimeBuilder};

    use super::*;
    use crate::client::core::rt::TokioTimer;

    async fn build_ping_pong() -> PingPong {
        let (client_io, server_io) = duplex(1024);

        let client = tokio::spawn(async move { http2::client::handshake(client_io).await });
        let server = tokio::spawn(async move { http2::server::handshake(server_io).await });

        let (client_res, server_res) = tokio::join!(client, server);
        let (_, mut client_conn) = client_res.expect("client join").expect("client handshake");
        let _server_conn = server_res.expect("server join").expect("server handshake");

        client_conn.ping_pong().expect("ping_pong")
    }

    #[test]
    fn record_data_does_not_block_when_bdp_disabled() {
        let rt = RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let (recorder, _ponger) = rt.block_on(async {
            let ping_pong = build_ping_pong().await;
            let config = Config::new(
                false,
                0,
                Some(Duration::from_secs(60)),
                Duration::from_secs(5),
                true,
            );
            let timer = Time::Timer(Arc::new(TokioTimer::new()));
            channel(ping_pong, config, timer)
        });

        let shared = recorder.shared.as_ref().expect("shared").clone();
        let (locked_tx, locked_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        let lock_handle = std::thread::spawn(move || {
            let _guard = shared.inner.lock();
            let _ = locked_tx.send(());
            let _ = release_rx.recv();
        });

        locked_rx.recv().expect("lock acquired");

        let recorder_clone = recorder.clone();
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            recorder_clone.record_data(1);
            let _ = done_tx.send(());
        });

        assert!(
            done_rx.recv_timeout(Duration::from_millis(50)).is_ok(),
            "record_data blocked while shared lock held"
        );

        let _ = release_tx.send(());
        let _ = lock_handle.join();
    }
}
