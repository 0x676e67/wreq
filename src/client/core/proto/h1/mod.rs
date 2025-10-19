mod conn;
mod decode;
pub(crate) mod dispatch;
mod encode;
mod io;
mod role;

use bytes::BytesMut;
use http::{HeaderMap, Method};
use httparse::ParserConfig;

pub(crate) use self::{
    conn::Conn,
    decode::Decoder,
    dispatch::Dispatcher,
    encode::{EncodedBuf, Encoder},
    io::MINIMUM_MAX_BUFFER_SIZE,
};
use crate::client::core::{
    body::DecodedLength,
    error::{Error, Parse, Result},
    proto::{BodyLength, MessageHead},
};

pub(crate) type ClientTransaction = role::Client;

pub(crate) trait Http1Transaction {
    type Incoming;

    type Outgoing: Default;

    #[cfg(feature = "tracing")]
    const LOG: &'static str;

    fn parse(bytes: &mut BytesMut, ctx: ParseContext<'_>) -> ParseResult<Self::Incoming>;

    fn encode(enc: Encode<'_, Self::Outgoing>, dst: &mut Vec<u8>) -> Result<Encoder>;

    fn on_error(err: &Error) -> Option<MessageHead<Self::Outgoing>>;

    fn is_client() -> bool {
        !Self::is_server()
    }

    fn is_server() -> bool {
        !Self::is_client()
    }

    fn should_error_on_parse_eof() -> bool {
        Self::is_client()
    }

    fn should_read_first() -> bool {
        Self::is_server()
    }

    fn update_date() {}
}

/// Result newtype for Http1Transaction::parse.
pub(crate) type ParseResult<T> = std::result::Result<Option<ParsedMessage<T>>, Parse>;

#[derive(Debug)]
pub(crate) struct ParsedMessage<T> {
    head: MessageHead<T>,
    decode: DecodedLength,
    expect_continue: bool,
    keep_alive: bool,
    wants_upgrade: bool,
}

pub(crate) struct ParseContext<'a> {
    cached_headers: &'a mut Option<HeaderMap>,
    req_method: &'a mut Option<Method>,
    h1_parser_config: ParserConfig,
    h1_max_headers: Option<usize>,
    h09_responses: bool,
}

/// Passed to Http1Transaction::encode
pub(crate) struct Encode<'a, T> {
    head: &'a mut MessageHead<T>,
    body: Option<BodyLength>,
    req_method: &'a mut Option<Method>,
}

/// Extra flags that a request "wants", like expect-continue or upgrades.
#[derive(Clone, Copy, Debug)]
struct Wants(u8);

impl Wants {
    const EMPTY: Wants = Wants(0b00);
    const EXPECT: Wants = Wants(0b01);
    const UPGRADE: Wants = Wants(0b10);

    #[must_use]
    fn add(self, other: Wants) -> Wants {
        Wants(self.0 | other.0)
    }

    fn contains(&self, other: Wants) -> bool {
        (self.0 & other.0) == other.0
    }
}
