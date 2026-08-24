//! Protocol-version adapters. The session layer never sees an
//! `mqtt_proto::v3` or `v5` packet directly; each adapter decodes its
//! version's packets into the shared events below and encodes the session's
//! replies back, including the version's own way of saying no (a v3.1.1
//! session can only be closed; a v5 session gets a reason code).
//!
//! Both ship together; v5 is the primary target per the owner's ruling, with
//! v3 beside it for the Zephyr-class clients that speak 3.1.1 today. Keeping
//! the session version-neutral is what stops the two versions from drifting
//! into two brokers: every rule is decided once, and the adapters only
//! decide how to say it.

pub mod v3;
pub mod v5;

use bytes::Bytes;
use mqtt_proto::Protocol;
use pigeonhole_wire::framing::{FramingError, RawPacket};

/// The versions this broker serves. MQTT 3.1 (protocol level 3) is not one
/// of them: nothing in the fleet speaks it, and admitting it would mean
/// carrying its own client-id rules for no device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
  V311,
  V500,
}

impl Version {
  pub fn from_protocol(protocol: Protocol) -> Option<Version> {
    match protocol {
      Protocol::V311 => Some(Version::V311),
      Protocol::V500 => Some(Version::V500),
      Protocol::V310 => None,
    }
  }

  pub fn as_str(self) -> &'static str {
    match self {
      Version::V311 => "3.1.1",
      Version::V500 => "5.0",
    }
  }
}

/// A will, as the session holds it. The declared QoS is not carried: an
/// upstream delivery is one HTTP POST whatever the will asked for, and a v5
/// will above the advertised Maximum QoS is refused at CONNECT rather than
/// downgraded here.
#[derive(Debug, Clone)]
pub struct Will {
  pub topic: String,
  pub payload: Bytes,
  pub qos: u8,
}

/// What a CONNECT claims, with the version's spellings already flattened.
#[derive(Debug, Clone)]
pub struct ConnectRequest {
  pub client_id: String,
  pub username: Option<String>,
  pub password: Option<Bytes>,
  pub keep_alive: u16,
  pub clean_start: bool,
  pub will: Option<Will>,
  /// v5 only: how many unacknowledged publishes the client will accept from
  /// the broker. The broker sends at most one retained shadow at a time, so
  /// this is honored trivially and recorded for the log line.
  pub receive_max: Option<u16>,
}

/// One inbound PUBLISH. `payload` is a `Bytes` slice of the packet, never
/// parsed here: the bridge copies it to the device route as it arrived.
#[derive(Debug, Clone)]
pub struct PublishRequest {
  pub topic: String,
  pub payload: Bytes,
  pub qos: u8,
  pub pid: Option<u16>,
  pub dup: bool,
  pub retain: bool,
  /// v5 only. Advertised Topic Alias Maximum is 0, so any value here is a
  /// protocol error rather than a lookup.
  pub topic_alias: Option<u16>,
}

/// Everything a client can send that this broker acts on. Packet types a
/// client has no business sending to a server (CONNACK, SUBACK, ...) and the
/// QoS 2 exchange packets collapse into [`Inbound::Unexpected`], which the
/// session turns into a protocol error.
#[derive(Debug, Clone)]
pub enum Inbound {
  Connect(Box<ConnectRequest>),
  Publish(PublishRequest),
  Subscribe {
    pid: u16,
    filters: Vec<(String, u8)>,
  },
  Unsubscribe {
    pid: u16,
    filters: Vec<String>,
  },
  Puback {
    pid: u16,
  },
  Pingreq,
  Disconnect {
    /// v5 lets a client ask for its will to be sent on a clean disconnect
    /// (reason 0x04). Anything else means the will is discarded.
    deliver_will: bool,
  },
  Unexpected(&'static str),
}

/// How a CONNECT was answered. Named by what happened rather than by a code,
/// because the two versions spell most of these differently and one of them
/// cannot spell some of them at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnackOutcome {
  Accepted,
  /// The credential was rejected upstream.
  BadCredentials,
  /// Authenticated shape, refused by policy.
  NotAuthorized,
  /// Retryable: the edge was unreachable, erroring, or answered with
  /// something that was not an auth verdict at all.
  ServerUnavailable,
  /// The identity was missing, malformed, or disagreed with itself.
  ClientIdNotValid,
  /// The account's message allowance is spent. Valid credentials, come back
  /// later, which is why it is not a credential failure on either version.
  QuotaExceeded,
  /// A will above the advertised Maximum QoS.
  QoSNotSupported,
  /// A will naming a topic this session could not publish to itself. The
  /// will is bridged as an ordinary publish, so there would be no route for
  /// it.
  WillTopicInvalid,
  UnsupportedVersion,
  /// The CONNECT parsed far enough to name its version, then did not decode.
  MalformedPacket,
  /// The broker is shedding load before it authenticates anyone.
  ServerBusy,
}

impl ConnackOutcome {
  pub fn accepted(self) -> bool {
    matches!(self, ConnackOutcome::Accepted)
  }
}

/// What a QoS 1 PUBACK carries. On 3.1.1 every one of these that is sent at
/// all is the same four bytes; the distinction still lives here so the ack
/// policy is written once (`docs/design.md` section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckOutcome {
  Success,
  /// Permanent and the client's fault: the report will never be accepted as
  /// sent, so acking it is the honest answer and retrying would loop.
  PayloadFormatInvalid,
  UnspecifiedError,
  /// The free-tier fuse. On v5 the session survives and the client learns
  /// why; a 3.1.1 session gets a close instead, its only signal.
  QuotaExceeded,
  NotAuthorized,
}

/// One entry in a SUBACK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubResult {
  GrantedQos0,
  GrantedQos1,
  NotAuthorized,
  SharedNotSupported,
}

/// Why the broker is ending a session. Every one of these is a v5 reason
/// code; on 3.1.1 they all become a closed connection, which is that
/// version's whole vocabulary for refusal after CONNACK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectReason {
  /// The credential stopped working mid-session (a bridged 401, or the
  /// Durable Object closing the feed after a token rotation or a deletion).
  NotAuthorized,
  ServerShuttingDown,
  KeepAliveTimeout,
  SessionTakenOver,
  /// Published to a topic that is not one of the session's leaves.
  TopicNameInvalid,
  ReceiveMaximumExceeded,
  TopicAliasInvalid,
  PacketTooLarge,
  MessageRateTooHigh,
  QuotaExceeded,
  QoSNotSupported,
  ProtocolError,
  MalformedPacket,
  /// The upstream leg failed in a way worth retrying.
  ServerBusy,
}

/// Everything the broker sends. `Disconnect` on 3.1.1 encodes to nothing:
/// the caller closes the socket, which is the message.
#[derive(Debug, Clone)]
pub enum Outbound {
  Connack {
    outcome: ConnackOutcome,
    /// The keepalive the broker will actually enforce, which v5 reports back
    /// and 3.1.1 can only leave implicit.
    server_keep_alive: u16,
    /// v5 Receive Maximum.
    receive_max: u16,
    /// Reason text for the cases where a code alone would be ambiguous.
    reason: Option<&'static str>,
  },
  Puback {
    pid: u16,
    outcome: AckOutcome,
  },
  Suback {
    pid: u16,
    results: Vec<SubResult>,
  },
  Unsuback {
    pid: u16,
    count: usize,
  },
  Pingresp,
  Publish {
    topic: String,
    payload: Bytes,
    qos: u8,
    pid: Option<u16>,
    retain: bool,
  },
  Disconnect {
    reason: DisconnectReason,
    text: Option<&'static str>,
  },
}

/// Decodes one packet into a version-neutral event.
pub fn decode(version: Version, raw: &RawPacket) -> Result<Inbound, FramingError> {
  match version {
    Version::V311 => v3::decode(raw),
    Version::V500 => v5::decode(raw),
  }
}

/// Encodes one reply. `None` means this version has no way to say it and the
/// caller should close instead.
pub fn encode(version: Version, outbound: &Outbound) -> Result<Option<Vec<u8>>, String> {
  match version {
    Version::V311 => v3::encode(outbound),
    Version::V500 => v5::encode(outbound),
  }
}

/// Whether a session of this version can be told anything at all after
/// CONNACK, or whether a refusal has to be a closed socket.
pub fn can_signal_after_connack(version: Version) -> bool {
  matches!(version, Version::V500)
}
