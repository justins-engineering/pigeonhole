//! Size-capped reading and writing of MQTT packets over tokio IO, shared by
//! the broker's session reader and the client's raw connection. The reader
//! decodes the fixed header first and refuses the packet once the remaining
//! length exceeds [`limits::MAX_PACKET_BYTES`], before any body bytes are
//! read, so a hostile or broken peer cannot make either end allocate for a
//! packet it will reject. The codec itself is `mqtt_proto` (v3 and v5 packet
//! types); this module only adds the cap and the per-packet read and write.
//!
//! Reading is deliberately two steps, raw bytes then decode. A connection's
//! protocol version is not known until its CONNECT has been parsed, and the
//! version decides which codec every later packet goes through, so the read
//! path cannot commit to one. [`RawPacket::connect_protocol`] answers that
//! question from the CONNECT's own bytes.

use std::io;

use mqtt_proto::{Protocol, v3, v5};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::limits;

/// Why a packet could not be read or decoded. The variants are kept apart
/// because they call for different answers on the wire: an oversize packet
/// has a reason code of its own, a malformed one is a protocol error, and a
/// clean EOF is just the peer hanging up.
#[derive(Debug, thiserror::Error)]
pub enum FramingError {
  /// The peer closed cleanly, between packets.
  #[error("connection closed")]
  Eof,
  #[error("io: {0}")]
  Io(#[from] io::Error),
  /// Refused from the fixed header alone, before the body was read.
  #[error("packet remaining length {remaining_len} over the {cap}-byte cap")]
  TooLarge { remaining_len: usize, cap: usize },
  /// The fixed header or the packet body did not decode.
  #[error("malformed packet: {0}")]
  Malformed(String),
}

impl FramingError {
  /// True when the peer simply went away, which every caller treats as an
  /// ordinary end of session rather than as a fault to report back.
  pub fn is_disconnect(&self) -> bool {
    match self {
      FramingError::Eof => true,
      FramingError::Io(e) => matches!(
        e.kind(),
        io::ErrorKind::UnexpectedEof
          | io::ErrorKind::ConnectionReset
          | io::ErrorKind::BrokenPipe
          | io::ErrorKind::ConnectionAborted
      ),
      _ => false,
    }
  }
}

/// One packet as it arrived: the fixed header plus exactly the remaining
/// bytes it declared. Held undecoded so the caller can pick the codec.
#[derive(Debug, Clone)]
pub struct RawPacket {
  /// The whole packet, fixed header included, ready to hand to a codec.
  bytes: Vec<u8>,
  header_len: usize,
}

impl RawPacket {
  /// First byte: packet type in the high nibble, flags in the low one.
  pub fn control_byte(&self) -> u8 {
    self.bytes[0]
  }

  /// Packet type nibble. Useful before a version is known, which is the one
  /// situation the typed packets cannot help with.
  pub fn packet_type(&self) -> u8 {
    self.bytes[0] >> 4
  }

  /// Everything after the fixed header.
  pub fn body(&self) -> &[u8] {
    &self.bytes[self.header_len..]
  }

  pub fn remaining_len(&self) -> usize {
    self.bytes.len() - self.header_len
  }

  pub fn total_len(&self) -> usize {
    self.bytes.len()
  }

  pub fn as_bytes(&self) -> &[u8] {
    &self.bytes
  }

  pub fn decode_v3(&self) -> Result<v3::Packet, FramingError> {
    match v3::Packet::decode(&self.bytes) {
      Ok(Some(packet)) => Ok(packet),
      // The declared remaining length was read in full, so "needs more" can
      // only mean the packet's own internal lengths disagree with it.
      Ok(None) => Err(FramingError::Malformed(
        "remaining length disagrees with the packet body".to_string(),
      )),
      Err(e) => Err(FramingError::Malformed(e.to_string())),
    }
  }

  pub fn decode_v5(&self) -> Result<v5::Packet, FramingError> {
    match v5::Packet::decode(&self.bytes) {
      Ok(Some(packet)) => Ok(packet),
      Ok(None) => Err(FramingError::Malformed(
        "remaining length disagrees with the packet body".to_string(),
      )),
      Err(e) => Err(FramingError::Malformed(e.to_string())),
    }
  }

  /// Reads the protocol name and level out of a CONNECT, which is the only
  /// packet that carries them and the reason the read path stays untyped
  /// until it has been seen.
  pub fn connect_protocol(&self) -> Result<Protocol, FramingError> {
    if self.packet_type() != CONNECT_PACKET_TYPE {
      return Err(FramingError::Malformed(
        "expected a CONNECT packet first".to_string(),
      ));
    }
    let mut offset = 0;
    Protocol::decode(self.body(), &mut offset).map_err(|e| FramingError::Malformed(e.to_string()))
  }
}

/// Packet type nibble of CONNECT, the one packet whose type must be known
/// before any codec can be chosen.
pub const CONNECT_PACKET_TYPE: u8 = 1;

/// Reads one packet, refusing an oversize one from its header alone.
///
/// The cap is checked between the header and the body deliberately: the
/// remaining length is attacker-controlled and up to 256 MiB per the spec,
/// so allocating for it before deciding is how a broker gets memory-flooded
/// by packets it was always going to reject.
pub async fn read_packet<R: AsyncRead + Unpin>(reader: &mut R) -> Result<RawPacket, FramingError> {
  read_packet_capped(reader, limits::MAX_PACKET_BYTES).await
}

/// [`read_packet`] with an explicit cap, so tests can drive the refusal
/// without building a 20 KiB packet.
pub async fn read_packet_capped<R: AsyncRead + Unpin>(
  reader: &mut R,
  cap: usize,
) -> Result<RawPacket, FramingError> {
  let mut header = Vec::with_capacity(5);

  let mut first = [0u8; 1];
  match reader.read(&mut first).await {
    Ok(0) => return Err(FramingError::Eof),
    Ok(_) => header.push(first[0]),
    Err(e) => return Err(FramingError::Io(e)),
  }

  let mut remaining_len: usize = 0;
  let mut shift = 0;
  loop {
    let mut byte = [0u8; 1];
    reader.read_exact(&mut byte).await?;
    header.push(byte[0]);
    remaining_len |= ((byte[0] & 0x7F) as usize) << shift;
    if byte[0] & 0x80 == 0 {
      break;
    }
    shift += 7;
    if shift > 21 {
      return Err(FramingError::Malformed(
        "remaining length is not a valid variable byte integer".to_string(),
      ));
    }
  }

  if remaining_len > cap {
    return Err(FramingError::TooLarge { remaining_len, cap });
  }

  let header_len = header.len();
  let mut bytes = header;
  bytes.resize(header_len + remaining_len, 0);
  reader.read_exact(&mut bytes[header_len..]).await?;

  Ok(RawPacket { bytes, header_len })
}

/// Writes one already-encoded packet and flushes it. MQTT packets are small
/// and latency-sensitive (a PUBACK held in a buffer is a stalled client), so
/// there is no write batching here.
pub async fn write_packet<W: AsyncWrite + Unpin>(writer: &mut W, packet: &[u8]) -> io::Result<()> {
  writer.write_all(packet).await?;
  writer.flush().await
}

#[cfg(test)]
mod tests {
  use super::*;
  use mqtt_proto::{QoS, QosPid, TopicName};

  fn encoded_v3(packet: &v3::Packet) -> Vec<u8> {
    packet.encode().expect("encodes").as_ref().to_vec()
  }

  #[tokio::test]
  async fn reads_a_packet_and_hands_back_its_exact_bytes() {
    let packet = v3::Packet::Publish(v3::Publish {
      dup: false,
      retain: false,
      qos_pid: QosPid::Level0,
      topic_name: TopicName::try_from(crate::topics::TELEMETRY).expect("topic"),
      payload: b"{\"temp\":\"21.5\"}".as_slice().into(),
    });
    let wire = encoded_v3(&packet);

    let mut reader = wire.as_slice();
    let raw = read_packet(&mut reader).await.expect("reads");
    assert_eq!(raw.as_bytes(), wire.as_slice());
    assert_eq!(raw.packet_type(), 3);
    assert_eq!(raw.decode_v3().expect("decodes"), packet);
  }

  #[tokio::test]
  async fn a_clean_close_between_packets_is_eof_not_an_error() {
    let mut reader: &[u8] = &[];
    let err = read_packet(&mut reader).await.expect_err("no packet");
    assert!(matches!(err, FramingError::Eof));
    assert!(err.is_disconnect());
  }

  #[tokio::test]
  async fn a_truncated_packet_is_an_error_not_a_short_packet() {
    // A PUBLISH header promising 200 bytes with none behind it.
    let wire = [0x30u8, 0xC8];
    let mut reader: &[u8] = &wire;
    let err = read_packet(&mut reader).await.expect_err("truncated");
    assert!(matches!(err, FramingError::Io(_)));
  }

  #[tokio::test]
  async fn an_oversize_packet_is_refused_from_its_header_before_the_body() {
    // Remaining length 300 as a two-byte varint, and no body at all: the
    // refusal has to come from the header, or this would block on a read.
    let wire = [0x30u8, 0xAC, 0x02];
    let mut reader: &[u8] = &wire;
    let err = read_packet_capped(&mut reader, 256)
      .await
      .expect_err("over cap");
    match err {
      FramingError::TooLarge { remaining_len, cap } => {
        assert_eq!(remaining_len, 300);
        assert_eq!(cap, 256);
      }
      other => panic!("expected TooLarge, got {other:?}"),
    }
  }

  #[tokio::test]
  async fn a_packet_at_the_cap_is_accepted() {
    let payload = vec![b'x'; 200];
    let packet = v3::Packet::Publish(v3::Publish {
      dup: false,
      retain: false,
      qos_pid: QosPid::Level0,
      topic_name: TopicName::try_from(crate::topics::LOGS).expect("topic"),
      payload: payload.into(),
    });
    let wire = encoded_v3(&packet);

    let mut reader = wire.as_slice();
    let remaining = read_packet(&mut reader)
      .await
      .expect("reads")
      .remaining_len();

    let mut reader = wire.as_slice();
    let raw = read_packet_capped(&mut reader, remaining)
      .await
      .expect("a packet exactly at the cap is not over it");
    assert_eq!(raw.remaining_len(), remaining);

    let mut reader = wire.as_slice();
    assert!(
      read_packet_capped(&mut reader, remaining - 1)
        .await
        .is_err(),
      "one byte over the cap is refused"
    );
  }

  #[tokio::test]
  async fn a_bad_variable_byte_integer_is_malformed() {
    let wire = [0x30u8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    let mut reader: &[u8] = &wire;
    let err = read_packet(&mut reader).await.expect_err("bad varint");
    assert!(matches!(err, FramingError::Malformed(_)));
  }

  #[tokio::test]
  async fn the_connect_protocol_is_readable_before_a_codec_is_chosen() {
    for (protocol, clean) in [(Protocol::V311, true), (Protocol::V500, true)] {
      let wire = match protocol {
        Protocol::V500 => encoded_v5(&v5::Packet::Connect(v5::Connect {
          protocol,
          clean_start: clean,
          keep_alive: 60,
          properties: Default::default(),
          client_id: "pigeon".into(),
          last_will: None,
          username: None,
          password: None,
        })),
        _ => encoded_v3(&v3::Packet::Connect(v3::Connect {
          protocol,
          clean_session: clean,
          keep_alive: 60,
          client_id: "pigeon".into(),
          last_will: None,
          username: None,
          password: None,
        })),
      };
      let mut reader = wire.as_slice();
      let raw = read_packet(&mut reader).await.expect("reads");
      assert_eq!(raw.connect_protocol().expect("protocol"), protocol);
    }
  }

  #[tokio::test]
  async fn asking_a_non_connect_packet_for_its_protocol_is_an_error() {
    let wire = encoded_v3(&v3::Packet::Pingreq);
    let mut reader = wire.as_slice();
    let raw = read_packet(&mut reader).await.expect("reads");
    assert!(raw.connect_protocol().is_err());
  }

  #[tokio::test]
  async fn back_to_back_packets_are_read_one_at_a_time() {
    let mut wire = encoded_v3(&v3::Packet::Pingreq);
    wire.extend_from_slice(&encoded_v3(&v3::Packet::Disconnect));

    let mut reader = wire.as_slice();
    let first = read_packet(&mut reader).await.expect("first");
    let second = read_packet(&mut reader).await.expect("second");
    assert_eq!(first.decode_v3().expect("decodes"), v3::Packet::Pingreq);
    assert_eq!(second.decode_v3().expect("decodes"), v3::Packet::Disconnect);
  }

  #[tokio::test]
  async fn writing_a_packet_puts_exactly_its_bytes_on_the_wire() {
    let packet = v3::Packet::Pingresp;
    let wire = encoded_v3(&packet);
    let mut out = Vec::new();
    write_packet(&mut out, &wire).await.expect("writes");
    assert_eq!(out, wire);
  }

  #[test]
  fn a_qos2_publish_still_decodes_so_the_session_can_answer_it_by_the_spec() {
    // Refusing QoS 2 is a decision the session makes with a reason code, so
    // the codec must not swallow the packet before it gets there.
    let packet = v3::Packet::Publish(v3::Publish {
      dup: false,
      retain: false,
      qos_pid: QosPid::Level2(mqtt_proto::Pid::try_from(1).expect("pid")),
      topic_name: TopicName::try_from(crate::topics::TELEMETRY).expect("topic"),
      payload: b"{}".as_slice().into(),
    });
    let wire = encoded_v3(&packet);
    let raw = RawPacket {
      header_len: 2,
      bytes: wire,
    };
    let decoded = raw.decode_v3().expect("decodes");
    match decoded {
      v3::Packet::Publish(publish) => assert_eq!(publish.qos_pid.qos(), QoS::Level2),
      other => panic!("expected a publish, got {other:?}"),
    }
  }

  fn encoded_v5(packet: &v5::Packet) -> Vec<u8> {
    packet.encode().expect("encodes").as_ref().to_vec()
  }
}
