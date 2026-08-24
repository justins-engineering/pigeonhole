//! MQTT 3.1.1 adapter, beside the primary v5 one for the clients that speak
//! 3.1.1 today (Zephyr's in-tree client among them). The protocol's own
//! limits shape what this can say: there is no negative acknowledgement, so
//! the bridge's "retry later" outcomes become a closed connection and the
//! client's own reconnect is the retry; and with no Maximum QoS
//! advertisement, a QoS 2 PUBLISH is refused by closing the connection. The
//! broker never sends PUBREC, so it never enters an exchange it cannot
//! honor exactly once.

use mqtt_proto::{QosPid, TopicName, v3};
use pigeonhole_wire::framing::{FramingError, RawPacket};

use super::{
  AckOutcome, ConnackOutcome, ConnectRequest, Inbound, Outbound, PublishRequest, SubResult, Will,
};

pub fn decode(raw: &RawPacket) -> Result<Inbound, FramingError> {
  Ok(match raw.decode_v3()? {
    v3::Packet::Connect(connect) => Inbound::Connect(Box::new(ConnectRequest {
      client_id: connect.client_id.to_string(),
      username: connect.username.as_ref().map(|u| u.to_string()),
      password: connect.password.clone(),
      keep_alive: connect.keep_alive,
      clean_start: connect.clean_session,
      will: connect.last_will.as_ref().map(|will| Will {
        topic: will.topic_name.to_string(),
        payload: will.message.clone(),
        qos: will.qos as u8,
      }),
      receive_max: None,
    })),
    v3::Packet::Publish(publish) => Inbound::Publish(PublishRequest {
      topic: publish.topic_name.to_string(),
      payload: publish.payload.clone(),
      qos: publish.qos_pid.qos() as u8,
      pid: publish.qos_pid.pid().map(|p| p.value()),
      dup: publish.dup,
      retain: publish.retain,
      topic_alias: None,
    }),
    v3::Packet::Subscribe(subscribe) => Inbound::Subscribe {
      pid: subscribe.pid.value(),
      filters: subscribe
        .topics
        .iter()
        .map(|(filter, qos)| (filter.to_string(), *qos as u8))
        .collect(),
    },
    v3::Packet::Unsubscribe(unsubscribe) => Inbound::Unsubscribe {
      pid: unsubscribe.pid.value(),
      filters: unsubscribe.topics.iter().map(|f| f.to_string()).collect(),
    },
    v3::Packet::Puback(pid) => Inbound::Puback { pid: pid.value() },
    v3::Packet::Pingreq => Inbound::Pingreq,
    // 3.1.1 has no way to ask for a will on a clean disconnect: a DISCONNECT
    // always discards it.
    v3::Packet::Disconnect => Inbound::Disconnect {
      deliver_will: false,
    },
    v3::Packet::Pubrec(_) | v3::Packet::Pubrel(_) | v3::Packet::Pubcomp(_) => {
      Inbound::Unexpected("a QoS 2 exchange packet")
    }
    v3::Packet::Connack(_)
    | v3::Packet::Suback(_)
    | v3::Packet::Unsuback(_)
    | v3::Packet::Pingresp => Inbound::Unexpected("a server-to-client packet"),
  })
}

pub fn encode(outbound: &Outbound) -> Result<Option<Vec<u8>>, String> {
  let packet = match outbound {
    Outbound::Connack { outcome, .. } => match connect_return_code(*outcome) {
      Some(code) => v3::Packet::Connack(v3::Connack {
        // Always zero: sessions are stateless, and the retained shadow gives
        // a reconnecting device the catch-up a stored session would have.
        session_present: false,
        code,
      }),
      // Nothing in 3.1.1's five refusal codes fits, so the connection is
      // closed without a CONNACK, which the spec allows for exactly this.
      None => return Ok(None),
    },
    Outbound::Puback { pid, outcome } => match puback_is_sent(*outcome) {
      true => v3::Packet::Puback(pid_from(*pid)?),
      // No negative acknowledgement exists. Not acking and closing is the
      // whole signal, and the client's redelivery is the retry.
      false => return Ok(None),
    },
    // Encoded by hand rather than through the codec: mqtt-proto 0.4.0's
    // `SubscribeReturnCode` carries no explicit discriminants, so its
    // encoder writes `Failure as u8`, which is 3, where the spec's failure
    // code is 0x80. Its own decoder then rejects what it wrote, and a real
    // client would read a refusal as a granted QoS it never asked for.
    Outbound::Suback { pid, results } => return Ok(Some(encode_suback(*pid, results))),
    Outbound::Unsuback { pid, .. } => v3::Packet::Unsuback(pid_from(*pid)?),
    Outbound::Pingresp => v3::Packet::Pingresp,
    Outbound::Publish {
      topic,
      payload,
      qos,
      pid,
      retain,
    } => v3::Packet::Publish(v3::Publish {
      dup: false,
      retain: *retain,
      qos_pid: qos_pid(*qos, *pid)?,
      topic_name: TopicName::try_from(topic.as_str()).map_err(|e| e.to_string())?,
      payload: payload.clone(),
    }),
    // A server DISCONNECT does not exist in 3.1.1. The caller closes.
    Outbound::Disconnect { .. } => return Ok(None),
  };
  packet
    .encode()
    .map(|bytes| Some(bytes.as_ref().to_vec()))
    .map_err(|e| e.to_string())
}

/// The five refusals 3.1.1 can express. Everything else closes.
///
/// A spent allowance maps to "server unavailable" because that is the only
/// one of the five that means "retry later"; reading it as a credential
/// failure would send a device off to re-provision over a billing state.
fn connect_return_code(outcome: ConnackOutcome) -> Option<v3::ConnectReturnCode> {
  Some(match outcome {
    ConnackOutcome::Accepted => v3::ConnectReturnCode::Accepted,
    ConnackOutcome::BadCredentials => v3::ConnectReturnCode::BadUserNameOrPassword,
    // 3.1.1 has no topic-name refusal at CONNECT, and "not authorized" is
    // the nearest true statement: the session may not publish there.
    ConnackOutcome::NotAuthorized | ConnackOutcome::WillTopicInvalid => {
      v3::ConnectReturnCode::NotAuthorized
    }
    ConnackOutcome::ServerUnavailable
    | ConnackOutcome::QuotaExceeded
    | ConnackOutcome::ServerBusy => v3::ConnectReturnCode::ServerUnavailable,
    ConnackOutcome::ClientIdNotValid => v3::ConnectReturnCode::IdentifierRejected,
    ConnackOutcome::UnsupportedVersion => v3::ConnectReturnCode::UnacceptableProtocolVersion,
    ConnackOutcome::QoSNotSupported | ConnackOutcome::MalformedPacket => return None,
  })
}

/// Whether this outcome is acknowledged at all on 3.1.1.
///
/// Permanent refusals are acked: the report is never going to be accepted,
/// so the honest answer is to stop the client retrying it. Retryable ones
/// are not, because withholding the ack is the only way to say "again".
fn puback_is_sent(outcome: AckOutcome) -> bool {
  match outcome {
    AckOutcome::Success | AckOutcome::PayloadFormatInvalid | AckOutcome::UnspecifiedError => true,
    AckOutcome::QuotaExceeded | AckOutcome::NotAuthorized => false,
  }
}

/// The four bytes a 3.1.1 SUBACK may carry, from the spec's own table.
/// 3.1.1 has one failure code for every reason a filter can be refused.
fn subscribe_return_byte(result: SubResult) -> u8 {
  match result {
    SubResult::GrantedQos0 => 0x00,
    SubResult::GrantedQos1 => 0x01,
    SubResult::NotAuthorized | SubResult::SharedNotSupported => 0x80,
  }
}

/// SUBACK is a fixed header, a packet id, and one return byte per requested
/// filter. The remaining length fits one variable-byte integer for any
/// SUBSCRIBE this broker will accept, since the packet cap bounds how many
/// filters one can carry.
fn encode_suback(pid: u16, results: &[SubResult]) -> Vec<u8> {
  const CONTROL_BYTE: u8 = 0b1001_0000;
  let remaining_len = 2 + results.len();
  let mut packet = Vec::with_capacity(2 + remaining_len);
  packet.push(CONTROL_BYTE);
  let mut value = remaining_len;
  loop {
    let mut byte = (value % 128) as u8;
    value /= 128;
    if value > 0 {
      byte |= 0x80;
    }
    packet.push(byte);
    if value == 0 {
      break;
    }
  }
  packet.push((pid >> 8) as u8);
  packet.push((pid & 0xFF) as u8);
  packet.extend(results.iter().map(|r| subscribe_return_byte(*r)));
  packet
}

fn pid_from(pid: u16) -> Result<mqtt_proto::Pid, String> {
  mqtt_proto::Pid::try_from(pid).map_err(|e| e.to_string())
}

fn qos_pid(qos: u8, pid: Option<u16>) -> Result<QosPid, String> {
  Ok(match (qos, pid) {
    (0, _) => QosPid::Level0,
    (1, Some(pid)) => QosPid::Level1(pid_from(pid)?),
    (1, None) => return Err("a QoS 1 publish needs a packet id".to_string()),
    (other, _) => return Err(format!("this broker never sends QoS {other}")),
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::proto::DisconnectReason;

  async fn round_trip(packet: &v3::Packet) -> Inbound {
    let wire = packet.encode().expect("encodes").as_ref().to_vec();
    let raw = raw_from(wire).await;
    decode(&raw).expect("decodes")
  }

  async fn raw_from(wire: Vec<u8>) -> RawPacket {
    let mut slice = wire.as_slice();
    pigeonhole_wire::framing::read_packet(&mut slice)
      .await
      .expect("frames")
  }

  #[tokio::test]
  async fn a_qos2_publish_decodes_so_the_session_can_refuse_it_deliberately() {
    let event = round_trip(&v3::Packet::Publish(v3::Publish {
      dup: false,
      retain: false,
      qos_pid: QosPid::Level2(mqtt_proto::Pid::try_from(4).expect("pid")),
      topic_name: TopicName::try_from(pigeonhole_wire::topics::TELEMETRY).expect("topic"),
      payload: b"{}".as_slice().into(),
    }))
    .await;
    match event {
      Inbound::Publish(publish) => assert_eq!(publish.qos, 2),
      other => panic!("expected a publish, got {other:?}"),
    }
  }

  #[tokio::test]
  async fn the_qos2_exchange_packets_are_unexpected_rather_than_answered() {
    for packet in [
      v3::Packet::Pubrec(mqtt_proto::Pid::try_from(1).expect("pid")),
      v3::Packet::Pubrel(mqtt_proto::Pid::try_from(1).expect("pid")),
      v3::Packet::Pubcomp(mqtt_proto::Pid::try_from(1).expect("pid")),
    ] {
      assert!(matches!(round_trip(&packet).await, Inbound::Unexpected(_)));
    }
  }

  #[tokio::test]
  async fn a_disconnect_never_asks_for_the_will_on_this_version() {
    assert!(matches!(
      round_trip(&v3::Packet::Disconnect).await,
      Inbound::Disconnect {
        deliver_will: false
      }
    ));
  }

  #[test]
  fn refusals_with_no_v3_spelling_encode_to_a_close() {
    for outcome in [
      ConnackOutcome::QoSNotSupported,
      ConnackOutcome::MalformedPacket,
    ] {
      let encoded = encode(&Outbound::Connack {
        outcome,
        server_keep_alive: 60,
        receive_max: 16,
        reason: None,
      })
      .expect("encodes");
      assert!(encoded.is_none(), "{outcome:?} has no v3 code");
    }
  }

  #[test]
  fn a_spent_allowance_reads_as_retry_later_not_as_a_bad_credential() {
    assert_eq!(
      connect_return_code(ConnackOutcome::QuotaExceeded),
      Some(v3::ConnectReturnCode::ServerUnavailable)
    );
  }

  #[test]
  fn a_retryable_publish_outcome_withholds_the_ack() {
    for outcome in [AckOutcome::QuotaExceeded, AckOutcome::NotAuthorized] {
      let encoded = encode(&Outbound::Puback { pid: 1, outcome }).expect("encodes");
      assert!(encoded.is_none(), "{outcome:?} must not be acked on v3");
    }
    for outcome in [
      AckOutcome::Success,
      AckOutcome::PayloadFormatInvalid,
      AckOutcome::UnspecifiedError,
    ] {
      let encoded = encode(&Outbound::Puback { pid: 1, outcome }).expect("encodes");
      assert!(encoded.is_some(), "{outcome:?} is acked on v3");
    }
  }

  #[test]
  fn every_disconnect_reason_encodes_to_a_close() {
    let encoded = encode(&Outbound::Disconnect {
      reason: DisconnectReason::NotAuthorized,
      text: None,
    })
    .expect("encodes");
    assert!(encoded.is_none());
  }

  #[tokio::test]
  async fn a_refused_filter_gets_the_one_failure_code_this_version_has() {
    let encoded = encode(&Outbound::Suback {
      pid: 3,
      results: vec![SubResult::NotAuthorized, SubResult::SharedNotSupported],
    })
    .expect("encodes")
    .expect("a suback is sent");
    // Asserted on the bytes rather than through the codec, because the
    // codec is the thing being worked around here.
    assert_eq!(encoded, vec![0b1001_0000, 4, 0, 3, 0x80, 0x80]);
  }

  #[tokio::test]
  async fn a_granted_filter_carries_the_qos_it_was_granted_at() {
    let encoded = encode(&Outbound::Suback {
      pid: 1,
      results: vec![SubResult::GrantedQos1, SubResult::GrantedQos0],
    })
    .expect("encodes")
    .expect("a suback is sent");
    assert_eq!(encoded, vec![0b1001_0000, 4, 0, 1, 0x01, 0x00]);
    // And it frames as one packet, which is the part hand-encoding could
    // plausibly get wrong.
    let raw = raw_from(encoded).await;
    assert_eq!(raw.packet_type(), 9);
    assert_eq!(raw.remaining_len(), 4);
  }
}
