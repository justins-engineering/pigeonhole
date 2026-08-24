//! MQTT 5 adapter, the primary protocol target. Reason codes carry the
//! bridge's ack table to the device honestly, CONNACK properties advertise
//! what this broker actually is (Maximum QoS 1, no shared subscriptions, no
//! topic aliases, Session Expiry Interval 0), a QoS 2 PUBLISH is the
//! protocol error the spec makes it once Maximum QoS 1 was advertised, and
//! session takeover and token rotation get their named DISCONNECT reasons.

use mqtt_proto::{QoS, QosPid, TopicName, v5};
use pigeonhole_wire::framing::{FramingError, RawPacket};
use pigeonhole_wire::limits;

use super::{
  AckOutcome, ConnackOutcome, ConnectRequest, DisconnectReason, Inbound, Outbound, PublishRequest,
  SubResult, Will,
};

pub fn decode(raw: &RawPacket) -> Result<Inbound, FramingError> {
  Ok(match raw.decode_v5()? {
    v5::Packet::Connect(connect) => Inbound::Connect(Box::new(ConnectRequest {
      client_id: connect.client_id.to_string(),
      username: connect.username.as_ref().map(|u| u.to_string()),
      password: connect.password.clone(),
      keep_alive: connect.keep_alive,
      clean_start: connect.clean_start,
      will: connect.last_will.as_ref().map(|will| Will {
        topic: will.topic_name.to_string(),
        payload: will.payload.clone(),
        qos: will.qos as u8,
      }),
      receive_max: connect.properties.receive_max,
    })),
    v5::Packet::Publish(publish) => Inbound::Publish(PublishRequest {
      topic: publish.topic_name.to_string(),
      payload: publish.payload.clone(),
      qos: publish.qos_pid.qos() as u8,
      pid: publish.qos_pid.pid().map(|p| p.value()),
      dup: publish.dup,
      retain: publish.retain,
      topic_alias: publish.properties.topic_alias,
    }),
    v5::Packet::Subscribe(subscribe) => Inbound::Subscribe {
      pid: subscribe.pid.value(),
      filters: subscribe
        .topics
        .iter()
        .map(|(filter, options)| (filter.to_string(), options.max_qos as u8))
        .collect(),
    },
    v5::Packet::Unsubscribe(unsubscribe) => Inbound::Unsubscribe {
      pid: unsubscribe.pid.value(),
      filters: unsubscribe.topics.iter().map(|f| f.to_string()).collect(),
    },
    v5::Packet::Puback(puback) => Inbound::Puback {
      pid: puback.pid.value(),
    },
    v5::Packet::Pingreq => Inbound::Pingreq,
    v5::Packet::Disconnect(disconnect) => Inbound::Disconnect {
      deliver_will: disconnect.reason_code == v5::DisconnectReasonCode::DisconnectWithWillMessage,
    },
    v5::Packet::Pubrec(_) | v5::Packet::Pubrel(_) | v5::Packet::Pubcomp(_) => {
      Inbound::Unexpected("a QoS 2 exchange packet")
    }
    // Enhanced authentication is not offered: the session's credential is
    // decided by the handshake and the CONNECT, and there is no exchange to
    // continue.
    v5::Packet::Auth(_) => Inbound::Unexpected("an AUTH packet"),
    v5::Packet::Connack(_)
    | v5::Packet::Suback(_)
    | v5::Packet::Unsuback(_)
    | v5::Packet::Pingresp => Inbound::Unexpected("a server-to-client packet"),
  })
}

pub fn encode(outbound: &Outbound) -> Result<Option<Vec<u8>>, String> {
  let packet = match outbound {
    Outbound::Connack {
      outcome,
      server_keep_alive,
      receive_max,
      reason,
    } => v5::Packet::Connack(v5::Connack {
      session_present: false,
      reason_code: connect_reason_code(*outcome),
      properties: connack_properties(*outcome, *server_keep_alive, *receive_max, *reason),
    }),
    Outbound::Puback { pid, outcome } => v5::Packet::Puback(v5::Puback {
      pid: pid_from(*pid)?,
      reason_code: puback_reason_code(*outcome),
      properties: Default::default(),
    }),
    Outbound::Suback { pid, results } => v5::Packet::Suback(v5::Suback {
      pid: pid_from(*pid)?,
      properties: Default::default(),
      topics: results.iter().map(|r| subscribe_reason_code(*r)).collect(),
    }),
    Outbound::Unsuback { pid, count } => v5::Packet::Unsuback(v5::Unsuback {
      pid: pid_from(*pid)?,
      properties: Default::default(),
      // Unsubscribing from a filter that was never granted is not an error
      // in either version, and this broker keeps no per-filter state to
      // report a miss against.
      topics: vec![v5::UnsubscribeReasonCode::Success; *count],
    }),
    Outbound::Pingresp => v5::Packet::Pingresp,
    Outbound::Publish {
      topic,
      payload,
      qos,
      pid,
      retain,
    } => v5::Packet::Publish(v5::Publish {
      dup: false,
      retain: *retain,
      qos_pid: qos_pid(*qos, *pid)?,
      topic_name: TopicName::try_from(topic.as_str()).map_err(|e| e.to_string())?,
      payload: payload.clone(),
      properties: Default::default(),
    }),
    Outbound::Disconnect { reason, text } => v5::Packet::Disconnect(v5::Disconnect {
      reason_code: disconnect_reason_code(*reason),
      properties: v5::DisconnectProperties {
        reason_string: text.map(|t| t.into()),
        ..Default::default()
      },
    }),
  };
  packet
    .encode()
    .map(|bytes| Some(bytes.as_ref().to_vec()))
    .map_err(|e| e.to_string())
}

/// What the broker tells a client about itself, and the reason it is worth
/// spelling out: on 3.1.1 every one of these is an undocumented convention
/// the device has to be built to already know.
fn connack_properties(
  outcome: ConnackOutcome,
  server_keep_alive: u16,
  receive_max: u16,
  reason: Option<&'static str>,
) -> v5::ConnackProperties {
  let mut properties = v5::ConnackProperties {
    reason_string: reason.map(|r| r.into()),
    ..Default::default()
  };
  if !outcome.accepted() {
    return properties;
  }
  // Sessions are stateless, so the expiry is zero rather than absent: a
  // client that asked for a longer one learns it did not get it.
  properties.session_expiry_interval = Some(0);
  properties.receive_max = Some(receive_max);
  // The spec's own mechanism for refusing QoS 2, which is why v5 can refuse
  // it without closing anything: a QoS 2 PUBLISH after this is a protocol
  // error rather than a surprise.
  properties.max_qos = Some(QoS::Level1);
  properties.retain_available = Some(true);
  properties.max_packet_size = Some(limits::MAX_PACKET_BYTES as u32);
  // Topic aliases are refused rather than supported: the session-scoped
  // topics are 12 to 20 bytes, so an alias saves almost nothing and would
  // add per-session state to a bridge that deliberately has none.
  properties.topic_alias_max = Some(0);
  properties.wildcard_subscription_available = Some(true);
  properties.subscription_id_available = Some(false);
  properties.shared_subscription_available = Some(false);
  properties.server_keep_alive = Some(server_keep_alive);
  properties
}

fn connect_reason_code(outcome: ConnackOutcome) -> v5::ConnectReasonCode {
  match outcome {
    ConnackOutcome::Accepted => v5::ConnectReasonCode::Success,
    ConnackOutcome::BadCredentials => v5::ConnectReasonCode::BadUserNameOrPassword,
    ConnackOutcome::NotAuthorized => v5::ConnectReasonCode::NotAuthorized,
    ConnackOutcome::ServerUnavailable => v5::ConnectReasonCode::ServerUnavailable,
    ConnackOutcome::ClientIdNotValid => v5::ConnectReasonCode::ClientIdentifierNotValid,
    ConnackOutcome::QuotaExceeded => v5::ConnectReasonCode::QuotaExceeded,
    ConnackOutcome::QoSNotSupported => v5::ConnectReasonCode::QoSNotSupported,
    ConnackOutcome::WillTopicInvalid => v5::ConnectReasonCode::TopicNameInvalid,
    ConnackOutcome::UnsupportedVersion => v5::ConnectReasonCode::UnsupportedProtocolVersion,
    ConnackOutcome::MalformedPacket => v5::ConnectReasonCode::MalformedPacket,
    ConnackOutcome::ServerBusy => v5::ConnectReasonCode::ServerBusy,
  }
}

fn puback_reason_code(outcome: AckOutcome) -> v5::PubackReasonCode {
  match outcome {
    AckOutcome::Success => v5::PubackReasonCode::Success,
    AckOutcome::PayloadFormatInvalid => v5::PubackReasonCode::PayloadFormatInvalid,
    AckOutcome::UnspecifiedError => v5::PubackReasonCode::UnspecifiedError,
    AckOutcome::QuotaExceeded => v5::PubackReasonCode::QuotaExceeded,
    AckOutcome::NotAuthorized => v5::PubackReasonCode::NotAuthorized,
  }
}

fn subscribe_reason_code(result: SubResult) -> v5::SubscribeReasonCode {
  match result {
    SubResult::GrantedQos0 => v5::SubscribeReasonCode::GrantedQoS0,
    SubResult::GrantedQos1 => v5::SubscribeReasonCode::GrantedQoS1,
    SubResult::NotAuthorized => v5::SubscribeReasonCode::NotAuthorized,
    SubResult::SharedNotSupported => v5::SubscribeReasonCode::SharedSubscriptionNotSupported,
  }
}

fn disconnect_reason_code(reason: DisconnectReason) -> v5::DisconnectReasonCode {
  match reason {
    DisconnectReason::NotAuthorized => v5::DisconnectReasonCode::NotAuthorized,
    DisconnectReason::ServerShuttingDown => v5::DisconnectReasonCode::ServerShuttingDown,
    DisconnectReason::KeepAliveTimeout => v5::DisconnectReasonCode::KeepAliveTimeout,
    DisconnectReason::SessionTakenOver => v5::DisconnectReasonCode::SessionTakenOver,
    DisconnectReason::TopicNameInvalid => v5::DisconnectReasonCode::TopicNameInvalid,
    DisconnectReason::ReceiveMaximumExceeded => v5::DisconnectReasonCode::ReceiveMaximumExceeded,
    DisconnectReason::TopicAliasInvalid => v5::DisconnectReasonCode::TopicAliasInvalid,
    DisconnectReason::PacketTooLarge => v5::DisconnectReasonCode::PacketTooLarge,
    DisconnectReason::MessageRateTooHigh => v5::DisconnectReasonCode::MessageRateTooHigh,
    DisconnectReason::QuotaExceeded => v5::DisconnectReasonCode::QuotaExceeded,
    DisconnectReason::QoSNotSupported => v5::DisconnectReasonCode::QoSNotSupported,
    DisconnectReason::ProtocolError => v5::DisconnectReasonCode::ProtocolError,
    DisconnectReason::MalformedPacket => v5::DisconnectReasonCode::MalformedPacket,
    DisconnectReason::ServerBusy => v5::DisconnectReasonCode::ServerBusy,
  }
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

  async fn raw_from(wire: Vec<u8>) -> RawPacket {
    let mut slice = wire.as_slice();
    pigeonhole_wire::framing::read_packet(&mut slice)
      .await
      .expect("frames")
  }

  async fn round_trip(packet: &v5::Packet) -> Inbound {
    let wire = packet.encode().expect("encodes").as_ref().to_vec();
    decode(&raw_from(wire).await).expect("decodes")
  }

  async fn encoded_connack(outcome: ConnackOutcome) -> v5::Connack {
    let wire = encode(&Outbound::Connack {
      outcome,
      server_keep_alive: 300,
      receive_max: limits::RECEIVE_MAXIMUM,
      reason: None,
    })
    .expect("encodes")
    .expect("v5 always answers");
    match raw_from(wire).await.decode_v5().expect("decodes") {
      v5::Packet::Connack(connack) => connack,
      other => panic!("expected a connack, got {other:?}"),
    }
  }

  #[tokio::test]
  async fn an_accepted_connack_advertises_maximum_qos_1_and_no_aliases() {
    let connack = encoded_connack(ConnackOutcome::Accepted).await;
    assert_eq!(connack.reason_code, v5::ConnectReasonCode::Success);
    assert!(!connack.session_present, "sessions are stateless");
    assert_eq!(connack.properties.max_qos, Some(QoS::Level1));
    assert_eq!(connack.properties.topic_alias_max, Some(0));
    assert_eq!(
      connack.properties.shared_subscription_available,
      Some(false)
    );
    assert_eq!(connack.properties.session_expiry_interval, Some(0));
    assert_eq!(connack.properties.server_keep_alive, Some(300));
    assert_eq!(
      connack.properties.receive_max,
      Some(limits::RECEIVE_MAXIMUM)
    );
    assert_eq!(
      connack.properties.max_packet_size,
      Some(limits::MAX_PACKET_BYTES as u32)
    );
  }

  #[tokio::test]
  async fn a_refused_connack_carries_no_negotiated_limits() {
    let connack = encoded_connack(ConnackOutcome::BadCredentials).await;
    assert_eq!(
      connack.reason_code,
      v5::ConnectReasonCode::BadUserNameOrPassword
    );
    assert_eq!(
      connack.properties.max_qos, None,
      "a refusal negotiates nothing"
    );
  }

  #[tokio::test]
  async fn a_spent_allowance_is_quota_exceeded_not_a_credential_failure() {
    let connack = encoded_connack(ConnackOutcome::QuotaExceeded).await;
    assert_eq!(connack.reason_code, v5::ConnectReasonCode::QuotaExceeded);
  }

  #[tokio::test]
  async fn every_refusal_this_version_has_is_expressible() {
    for outcome in [
      ConnackOutcome::BadCredentials,
      ConnackOutcome::NotAuthorized,
      ConnackOutcome::ServerUnavailable,
      ConnackOutcome::ClientIdNotValid,
      ConnackOutcome::QuotaExceeded,
      ConnackOutcome::QoSNotSupported,
      ConnackOutcome::WillTopicInvalid,
      ConnackOutcome::UnsupportedVersion,
      ConnackOutcome::MalformedPacket,
      ConnackOutcome::ServerBusy,
    ] {
      let encoded = encode(&Outbound::Connack {
        outcome,
        server_keep_alive: 60,
        receive_max: 16,
        reason: None,
      })
      .expect("encodes");
      assert!(encoded.is_some(), "{outcome:?} must reach the client on v5");
    }
  }

  #[tokio::test]
  async fn a_fuse_refusal_is_acked_with_its_reason_so_the_session_survives() {
    let wire = encode(&Outbound::Puback {
      pid: 7,
      outcome: AckOutcome::QuotaExceeded,
    })
    .expect("encodes")
    .expect("v5 acks with a reason");
    match raw_from(wire).await.decode_v5().expect("decodes") {
      v5::Packet::Puback(puback) => {
        assert_eq!(puback.reason_code, v5::PubackReasonCode::QuotaExceeded);
        assert_eq!(puback.pid.value(), 7);
      }
      other => panic!("expected a puback, got {other:?}"),
    }
  }

  #[tokio::test]
  async fn a_shared_filter_is_refused_with_its_own_reason_code() {
    let wire = encode(&Outbound::Suback {
      pid: 2,
      results: vec![SubResult::SharedNotSupported, SubResult::NotAuthorized],
    })
    .expect("encodes")
    .expect("a suback is sent");
    match raw_from(wire).await.decode_v5().expect("decodes") {
      v5::Packet::Suback(suback) => assert_eq!(
        suback.topics,
        vec![
          v5::SubscribeReasonCode::SharedSubscriptionNotSupported,
          v5::SubscribeReasonCode::NotAuthorized
        ]
      ),
      other => panic!("expected a suback, got {other:?}"),
    }
  }

  #[tokio::test]
  async fn a_topic_alias_survives_decoding_so_it_can_be_refused_as_a_protocol_error() {
    let event = round_trip(&v5::Packet::Publish(v5::Publish {
      dup: false,
      retain: false,
      qos_pid: QosPid::Level0,
      topic_name: TopicName::try_from(pigeonhole_wire::topics::TELEMETRY).expect("topic"),
      payload: b"{}".as_slice().into(),
      properties: v5::PublishProperties {
        topic_alias: Some(3),
        ..Default::default()
      },
    }))
    .await;
    match event {
      Inbound::Publish(publish) => assert_eq!(publish.topic_alias, Some(3)),
      other => panic!("expected a publish, got {other:?}"),
    }
  }

  #[tokio::test]
  async fn a_disconnect_can_ask_for_the_will_on_this_version() {
    let with_will = round_trip(&v5::Packet::Disconnect(v5::Disconnect {
      reason_code: v5::DisconnectReasonCode::DisconnectWithWillMessage,
      properties: Default::default(),
    }))
    .await;
    assert!(matches!(
      with_will,
      Inbound::Disconnect { deliver_will: true }
    ));

    let plain = round_trip(&v5::Packet::Disconnect(v5::Disconnect {
      reason_code: v5::DisconnectReasonCode::NormalDisconnect,
      properties: Default::default(),
    }))
    .await;
    assert!(matches!(
      plain,
      Inbound::Disconnect {
        deliver_will: false
      }
    ));
  }

  #[tokio::test]
  async fn an_auth_packet_is_unexpected_rather_than_starting_an_exchange() {
    let event = round_trip(&v5::Packet::Auth(v5::Auth {
      reason_code: v5::AuthReasonCode::ContinueAuthentication,
      properties: Default::default(),
    }))
    .await;
    assert!(matches!(event, Inbound::Unexpected(_)));
  }

  #[tokio::test]
  async fn a_qos2_publish_decodes_so_the_session_can_answer_0x9b() {
    let event = round_trip(&v5::Packet::Publish(v5::Publish {
      dup: false,
      retain: false,
      qos_pid: QosPid::Level2(mqtt_proto::Pid::try_from(9).expect("pid")),
      topic_name: TopicName::try_from(pigeonhole_wire::topics::TELEMETRY).expect("topic"),
      payload: b"{}".as_slice().into(),
      properties: Default::default(),
    }))
    .await;
    match event {
      Inbound::Publish(publish) => assert_eq!(publish.qos, 2),
      other => panic!("expected a publish, got {other:?}"),
    }
  }

  #[tokio::test]
  async fn a_takeover_disconnect_names_itself() {
    let wire = encode(&Outbound::Disconnect {
      reason: DisconnectReason::SessionTakenOver,
      text: None,
    })
    .expect("encodes")
    .expect("v5 says why");
    match raw_from(wire).await.decode_v5().expect("decodes") {
      v5::Packet::Disconnect(disconnect) => assert_eq!(
        disconnect.reason_code,
        v5::DisconnectReasonCode::SessionTakenOver
      ),
      other => panic!("expected a disconnect, got {other:?}"),
    }
  }

  #[tokio::test]
  async fn a_revocation_disconnect_can_carry_the_reason_in_words() {
    let wire = encode(&Outbound::Disconnect {
      reason: DisconnectReason::NotAuthorized,
      text: Some("pigeon deleted"),
    })
    .expect("encodes")
    .expect("v5 says why");
    match raw_from(wire).await.decode_v5().expect("decodes") {
      v5::Packet::Disconnect(disconnect) => {
        assert_eq!(
          disconnect.reason_code,
          v5::DisconnectReasonCode::NotAuthorized
        );
        assert_eq!(
          disconnect.properties.reason_string.as_deref(),
          Some("pigeon deleted")
        );
      }
      other => panic!("expected a disconnect, got {other:?}"),
    }
  }
}
