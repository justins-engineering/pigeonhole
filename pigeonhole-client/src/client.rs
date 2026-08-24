//! The typed client. `PigeonClient::connect` takes a pigeon's id, the broker
//! endpoint (`mqtts://host:8883`) and either a bearer token (certificate
//! mode: username = id, password = token) or a PSK pair, runs
//! CONNECT/CONNACK, keeps the session alive, and tracks QoS 1 publishes to
//! their PUBACK.
//!
//! Typed operations mirror the device routes one to one, because the topics
//! do: `report_telemetry`, `report_shadow`, `upload_log_chunk`, and
//! `subscribe_shadow_target`, whose stream yields each retained or pushed
//! shadow as the raw JSON the platform sent alongside its parsed form.
//!
//! Backoff and reconnection are the caller's policy. This layer reports a
//! dropped session rather than hiding it, which is the honest shape for a
//! bridge whose whole contract says redelivery is the client's.

use std::collections::HashMap;
use std::time::Duration;

use bytes::Bytes;
use mqtt_proto::{Protocol, QoS, QosPid, TopicFilter, TopicName, v3, v5};
use pigeonhole_wire::framing::{self, RawPacket};
use pigeonhole_wire::payload::{Metrics, PigeonShadow, ShadowReport};
use pigeonhole_wire::topics;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio_openssl::SslStream;

use crate::raw::{Endpoint, RawConnection, Transport};
use crate::{ClientError, raw};

/// Which version to speak. MQTT 5 is the platform's primary target; 3.1.1 is
/// what the Zephyr device library speaks today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
  V311,
  V500,
}

impl ProtocolVersion {
  fn protocol(self) -> Protocol {
    match self {
      ProtocolVersion::V311 => Protocol::V311,
      ProtocolVersion::V500 => Protocol::V500,
    }
  }
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
  pub endpoint: Endpoint,
  pub transport: Transport,
  pub pigeon_id: String,
  /// The CONNECT password. Required in certificate mode, ignored in PSK
  /// mode, where the handshake already resolved it.
  pub token: Option<String>,
  pub version: ProtocolVersion,
  pub keep_alive: u16,
}

impl ClientConfig {
  /// Certificate mode against a broker, with the system trust store.
  pub fn certificate(endpoint: Endpoint, pigeon_id: String, token: String) -> ClientConfig {
    ClientConfig {
      endpoint,
      transport: Transport::certificate(),
      pigeon_id,
      token: Some(token),
      version: ProtocolVersion::V500,
      keep_alive: 60,
    }
  }

  /// PSK mode, where the identity is the pigeon id and the key is the raw
  /// UTF-8 of its `tls_psk_secret`.
  pub fn psk(endpoint: Endpoint, pigeon_id: String, secret: String) -> ClientConfig {
    ClientConfig {
      endpoint,
      transport: Transport::Psk {
        identity: pigeon_id.clone(),
        secret,
      },
      pigeon_id,
      token: None,
      version: ProtocolVersion::V500,
      keep_alive: 60,
    }
  }
}

/// One shadow as the platform sent it. The raw bytes are kept because they
/// are what the broker retained: the parsed form is a convenience over them,
/// not a replacement.
#[derive(Debug, Clone)]
pub struct Shadow {
  pub raw: Bytes,
  pub parsed: PigeonShadow,
}

/// Retained and pushed shadow targets, in arrival order.
#[derive(Debug)]
pub struct ShadowStream(mpsc::Receiver<Shadow>);

impl ShadowStream {
  /// `None` once the session has ended.
  pub async fn next(&mut self) -> Option<Shadow> {
    self.0.recv().await
  }
}

#[derive(Debug)]
pub struct PigeonClient {
  commands: mpsc::Sender<Command>,
}

#[derive(Debug)]
enum Command {
  Publish {
    topic: &'static str,
    payload: Bytes,
    qos: u8,
    acked: Option<oneshot::Sender<Result<(), ClientError>>>,
  },
  Subscribe {
    qos: u8,
    acked: oneshot::Sender<Result<(), ClientError>>,
  },
  Disconnect,
}

impl PigeonClient {
  /// Connects, authenticates, and leaves a live session behind. The stream
  /// yields shadow targets once `subscribe_shadow_target` has been called.
  pub async fn connect(config: ClientConfig) -> Result<(PigeonClient, ShadowStream), ClientError> {
    let mut connection = RawConnection::connect(&config.endpoint, &config.transport).await?;
    send_connect(&mut connection, &config).await?;
    read_connack(&mut connection, config.version).await?;

    let (read, write) = connection.split();
    let (command_tx, command_rx) = mpsc::channel(32);
    let (shadow_tx, shadow_rx) = mpsc::channel(16);

    tokio::spawn(run(
      Session {
        version: config.version,
        keep_alive: config.keep_alive,
        next_pid: 0,
        pending: HashMap::new(),
      },
      read,
      write,
      command_rx,
      shadow_tx,
    ));

    Ok((
      PigeonClient {
        commands: command_tx,
      },
      ShadowStream(shadow_rx),
    ))
  }

  /// Publishes one telemetry report. At QoS 1 this returns when the broker
  /// acknowledges it, which means the platform accepted it; at QoS 0 it
  /// returns once the packet is on the wire.
  pub async fn report_telemetry(&self, metrics: &Metrics, qos: u8) -> Result<(), ClientError> {
    let payload =
      serde_json::to_vec(metrics).map_err(|e| ClientError::Codec(format!("telemetry: {e}")))?;
    self.publish(topics::TELEMETRY, payload.into(), qos).await
  }

  /// Confirms the device applied a target config.
  pub async fn report_shadow(&self, report: &ShadowReport, qos: u8) -> Result<(), ClientError> {
    let payload =
      serde_json::to_vec(report).map_err(|e| ClientError::Codec(format!("shadow report: {e}")))?;
    self
      .publish(topics::SHADOW_REPORT, payload.into(), qos)
      .await
  }

  /// Uploads one dictionary-log chunk. The bytes are opaque and go up as
  /// they are.
  pub async fn upload_log_chunk(&self, chunk: &[u8], qos: u8) -> Result<(), ClientError> {
    self
      .publish(topics::LOGS, Bytes::copy_from_slice(chunk), qos)
      .await
  }

  /// Subscribes to the retained shadow target. The current value arrives on
  /// the stream immediately after, which is what "retained" means here.
  pub async fn subscribe_shadow_target(&self, qos: u8) -> Result<(), ClientError> {
    let (acked, wait) = oneshot::channel();
    self
      .commands
      .send(Command::Subscribe { qos, acked })
      .await
      .map_err(|_| ClientError::Closed)?;
    wait.await.map_err(|_| ClientError::Closed)?
  }

  /// Says goodbye, which also tells the broker to discard any will.
  pub async fn disconnect(self) -> Result<(), ClientError> {
    self
      .commands
      .send(Command::Disconnect)
      .await
      .map_err(|_| ClientError::Closed)
  }

  async fn publish(&self, topic: &'static str, payload: Bytes, qos: u8) -> Result<(), ClientError> {
    if qos > 1 {
      return Err(ClientError::Protocol(
        "this platform offers QoS 0 and 1".to_string(),
      ));
    }
    let (acked, wait) = if qos == 0 {
      (None, None)
    } else {
      let (tx, rx) = oneshot::channel();
      (Some(tx), Some(rx))
    };
    self
      .commands
      .send(Command::Publish {
        topic,
        payload,
        qos,
        acked,
      })
      .await
      .map_err(|_| ClientError::Closed)?;
    match wait {
      Some(wait) => wait.await.map_err(|_| ClientError::Closed)?,
      None => Ok(()),
    }
  }
}

async fn send_connect(
  connection: &mut RawConnection,
  config: &ClientConfig,
) -> Result<(), ClientError> {
  // The password is the device token in certificate mode. In PSK mode the
  // handshake already resolved the pigeon's credentials, so the broker
  // ignores whatever is here.
  let password = config
    .token
    .as_ref()
    .map(|token| Bytes::copy_from_slice(token.as_bytes()));

  match config.version {
    ProtocolVersion::V311 => {
      connection
        .send_v3(&v3::Packet::Connect(v3::Connect {
          protocol: config.version.protocol(),
          clean_session: true,
          keep_alive: config.keep_alive,
          client_id: config.pigeon_id.as_str().into(),
          last_will: None,
          username: Some(config.pigeon_id.as_str().into()),
          password,
        }))
        .await
    }
    ProtocolVersion::V500 => {
      connection
        .send_v5(&v5::Packet::Connect(v5::Connect {
          protocol: config.version.protocol(),
          clean_start: true,
          keep_alive: config.keep_alive,
          properties: Default::default(),
          client_id: config.pigeon_id.as_str().into(),
          last_will: None,
          username: Some(config.pigeon_id.as_str().into()),
          password,
        }))
        .await
    }
  }
}

async fn read_connack(
  connection: &mut RawConnection,
  version: ProtocolVersion,
) -> Result<(), ClientError> {
  let raw = connection
    .recv_within(Duration::from_secs(30))
    .await?
    .ok_or(ClientError::Timeout("CONNACK"))?;
  match version {
    ProtocolVersion::V311 => match raw.decode_v3()? {
      v3::Packet::Connack(connack) => match connack.code {
        v3::ConnectReturnCode::Accepted => Ok(()),
        other => Err(ClientError::Refused(format!("{other:?}"))),
      },
      other => Err(ClientError::Protocol(format!(
        "expected a CONNACK, got {other:?}"
      ))),
    },
    ProtocolVersion::V500 => match raw.decode_v5()? {
      v5::Packet::Connack(connack) => match connack.reason_code {
        v5::ConnectReasonCode::Success => Ok(()),
        other => Err(ClientError::Refused(
          match connack.properties.reason_string {
            // The broker says why in words where a code alone would be
            // ambiguous, and passing that through is most of why v5 is worth
            // speaking.
            Some(reason) => format!("{other:?}: {reason}"),
            None => format!("{other:?}"),
          },
        )),
      },
      other => Err(ClientError::Protocol(format!(
        "expected a CONNACK, got {other:?}"
      ))),
    },
  }
}

struct Session {
  version: ProtocolVersion,
  keep_alive: u16,
  next_pid: u16,
  pending: HashMap<u16, oneshot::Sender<Result<(), ClientError>>>,
}

impl Session {
  fn pid(&mut self) -> u16 {
    self.next_pid = self.next_pid.wrapping_add(1);
    if self.next_pid == 0 {
      self.next_pid = 1;
    }
    self.next_pid
  }
}

async fn run(
  mut session: Session,
  mut read: ReadHalf<SslStream<TcpStream>>,
  mut write: WriteHalf<SslStream<TcpStream>>,
  mut commands: mpsc::Receiver<Command>,
  shadows: mpsc::Sender<Shadow>,
) {
  // Half the negotiated keepalive, so one lost PINGRESP does not cost the
  // session.
  let ping_every = Duration::from_secs(u64::from(session.keep_alive).max(2) / 2);
  let mut ping = tokio::time::interval(ping_every);
  ping.tick().await;

  let ended: Result<(), ClientError> = loop {
    tokio::select! {
      command = commands.recv() => match command {
        None => break Ok(()),
        Some(Command::Disconnect) => {
          let _ = write_disconnect(&mut write, &session).await;
          break Ok(());
        }
        Some(Command::Publish { topic, payload, qos, acked }) => {
          let pid = if qos == 0 { None } else { Some(session.pid()) };
          if let Err(e) = write_publish(&mut write, &session, topic, &payload, qos, pid).await {
            if let Some(acked) = acked {
              let _ = acked.send(Err(e));
            }
            break Err(ClientError::Closed);
          }
          if let (Some(pid), Some(acked)) = (pid, acked) {
            session.pending.insert(pid, acked);
          }
        }
        Some(Command::Subscribe { qos, acked }) => {
          let pid = session.pid();
          if let Err(e) = write_subscribe(&mut write, &session, qos, pid).await {
            let _ = acked.send(Err(e));
            break Err(ClientError::Closed);
          }
          session.pending.insert(pid, acked);
        }
      },

      packet = framing::read_packet(&mut read) => match packet {
        Err(e) => break Err(ClientError::Framing(e)),
        Ok(raw) => {
          if let Err(e) = handle(&mut session, &raw, &shadows).await {
            break Err(e);
          }
        }
      },

      _ = ping.tick() => {
        if write_ping(&mut write, &session).await.is_err() {
          break Err(ClientError::Closed);
        }
      },
    }
  };

  // Whatever was waiting for an acknowledgement is not getting one. Telling
  // each caller is the point of the session reporting a drop rather than
  // hiding it.
  let reason = match ended {
    Ok(()) => ClientError::Closed,
    Err(e) => e,
  };
  for (_, acked) in session.pending.drain() {
    let _ = acked.send(Err(ClientError::Protocol(format!(
      "session ended before the acknowledgement: {reason}"
    ))));
  }
}

async fn handle(
  session: &mut Session,
  raw: &RawPacket,
  shadows: &mpsc::Sender<Shadow>,
) -> Result<(), ClientError> {
  match session.version {
    ProtocolVersion::V311 => match raw.decode_v3()? {
      v3::Packet::Puback(pid) => resolve(session, pid.value(), Ok(())),
      v3::Packet::Suback(suback) => {
        let pid = suback.pid.value();
        let granted = suback
          .topics
          .iter()
          .any(|code| !matches!(code, v3::SubscribeReturnCode::Failure));
        resolve(
          session,
          pid,
          if granted {
            Ok(())
          } else {
            Err(ClientError::Refused("subscription refused".to_string()))
          },
        );
      }
      v3::Packet::Publish(publish) => deliver(shadows, publish.payload).await,
      v3::Packet::Pingresp => {}
      other => {
        return Err(ClientError::Protocol(format!(
          "unexpected packet from the broker: {other:?}"
        )));
      }
    },
    ProtocolVersion::V500 => match raw.decode_v5()? {
      v5::Packet::Puback(puback) => {
        let outcome = match puback.reason_code {
          v5::PubackReasonCode::Success | v5::PubackReasonCode::NoMatchingSubscribers => Ok(()),
          other => Err(ClientError::Refused(format!("{other:?}"))),
        };
        resolve(session, puback.pid.value(), outcome);
      }
      v5::Packet::Suback(suback) => {
        let pid = suback.pid.value();
        let granted = suback.topics.iter().any(|code| {
          matches!(
            code,
            v5::SubscribeReasonCode::GrantedQoS0
              | v5::SubscribeReasonCode::GrantedQoS1
              | v5::SubscribeReasonCode::GrantedQoS2
          )
        });
        resolve(
          session,
          pid,
          if granted {
            Ok(())
          } else {
            Err(ClientError::Refused(format!("{:?}", suback.topics)))
          },
        );
      }
      v5::Packet::Publish(publish) => deliver(shadows, publish.payload).await,
      v5::Packet::Pingresp => {}
      v5::Packet::Disconnect(disconnect) => {
        return Err(ClientError::Refused(
          match disconnect.properties.reason_string {
            Some(reason) => format!("{:?}: {reason}", disconnect.reason_code),
            None => format!("{:?}", disconnect.reason_code),
          },
        ));
      }
      other => {
        return Err(ClientError::Protocol(format!(
          "unexpected packet from the broker: {other:?}"
        )));
      }
    },
  }
  Ok(())
}

fn resolve(session: &mut Session, pid: u16, outcome: Result<(), ClientError>) {
  if let Some(acked) = session.pending.remove(&pid) {
    let _ = acked.send(outcome);
  }
}

async fn deliver(shadows: &mpsc::Sender<Shadow>, payload: Bytes) {
  match serde_json::from_slice::<PigeonShadow>(&payload) {
    Ok(parsed) => {
      let _ = shadows
        .send(Shadow {
          raw: payload,
          parsed,
        })
        .await;
    }
    Err(e) => tracing::warn!(error = %e, "a shadow arrived that did not parse"),
  }
}

async fn write_publish(
  write: &mut WriteHalf<SslStream<TcpStream>>,
  session: &Session,
  topic: &str,
  payload: &Bytes,
  qos: u8,
  pid: Option<u16>,
) -> Result<(), ClientError> {
  let qos_pid = match (qos, pid) {
    (0, _) => QosPid::Level0,
    (1, Some(pid)) => {
      QosPid::Level1(mqtt_proto::Pid::try_from(pid).map_err(|e| ClientError::Codec(e.to_string()))?)
    }
    _ => return Err(ClientError::Protocol("QoS 1 needs a packet id".to_string())),
  };
  let topic_name = TopicName::try_from(topic).map_err(|e| ClientError::Codec(e.to_string()))?;
  let bytes = match session.version {
    ProtocolVersion::V311 => v3::Packet::Publish(v3::Publish {
      dup: false,
      retain: false,
      qos_pid,
      topic_name,
      payload: payload.clone(),
    })
    .encode()
    .map_err(|e| ClientError::Codec(e.to_string()))?,
    ProtocolVersion::V500 => v5::Packet::Publish(v5::Publish {
      dup: false,
      retain: false,
      qos_pid,
      topic_name,
      payload: payload.clone(),
      properties: Default::default(),
    })
    .encode()
    .map_err(|e| ClientError::Codec(e.to_string()))?,
  };
  framing::write_packet(write, bytes.as_ref()).await?;
  Ok(())
}

async fn write_subscribe(
  write: &mut WriteHalf<SslStream<TcpStream>>,
  session: &Session,
  qos: u8,
  pid: u16,
) -> Result<(), ClientError> {
  let pid = mqtt_proto::Pid::try_from(pid).map_err(|e| ClientError::Codec(e.to_string()))?;
  let filter =
    TopicFilter::try_from(topics::SHADOW_TARGET).map_err(|e| ClientError::Codec(e.to_string()))?;
  let qos = QoS::from_u8(qos.min(1)).map_err(|e| ClientError::Codec(e.to_string()))?;
  let bytes = match session.version {
    ProtocolVersion::V311 => v3::Packet::Subscribe(v3::Subscribe {
      pid,
      topics: vec![(filter, qos)],
    })
    .encode()
    .map_err(|e| ClientError::Codec(e.to_string()))?,
    ProtocolVersion::V500 => v5::Packet::Subscribe(v5::Subscribe {
      pid,
      properties: Default::default(),
      topics: vec![(
        filter,
        v5::SubscriptionOptions {
          max_qos: qos,
          no_local: false,
          retain_as_published: false,
          retain_handling: v5::RetainHandling::SendAtSubscribe,
        },
      )],
    })
    .encode()
    .map_err(|e| ClientError::Codec(e.to_string()))?,
  };
  framing::write_packet(write, bytes.as_ref()).await?;
  Ok(())
}

async fn write_ping(
  write: &mut WriteHalf<SslStream<TcpStream>>,
  session: &Session,
) -> Result<(), ClientError> {
  let bytes = match session.version {
    ProtocolVersion::V311 => v3::Packet::Pingreq.encode(),
    ProtocolVersion::V500 => v5::Packet::Pingreq.encode(),
  }
  .map_err(|e| ClientError::Codec(e.to_string()))?;
  framing::write_packet(write, bytes.as_ref()).await?;
  Ok(())
}

async fn write_disconnect(
  write: &mut WriteHalf<SslStream<TcpStream>>,
  session: &Session,
) -> Result<(), ClientError> {
  let bytes = match session.version {
    ProtocolVersion::V311 => v3::Packet::Disconnect.encode(),
    ProtocolVersion::V500 => v5::Packet::Disconnect(v5::Disconnect {
      reason_code: v5::DisconnectReasonCode::NormalDisconnect,
      properties: Default::default(),
    })
    .encode(),
  }
  .map_err(|e| ClientError::Codec(e.to_string()))?;
  framing::write_packet(write, bytes.as_ref()).await?;
  Ok(())
}

/// Re-exported so a caller can build a config without naming the raw layer.
pub use raw::{Endpoint as ClientEndpoint, Transport as ClientTransport};
