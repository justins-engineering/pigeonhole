//! A real broker in-process against a mock dovecote.
//!
//! Nothing here is a stand-in for the broker: `pigeonhole::server::start`
//! binds a real TLS listener on an ephemeral port with a self-signed
//! certificate, and the tests drive it with the raw client over that
//! listener. What is mocked is the edge, and only so that the answers a
//! device route can give (including the ones a healthy platform never
//! gives) are reachable from a test.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use pigeonhole::config::Config;
use pigeonhole::server::Broker;
use pigeonhole_client::raw::{Endpoint, RawConnection, Transport};
use tokio::sync::broadcast;

/// A pigeon id has to be 64 lowercase hex to get past the local shape check.
pub const PIGEON: &str = "aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899";
pub const OTHER_PIGEON: &str = "bb11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899";
pub const TOKEN: &str = "a-device-bearer-token";
pub const PSK_SECRET: &str = "0123456789abcdef0123456789abcdef";
pub const SERVICE_SECRET: &str = "the-shared-service-secret";

/// What the mock was asked for, so a test can assert on the path a publish
/// actually took rather than only on what came back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedRequest {
  pub leaf: String,
  pub pigeon: String,
  pub content_type: String,
  pub body: Vec<u8>,
  pub bearer: Option<String>,
}

/// Something the test wants the live device socket to do.
#[derive(Debug, Clone)]
pub enum WsCommand {
  /// Push a `shadow_update` carrying this shadow.
  PushShadow(serde_json::Value),
  /// Send a `shell_cmd` the bridge is expected to answer.
  ShellCmd(String),
  /// Close with a Durable Object close code.
  Close(u16),
  /// Stop reading the socket entirely, so pings go unanswered. The only way
  /// to reach the liveness path, since a polled WebSocket auto-pongs.
  GoSilent,
}

#[derive(Default)]
pub struct Recording {
  pub requests: Mutex<Vec<RecordedRequest>>,
  /// Text frames the device socket received.
  pub frames: Mutex<Vec<String>>,
  /// How many times a device socket was upgraded.
  pub upgrades: AtomicUsize,
  /// Upgrade attempts, successful or not.
  pub upgrade_attempts: AtomicUsize,
}

pub struct MockState {
  pub telemetry_status: AtomicU16,
  pub shadow_status: AtomicU16,
  pub logs_status: AtomicU16,
  pub upgrade_status: AtomicU16,
  /// Body served with a refusal, which is what separates one of dovecote's
  /// own 403s from an edge-mitigation page.
  pub refusal_body: Mutex<String>,
  /// Held before answering a publish, so a test can stall upstream and
  /// watch the reader keep working.
  pub publish_delay: AtomicU64,
  pub shadow: Mutex<serde_json::Value>,
  /// Identity to (psk, token), for the internal credential route.
  pub psk_entries: Mutex<HashMap<String, (String, String)>>,
  pub valid_tokens: Mutex<HashSet<String>>,
  pub recording: Recording,
  commands: broadcast::Sender<WsCommand>,
}

impl MockState {
  fn new() -> Arc<MockState> {
    let (commands, _) = broadcast::channel(16);
    let mut psk_entries = HashMap::new();
    psk_entries.insert(
      PIGEON.to_string(),
      (PSK_SECRET.to_string(), TOKEN.to_string()),
    );
    let mut valid_tokens = HashSet::new();
    valid_tokens.insert(TOKEN.to_string());
    Arc::new(MockState {
      telemetry_status: AtomicU16::new(202),
      shadow_status: AtomicU16::new(200),
      logs_status: AtomicU16::new(200),
      upgrade_status: AtomicU16::new(101),
      refusal_body: Mutex::new("forbidden".to_string()),
      publish_delay: AtomicU64::new(0),
      shadow: Mutex::new(shadow_value(1)),
      psk_entries: Mutex::new(psk_entries),
      valid_tokens: Mutex::new(valid_tokens),
      recording: Recording::default(),
      commands,
    })
  }

  pub fn command(&self, command: WsCommand) {
    let _ = self.commands.send(command);
  }

  pub fn requests(&self) -> Vec<RecordedRequest> {
    self.recording.requests.lock().expect("lock").clone()
  }

  pub fn frames(&self) -> Vec<String> {
    self.recording.frames.lock().expect("lock").clone()
  }

  pub fn upgrades(&self) -> usize {
    self.recording.upgrades.load(Ordering::SeqCst)
  }

  pub fn set_shadow(&self, target_version: i32) {
    *self.shadow.lock().expect("lock") = shadow_value(target_version);
  }

  /// Waits for a condition the mock records, so a test never sleeps a fixed
  /// amount and hopes.
  pub async fn wait_for(&self, what: &str, mut ready: impl FnMut(&MockState) -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
      if ready(self) {
        return;
      }
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
  }
}

/// A shadow shaped exactly as `docs/api.md` documents it.
pub fn shadow_value(target_version: i32) -> serde_json::Value {
  serde_json::json!({
    "target_version": target_version,
    "current_version": 0,
    "target_config": "{\"telemetry_interval\":30}",
    "current_config": "{}",
    "updated_at": 1784390937_i64,
  })
}

/// A broker, its mock edge, and the dev certificate they were stood up with.
pub struct Harness {
  pub broker: Broker,
  pub state: Arc<MockState>,
  pub endpoint: Endpoint,
  ca_pem: PathBuf,
}

impl Harness {
  pub async fn start() -> Harness {
    let state = MockState::new();
    let mock_addr = spawn_mock(Arc::clone(&state)).await;

    let issued =
      rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("dev certificate");
    let cert_pem = write_temp("cert", &issued.cert.pem());
    let key_pem = write_temp("key", &issued.signing_key.serialize_pem());

    let config = Config {
      // Loopback only, and port zero so tests never collide.
      listen: "127.0.0.1:0".to_string(),
      dovecote_url: format!("http://{mock_addr}"),
      service_secret: SERVICE_SECRET.to_string(),
      tls_cert: cert_pem.clone(),
      tls_key: key_pem.clone(),
      // Short enough that a rotation test does not wait a minute.
      psk_cache_ttl: Duration::from_secs(60),
    };

    let broker = pigeonhole::server::start(config)
      .await
      .expect("broker starts");
    let endpoint = Endpoint {
      host: "127.0.0.1".to_string(),
      port: broker.local_addr.port(),
    };

    Harness {
      broker,
      state,
      endpoint,
      ca_pem: cert_pem,
    }
  }

  /// A connection in certificate mode, TLS complete and nothing MQTT sent.
  pub async fn connect(&self) -> RawConnection {
    RawConnection::connect(
      &self.endpoint,
      &Transport::Certificate {
        ca_pem: Some(self.ca_pem.clone()),
        server_name: Some("localhost".to_string()),
      },
    )
    .await
    .expect("tls connects")
  }

  /// A connection whose PSK handshake resolved through the mock's internal
  /// credential route.
  pub async fn connect_psk(&self, identity: &str, secret: &str) -> Result<RawConnection, String> {
    RawConnection::connect(
      &self.endpoint,
      &Transport::Psk {
        identity: identity.to_string(),
        secret: secret.to_string(),
      },
    )
    .await
    .map_err(|e| e.to_string())
  }

  pub async fn shutdown(self) {
    self.broker.shutdown().await;
  }
}

fn write_temp(kind: &str, contents: &str) -> PathBuf {
  static COUNTER: AtomicU64 = AtomicU64::new(0);
  let n = COUNTER.fetch_add(1, Ordering::Relaxed);
  let path = std::env::temp_dir().join(format!(
    "pigeonhole-harness-{}-{n}-{kind}.pem",
    std::process::id()
  ));
  std::fs::write(&path, contents).expect("write pem");
  path
}

async fn spawn_mock(state: Arc<MockState>) -> SocketAddr {
  let app = Router::new()
    .route("/device/pigeons/{pigeon}/telemetry", post(telemetry))
    .route("/device/pigeons/{pigeon}/shadow", post(shadow_report))
    .route("/device/pigeons/{pigeon}/logs", post(logs))
    .route("/device/pigeons/{pigeon}/ws", get(device_socket))
    .route("/internal/device-psk/{identity}", get(device_psk))
    .with_state(state);

  let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
    .await
    .expect("mock binds");
  let addr = listener.local_addr().expect("mock addr");
  tokio::spawn(async move {
    let _ = axum::serve(listener, app).await;
  });
  addr
}

async fn telemetry(
  State(state): State<Arc<MockState>>,
  Path(pigeon): Path<String>,
  headers: HeaderMap,
  body: Bytes,
) -> Response {
  device_route(state, "telemetry", pigeon, headers, body).await
}

async fn shadow_report(
  State(state): State<Arc<MockState>>,
  Path(pigeon): Path<String>,
  headers: HeaderMap,
  body: Bytes,
) -> Response {
  device_route(state, "shadow", pigeon, headers, body).await
}

async fn logs(
  State(state): State<Arc<MockState>>,
  Path(pigeon): Path<String>,
  headers: HeaderMap,
  body: Bytes,
) -> Response {
  device_route(state, "logs", pigeon, headers, body).await
}

async fn device_route(
  state: Arc<MockState>,
  leaf: &str,
  pigeon: String,
  headers: HeaderMap,
  body: Bytes,
) -> Response {
  let bearer = headers
    .get("authorization")
    .and_then(|v| v.to_str().ok())
    .and_then(|v| v.strip_prefix("Bearer "))
    .map(str::to_string);
  let content_type = headers
    .get("content-type")
    .and_then(|v| v.to_str().ok())
    .unwrap_or_default()
    .to_string();

  state
    .recording
    .requests
    .lock()
    .expect("lock")
    .push(RecordedRequest {
      leaf: leaf.to_string(),
      pigeon,
      content_type,
      body: body.to_vec(),
      bearer,
    });

  let delay = state.publish_delay.load(Ordering::SeqCst);
  if delay > 0 {
    tokio::time::sleep(Duration::from_millis(delay)).await;
  }

  let status = match leaf {
    "telemetry" => state.telemetry_status.load(Ordering::SeqCst),
    "shadow" => state.shadow_status.load(Ordering::SeqCst),
    _ => state.logs_status.load(Ordering::SeqCst),
  };
  let body = if status >= 400 {
    state.refusal_body.lock().expect("lock").clone()
  } else {
    String::new()
  };
  (StatusCode::from_u16(status).expect("status"), body).into_response()
}

async fn device_psk(
  State(state): State<Arc<MockState>>,
  Path(identity): Path<String>,
  headers: HeaderMap,
) -> Response {
  let authorized = headers
    .get("authorization")
    .and_then(|v| v.to_str().ok())
    .map(|v| v == format!("Bearer {SERVICE_SECRET}"))
    .unwrap_or(false);
  if !authorized {
    return (StatusCode::FORBIDDEN, "service secret").into_response();
  }
  match state.psk_entries.lock().expect("lock").get(&identity) {
    Some((secret, token)) => axum::Json(serde_json::json!({
      "identity": identity,
      "secret": secret,
      "token": token,
    }))
    .into_response(),
    None => (StatusCode::NOT_FOUND, "unknown identity").into_response(),
  }
}

async fn device_socket(
  State(state): State<Arc<MockState>>,
  Path(_pigeon): Path<String>,
  headers: HeaderMap,
  upgrade: WebSocketUpgrade,
) -> Response {
  state
    .recording
    .upgrade_attempts
    .fetch_add(1, Ordering::SeqCst);

  let forced = state.upgrade_status.load(Ordering::SeqCst);
  if forced != 101 {
    let body = state.refusal_body.lock().expect("lock").clone();
    return (StatusCode::from_u16(forced).expect("status"), body).into_response();
  }

  // The upgrade is the session's authentication, so a token the platform
  // does not know has to be refused here and nowhere else.
  let bearer = headers
    .get("authorization")
    .and_then(|v| v.to_str().ok())
    .and_then(|v| v.strip_prefix("Bearer "))
    .unwrap_or_default()
    .to_string();
  if !state.valid_tokens.lock().expect("lock").contains(&bearer) {
    return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
  }

  state.recording.upgrades.fetch_add(1, Ordering::SeqCst);
  let commands = state.commands.subscribe();
  upgrade.on_upgrade(move |socket| serve_socket(socket, state, commands))
}

async fn serve_socket(
  mut socket: WebSocket,
  state: Arc<MockState>,
  mut commands: broadcast::Receiver<WsCommand>,
) {
  // The snapshot every freshly accepted device socket gets, which is what
  // seeds the broker's retained value.
  let snapshot = state.shadow.lock().expect("lock").clone();
  let _ = socket
    .send(Message::Text(
      serde_json::json!({ "type": "shadow_update", "shadow": snapshot })
        .to_string()
        .into(),
    ))
    .await;

  loop {
    tokio::select! {
      command = commands.recv() => match command {
        Ok(WsCommand::PushShadow(shadow)) => {
          let _ = socket.send(Message::Text(
            serde_json::json!({ "type": "shadow_update", "shadow": shadow }).to_string().into(),
          )).await;
        }
        Ok(WsCommand::ShellCmd(request_id)) => {
          let _ = socket.send(Message::Text(
            serde_json::json!({
              "type": "shell_cmd",
              "request_id": request_id,
              "cmd": "pigeon shadow",
            }).to_string().into(),
          )).await;
        }
        Ok(WsCommand::Close(code)) => {
          let _ = socket.send(Message::Close(Some(axum::extract::ws::CloseFrame {
            code,
            reason: "harness".into(),
          }))).await;
          return;
        }
        // Stop reading, which is what makes a ping go unanswered: a polled
        // socket answers one automatically.
        Ok(WsCommand::GoSilent) => {
          std::future::pending::<()>().await;
        }
        Err(broadcast::error::RecvError::Lagged(_)) => {}
        Err(broadcast::error::RecvError::Closed) => return,
      },

      message = socket.recv() => match message {
        Some(Ok(Message::Text(text))) => {
          state.recording.frames.lock().expect("lock").push(text.to_string());
        }
        Some(Ok(_)) => {}
        Some(Err(_)) | None => return,
      },
    }
  }
}

// ---------------------------------------------------------------------------
// Driving both protocol versions through one test body.
//
// The matrices are written once and run twice. Where the two versions really
// differ (a reason code against a bare close) the test says so explicitly
// rather than being duplicated.
// ---------------------------------------------------------------------------

use mqtt_proto::{Protocol, QoS, QosPid, TopicFilter, TopicName, v3, v5};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V {
  V3,
  V5,
}

impl V {
  pub fn both() -> [V; 2] {
    [V::V5, V::V3]
  }

  pub fn name(self) -> &'static str {
    match self {
      V::V3 => "3.1.1",
      V::V5 => "5.0",
    }
  }

  /// Whether this version can say anything after CONNACK, or whether every
  /// refusal has to be a closed socket.
  pub fn can_signal(self) -> bool {
    self == V::V5
  }
}

/// What came back, flattened across the two versions so a test can assert
/// on the outcome rather than on a packet shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
  ConnackAccepted,
  ConnackRefused(u8),
  Puback {
    pid: u16,
    reason: u8,
  },
  Suback {
    pid: u16,
    codes: Vec<u8>,
  },
  Unsuback {
    pid: u16,
  },
  Pingresp,
  Publish {
    topic: String,
    payload: Vec<u8>,
    retain: bool,
  },
  Disconnect(u8),
  Closed,
}

pub struct Client {
  pub connection: RawConnection,
  pub version: V,
}

impl Client {
  pub async fn send_connect(
    &mut self,
    client_id: &str,
    username: Option<&str>,
    password: Option<&str>,
  ) {
    self
      .send_connect_full(client_id, username, password, 60, None)
      .await
  }

  pub async fn send_connect_full(
    &mut self,
    client_id: &str,
    username: Option<&str>,
    password: Option<&str>,
    keep_alive: u16,
    will: Option<(&str, &[u8], u8)>,
  ) {
    match self.version {
      V::V3 => {
        let packet = v3::Packet::Connect(v3::Connect {
          protocol: Protocol::V311,
          clean_session: true,
          keep_alive,
          client_id: client_id.into(),
          last_will: will.map(|(topic, payload, qos)| v3::LastWill {
            qos: QoS::from_u8(qos).expect("qos"),
            retain: false,
            topic_name: TopicName::try_from(topic).expect("will topic"),
            message: payload.to_vec().into(),
          }),
          username: username.map(|u| u.into()),
          password: password.map(|p| p.as_bytes().to_vec().into()),
        });
        self
          .connection
          .send_v3(&packet)
          .await
          .expect("sends connect");
      }
      V::V5 => {
        let packet = v5::Packet::Connect(v5::Connect {
          protocol: Protocol::V500,
          clean_start: true,
          keep_alive,
          properties: Default::default(),
          client_id: client_id.into(),
          last_will: will.map(|(topic, payload, qos)| v5::LastWill {
            qos: QoS::from_u8(qos).expect("qos"),
            retain: false,
            topic_name: TopicName::try_from(topic).expect("will topic"),
            payload: payload.to_vec().into(),
            properties: Default::default(),
          }),
          username: username.map(|u| u.into()),
          password: password.map(|p| p.as_bytes().to_vec().into()),
        });
        self
          .connection
          .send_v5(&packet)
          .await
          .expect("sends connect");
      }
    }
  }

  pub async fn publish(&mut self, topic: &str, payload: &[u8], qos: u8, pid: Option<u16>) {
    let qos_pid = match (qos, pid) {
      (0, _) => QosPid::Level0,
      (1, Some(pid)) => QosPid::Level1(mqtt_proto::Pid::try_from(pid).expect("pid")),
      (2, Some(pid)) => QosPid::Level2(mqtt_proto::Pid::try_from(pid).expect("pid")),
      _ => panic!("a QoS {qos} publish needs a packet id"),
    };
    match self.version {
      V::V3 => {
        let packet = v3::Packet::Publish(v3::Publish {
          dup: false,
          retain: false,
          qos_pid,
          topic_name: TopicName::try_from(topic).expect("topic"),
          payload: payload.to_vec().into(),
        });
        self
          .connection
          .send_v3(&packet)
          .await
          .expect("sends publish");
      }
      V::V5 => {
        let packet = v5::Packet::Publish(v5::Publish {
          dup: false,
          retain: false,
          qos_pid,
          topic_name: TopicName::try_from(topic).expect("topic"),
          payload: payload.to_vec().into(),
          properties: Default::default(),
        });
        self
          .connection
          .send_v5(&packet)
          .await
          .expect("sends publish");
      }
    }
  }

  pub async fn subscribe(&mut self, pid: u16, filters: &[(&str, u8)]) {
    let pid = mqtt_proto::Pid::try_from(pid).expect("pid");
    match self.version {
      V::V3 => {
        let packet = v3::Packet::Subscribe(v3::Subscribe {
          pid,
          topics: filters
            .iter()
            .map(|(filter, qos)| {
              (
                TopicFilter::try_from(*filter).expect("filter"),
                QoS::from_u8(*qos).expect("qos"),
              )
            })
            .collect(),
        });
        self
          .connection
          .send_v3(&packet)
          .await
          .expect("sends subscribe");
      }
      V::V5 => {
        let packet = v5::Packet::Subscribe(v5::Subscribe {
          pid,
          properties: Default::default(),
          topics: filters
            .iter()
            .map(|(filter, qos)| {
              (
                TopicFilter::try_from(*filter).expect("filter"),
                v5::SubscriptionOptions {
                  max_qos: QoS::from_u8(*qos).expect("qos"),
                  no_local: false,
                  retain_as_published: false,
                  retain_handling: v5::RetainHandling::SendAtSubscribe,
                },
              )
            })
            .collect(),
        });
        self
          .connection
          .send_v5(&packet)
          .await
          .expect("sends subscribe");
      }
    }
  }

  pub async fn ping(&mut self) {
    match self.version {
      V::V3 => self
        .connection
        .send_v3(&v3::Packet::Pingreq)
        .await
        .expect("ping"),
      V::V5 => self
        .connection
        .send_v5(&v5::Packet::Pingreq)
        .await
        .expect("ping"),
    }
  }

  pub async fn disconnect(&mut self) {
    match self.version {
      V::V3 => self
        .connection
        .send_v3(&v3::Packet::Disconnect)
        .await
        .expect("disconnect"),
      V::V5 => self
        .connection
        .send_v5(&v5::Packet::Disconnect(v5::Disconnect {
          reason_code: v5::DisconnectReasonCode::NormalDisconnect,
          properties: Default::default(),
        }))
        .await
        .expect("disconnect"),
    }
  }

  /// Reads the next thing the broker said, or `Closed` when it hung up.
  pub async fn next(&mut self) -> Answer {
    self.next_within(Duration::from_secs(10)).await
  }

  pub async fn next_within(&mut self, within: Duration) -> Answer {
    match self.connection.recv_within(within).await {
      Ok(None) => panic!("the broker said nothing within {within:?}"),
      Err(e) => {
        let framing = format!("{e}");
        if framing.contains("connection closed") || framing.contains("io:") {
          Answer::Closed
        } else {
          panic!("unexpected client error: {e}")
        }
      }
      Ok(Some(raw)) => match self.version {
        // A v3 SUBACK is read from its bytes: mqtt-proto's own encoder
        // writes the wrong byte for a failure entry and its decoder then
        // rejects one, so the broker hand-encodes SUBACK and this reads it
        // the same way.
        V::V3 if raw.packet_type() == 9 => {
          let body = raw.body();
          Answer::Suback {
            pid: u16::from_be_bytes([body[0], body[1]]),
            codes: body[2..].to_vec(),
          }
        }
        V::V3 => flatten_v3(raw.decode_v3().expect("decodes")),
        V::V5 => flatten_v5(raw.decode_v5().expect("decodes")),
      },
    }
  }

  /// `true` when the broker closed the connection, draining whatever it
  /// said first. The same assertion holds on both versions: on 5 there is a
  /// DISCONNECT before the close, and on 3.1.1 the close is the message.
  pub async fn closed(&mut self) -> bool {
    self
      .connection
      .closed_within(Duration::from_secs(10))
      .await
      .expect("waits for the close")
  }

  /// Drops the connection without an MQTT DISCONNECT: the ungraceful exit a
  /// will exists for.
  pub async fn abort(self) {
    self.connection.abort().await;
  }

  /// Asserts nothing arrives in the window. Used where the point is that
  /// the broker stayed quiet.
  pub async fn silent_for(&mut self, within: Duration) {
    match self.connection.recv_within(within).await {
      Ok(None) => {}
      Ok(Some(raw)) => panic!("expected silence, got packet type {}", raw.packet_type()),
      Err(e) => panic!("expected silence, got {e}"),
    }
  }
}

fn flatten_v3(packet: v3::Packet) -> Answer {
  match packet {
    v3::Packet::Connack(connack) => match connack.code {
      v3::ConnectReturnCode::Accepted => Answer::ConnackAccepted,
      other => Answer::ConnackRefused(other as u8),
    },
    v3::Packet::Puback(pid) => Answer::Puback {
      pid: pid.value(),
      reason: 0,
    },
    v3::Packet::Unsuback(pid) => Answer::Unsuback { pid: pid.value() },
    v3::Packet::Pingresp => Answer::Pingresp,
    v3::Packet::Publish(publish) => Answer::Publish {
      topic: publish.topic_name.to_string(),
      payload: publish.payload.to_vec(),
      retain: publish.retain,
    },
    other => panic!("unexpected v3 packet from the broker: {other:?}"),
  }
}

fn flatten_v5(packet: v5::Packet) -> Answer {
  match packet {
    v5::Packet::Connack(connack) => match connack.reason_code {
      v5::ConnectReasonCode::Success => Answer::ConnackAccepted,
      other => Answer::ConnackRefused(other as u8),
    },
    v5::Packet::Puback(puback) => Answer::Puback {
      pid: puback.pid.value(),
      reason: puback.reason_code as u8,
    },
    v5::Packet::Suback(suback) => Answer::Suback {
      pid: suback.pid.value(),
      codes: suback.topics.iter().map(|code| *code as u8).collect(),
    },
    v5::Packet::Unsuback(unsuback) => Answer::Unsuback {
      pid: unsuback.pid.value(),
    },
    v5::Packet::Pingresp => Answer::Pingresp,
    v5::Packet::Publish(publish) => Answer::Publish {
      topic: publish.topic_name.to_string(),
      payload: publish.payload.to_vec(),
      retain: publish.retain,
    },
    v5::Packet::Disconnect(disconnect) => Answer::Disconnect(disconnect.reason_code as u8),
    other => panic!("unexpected v5 packet from the broker: {other:?}"),
  }
}

impl Harness {
  /// A connection with a CONNECT sent and its CONNACK read.
  pub async fn session(&self, version: V) -> Client {
    let mut client = Client {
      connection: self.connect().await,
      version,
    };
    client.send_connect(PIGEON, Some(PIGEON), Some(TOKEN)).await;
    assert_eq!(
      client.next().await,
      Answer::ConnackAccepted,
      "{} session accepted",
      version.name()
    );
    client
  }

  /// A connection with nothing MQTT sent yet.
  pub async fn raw_session(&self, version: V) -> Client {
    Client {
      connection: self.connect().await,
      version,
    }
  }
}
