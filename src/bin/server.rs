use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock},
};

use data_encoding::BASE32_NOPAD;
use dns_kv::Message;

use tokio::net::UdpSocket;

use simple_dns::{
    rdata::{RData, A, AAAA, TXT},
    Packet, Question, ResourceRecord, CLASS, QTYPE, TYPE,
};

// Easy mode error handling.
type Result<T> = core::result::Result<T, Error>;
type Error = Box<dyn std::error::Error>;

type Database = HashMap<String, String>;

static DATABASE: OnceLock<Mutex<Database>> = OnceLock::new();

fn get_value(key: &String) -> Option<String> {
    let mut db = DATABASE
        .get()
        .expect("Database not initialized")
        .lock()
        .expect("Failed to lock database");
    db.remove(key)
}

fn set_value(key: String, value: String) {
    let mut db = DATABASE
        .get()
        .expect("Database not initialized")
        .lock()
        .expect("Failed to lock database");
    db.insert(key, value);
}

fn append_value(key: String, value: String) {
    let mut db = DATABASE
        .get()
        .expect("Database not initialized")
        .lock()
        .expect("Failed to lock database");
    let mut current_value = db.remove(&key).unwrap_or_default();
    current_value.push_str(&value);
    tracing::debug!("{} {}", key.clone(), current_value.clone());
    db.insert(key, current_value);
}

async fn parse_a_query(q: Question<'_>) -> Result<ResourceRecord<'_>> {
    let key = q.qname.to_string().to_uppercase();
    tracing::info!("new a query: {key}");
    let value = get_value(&key).unwrap();

    let decoded = BASE32_NOPAD.decode(value.as_bytes())?;
    let msg: Message = bincode::deserialize(&decoded)?;

    set_value(msg.key.clone().to_uppercase(), value);

    tracing::info!("Set value {} {}", key.to_uppercase(), msg.key);
    Ok(ResourceRecord::new(
        q.qname,
        CLASS::IN,
        2,
        RData::A(A {
            address: u32::from_be_bytes([41, 41, 41, 41]),
        }),
    ))
}

async fn parse_aaaa_query(q: Question<'_>) -> Result<ResourceRecord<'_>> {
    let name = q.qname.to_string().to_uppercase();
    let parts: Vec<&str> = name.split(".").collect();
    if parts.len() < 2 {
        tracing::debug!("Not enough parts!");
        // TODO: handle some errors
        return Err("That did not work".into());
    }

    append_value(parts[1].to_string(), parts[0].to_string());

    Ok(ResourceRecord::new(
        q.qname.clone(),
        CLASS::IN,
        2,
        RData::AAAA(AAAA {
            address: u128::from_be_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 41, 41, 41, 41]),
        }),
    ))
}

async fn parse_txt_query(q: Question<'_>) -> Result<ResourceRecord<'_>> {
    let name = q.qname.to_string().to_uppercase();
    tracing::info!("Lookup {}", name);

    let value = get_value(&name).unwrap_or("AAAA".to_string());

    let len = value.clone().len().min(255);
    let (txt, remainder) = value.split_at(len);

    tracing::info!("Got value {}", value);

    if !remainder.is_empty() {
        set_value(name.clone(), remainder.to_string());
    } else {
        tracing::info!("No remaining info");
    };

    tracing::info!("returning {}", &value);

    let mut data = TXT::new();
    data.add_char_string(txt.to_string().try_into()?);
    Ok(ResourceRecord::new(
        q.qname.clone(),
        CLASS::IN,
        2,
        RData::TXT(data),
    ))
}

async fn handle_dns_query(socket: Arc<UdpSocket>, data: Vec<u8>, peer: SocketAddr) -> Result<()> {
    let packet = Packet::parse(&data)?;

    let mut response = packet.clone().into_reply();

    for q in packet.questions {
        let answer = match q.qtype {
            QTYPE::TYPE(TYPE::A) => Ok(parse_a_query(q).await?),
            QTYPE::TYPE(TYPE::AAAA) => Ok(parse_aaaa_query(q).await?),
            QTYPE::TYPE(TYPE::TXT) => Ok(parse_txt_query(q).await?),
            _ => Err("invalid type"),
        }?;

        response.answers.push(answer);
    }

    let rd = response.build_bytes_vec()?;
    socket.send_to(&rd, peer).await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(
            |_| format!("{}=debug", env!("CARGO_CRATE_NAME")),
        )))
        .try_init()?;

    DATABASE.get_or_init(|| Mutex::new(HashMap::new()));

    let socket = UdpSocket::bind("0.0.0.0:5353").await?;
    tracing::info!("listening on {}", socket.local_addr().unwrap());

    let socket = std::sync::Arc::new(socket);
    let mut buf = vec![0u8; 2048]; // max dns packet is 512

    loop {
        let socket = socket.clone();
        let (size, peer) = socket.recv_from(&mut buf).await?;
        let data = buf[..size].to_vec();
        // Spawn a new task for each incoming datagram
        tokio::spawn(async move {
            tracing::debug!("received {} bytes from {}", size, peer);
            let rv = handle_dns_query(socket, data, peer).await;
            if let Err(e) = rv {
                tracing::debug!("{e:?}");
            }
        });
    }
}
