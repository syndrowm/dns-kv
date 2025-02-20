use std::{
    collections::HashMap,
    io::Bytes,
    net::SocketAddr,
    sync::{Arc, LazyLock},
};

use tokio::net::UdpSocket;

use simple_dns::{
    rdata::{RData, A, AAAA, TXT},
    Packet, Question, ResourceRecord, CLASS, QTYPE, TYPE,
};

// Easy mode error handling.
type Result<T> = core::result::Result<T, Error>;
type Error = Box<dyn std::error::Error>;

#[allow(unused)]
type Database = HashMap<String, Bytes<u8>>;

#[allow(unused)]
static DATABASE: LazyLock<Arc<Database>> = LazyLock::new(|| Arc::new(HashMap::new()));

async fn parse_a_query(q: Question<'_>) -> Result<ResourceRecord<'_>> {
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
    let mut data = TXT::new();
    let _ = data.add_string("AAAA");
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
