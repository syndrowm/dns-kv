use clap::{arg, command, Arg};
use data_encoding::BASE32_NOPAD;
use dns_kv::Message;
use rand::Rng;
use simple_dns::{rdata::RData, Name, Packet, PacketFlag, Question, CLASS, TYPE};
use tokio::net::UdpSocket;

// Easy mode error handling.
type Result<T> = core::result::Result<T, Error>;
type Error = Box<dyn std::error::Error>;

const MAX_FQDN: usize = 63;

fn txt_query_record(domain: &str) -> Result<Vec<u8>> {
    let mut pkt = Packet::new_query(1);
    let q = Question::new(
        Name::new_unchecked(domain),
        TYPE::TXT.into(),
        CLASS::IN.into(),
        false,
    );
    pkt.set_flags(PacketFlag::RECURSION_DESIRED);
    pkt.questions.push(q);
    Ok(pkt.build_bytes_vec()?)
}

fn parse_txt_response(data: Vec<u8>) -> Result<String> {
    let mut rv = String::new();
    let packet = Packet::parse(&data)?;
    let answer = packet.answers[0].clone();
    if let RData::TXT(val) = answer.rdata {
        for (k, _) in val.attributes() {
            rv += &k;
        }
    }
    Ok(rv)
}

fn a_query_record(domain: &str) -> Result<Vec<u8>> {
    let mut pkt = Packet::new_query(1);
    let q = Question::new(
        Name::new_unchecked(domain),
        TYPE::A.into(),
        CLASS::IN.into(),
        false,
    );
    pkt.set_flags(PacketFlag::RECURSION_DESIRED);
    pkt.questions.push(q);
    Ok(pkt.build_bytes_vec()?)
}

fn aaaa_query_record(domain: &str) -> Result<Vec<u8>> {
    let mut pkt = Packet::new_query(1);
    let q = Question::new(
        Name::new_unchecked(domain),
        TYPE::AAAA.into(),
        CLASS::IN.into(),
        false,
    );
    pkt.set_flags(PacketFlag::RECURSION_DESIRED);
    pkt.questions.push(q);
    Ok(pkt.build_bytes_vec()?)
}

async fn get_value(server: &str, key: &str) -> Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;

    let query = txt_query_record(key)?;
    let mut incoming = String::new();
    loop {
        sock.send_to(&query, server).await?;
        let mut buf = [0; 4096];
        let (size, _) = sock.recv_from(&mut buf).await?;
        let data = buf[..size].to_vec();
        let data = parse_txt_response(data)?;
        incoming += &data;
        if data.len() < 255 {
            break;
        }
    }

    let decoded = BASE32_NOPAD.decode(incoming.as_bytes())?;
    let message: Message = bincode::deserialize(&decoded)?;
    tracing::info!("value:\n{}", message.value);
    Ok(())
}

async fn set_value(server: &str, key: &str, value: &str) -> Result<()> {
    let id: u16 = rand::rng().random();
    let domain = format!(".{id:x}");
    let message = Message {
        key: key.to_string(),
        value: value.to_string(),
    };

    let sock = UdpSocket::bind("0.0.0.0:0").await?;

    let blob = bincode::serialize(&message)?;
    let encoded = BASE32_NOPAD.encode(&blob);
    for chunk in encoded.as_bytes().chunks(MAX_FQDN - domain.len()) {
        let chunk = String::from_utf8(chunk.to_vec()).unwrap();
        let fqdn = format!("{}{}", chunk, domain);
        let query = aaaa_query_record(&fqdn)?;
        sock.send_to(&query, server).await?;
        // TODO: Error handle
        let mut buf = [0; 4096];
        let (size, _) = sock.recv_from(&mut buf).await?;
        let _data = buf[..size].to_vec();
    }

    let query = a_query_record(&format!("{id:x}"))?;
    sock.send_to(&query, server).await?;
    // TODO: Error handle
    let mut buf = [0; 4096];
    let (size, _) = sock.recv_from(&mut buf).await?;
    let _data = buf[..size].to_vec();

    println!("Set the key: \"{}\" on the server!", key);

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

    let matches =
        command!() // requires `cargo` feature
            .arg(arg!([server] "DNS Server to query").default_value("127.0.0.1:5353"))
            .arg(arg!(-g --get <KEY> "Get the KEY value"))
            .arg(
                Arg::new("set")
                    .long("set")
                    .num_args(2) // require exactly 2 values
                    .value_names(["KEY", "VALUE"]) // give them friendly names in help output
                    .help("Set the KEY to VALUE"),
            )
            .get_matches();

    let server = matches
        .get_one::<String>("server")
        .expect("server has default");

    let get_key = matches.get_one::<String>("get");
    if get_key.is_some() {
        return get_value(server, get_key.unwrap()).await;
    }

    let set_values = matches.get_many::<String>("set");
    if set_values.is_some() {
        let values: Vec<_> = set_values.unwrap().map(|v| v.as_str()).collect();
        return set_value(server, values[0], values[1]).await;
    }
    Ok(())
}
