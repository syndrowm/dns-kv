use clap::{arg, command};
use simple_dns::{Name, Packet, PacketFlag, Question, CLASS, TYPE};
use tokio::net::UdpSocket;

// Easy mode error handling.
type Result<T> = core::result::Result<T, Error>;
type Error = Box<dyn std::error::Error>;

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
            .arg(arg!(-g --get <NAME> "Get the domain").required(true))
            .get_matches();

    let domain = matches
        .get_one::<String>("get")
        .expect("domain is required");

    let server = matches
        .get_one::<String>("server")
        .expect("server has default");

    let query = txt_query_record(domain)?;

    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.send_to(&query, server).await?;

    let mut buf = [0; 4096];
    let (size, _) = sock.recv_from(&mut buf).await?;
    let data = buf[..size].to_vec();

    let packet = Packet::parse(&data)?;

    tracing::info!("{:#?}", packet.answers);

    Ok(())
}
