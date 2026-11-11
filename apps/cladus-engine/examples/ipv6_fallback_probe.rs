//! An isolated live acceptance probe: no driver, service or DNS changes.
//! cargo run -p cladus-engine --example ipv6_fallback_probe -- --help
use anyhow::{Context, ensure};
use cladus_core::policy::{GLOBAL_POLICY, PolicyTable};
use cladus_engine::relay::{Ipv6Fallback, ProxyEndpoint, RelayCounters, relay_with_fallback};
use clap::Parser;
use std::net::{Ipv6Addr, SocketAddr};
use std::process::Command;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    proxy: SocketAddr,
    #[arg(long)]
    ipv6: Ipv6Addr,
    #[arg(long, default_value = "chatgpt.com")]
    host: String,
    #[arg(long, default_value = "8.8.8.8:53")]
    dns: SocketAddr,
    /// Fail IPv6 in a test-owned SOCKS5 shim; IPv4 and DNS still use the real proxy.
    #[arg(long)]
    simulate_ipv6_eof: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let args = Args::parse();
    ensure!(
        !args.host.is_empty()
            && args
                .host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'),
        "invalid hostname"
    );
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let host = args.host;
    let app = tokio::task::spawn_blocking(move || {
        Command::new("curl.exe")
            .args([
                "--head",
                "--silent",
                "--show-error",
                "--output",
                "NUL",
                "--noproxy",
                "*",
                "--connect-timeout",
                "10",
                "--max-time",
                "45",
                "--http1.1",
                "--connect-to",
                &format!("{host}:443:127.0.0.1:{port}"),
                "--write-out",
                "http=%{http_code} tls=%{time_appconnect} total=%{time_total}",
                &format!("https://{host}/"),
            ])
            .output()
    });
    let (client, _) = timeout(Duration::from_secs(10), listener.accept()).await??;
    let endpoint = if args.simulate_ipv6_eof {
        failure_shim(args.proxy).await?
    } else {
        args.proxy
    };
    let proxy = ProxyEndpoint {
        host: endpoint.ip().to_string(),
        port: endpoint.port(),
        credentials: None,
    };
    let counters = RelayCounters::default();
    let policy = PolicyTable::default();
    let allows = |dst| policy.check(GLOBAL_POLICY, dst).is_ok();
    let result = timeout(
        Duration::from_secs(45),
        relay_with_fallback(
            client,
            &proxy,
            SocketAddr::new(args.ipv6.into(), 443),
            Ipv6Fallback {
                resolver: args.dns,
                allows: &allows,
                counters: &counters,
            },
        ),
    )
    .await
    .context("relay probe timed out")?;
    let output = app.await??;
    println!("{}", String::from_utf8_lossy(&output.stdout));
    println!("relay={result:?}");
    for c in counters
        .snapshot()
        .into_iter()
        .filter(|c| c.name.contains("fallback"))
    {
        println!("{}={}", c.name, c.value);
    }
    ensure!(
        output.status.success(),
        "curl: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    result?;
    if args.simulate_ipv6_eof {
        ensure!(
            counters
                .snapshot()
                .iter()
                .any(|c| c.name == "relay.ipv4_fallback_selected" && c.value == 1),
            "expected one IPv4 fallback"
        );
    }
    Ok(())
}

async fn failure_shim(real: SocketAddr) -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        while let Ok((mut client, _)) = listener.accept().await {
            tasks.spawn(async move {
                let mut greeting = [0; 3];
                client.read_exact(&mut greeting).await?;
                client.write_all(&[5, 0]).await?;
                let mut head = [0; 4];
                client.read_exact(&mut head).await?;
                let len = match head[3] {
                    1 => 6,
                    4 => 18,
                    _ => return Err(std::io::Error::other("test shim expects IP destinations")),
                };
                let mut tail = vec![0; len];
                client.read_exact(&mut tail).await?;
                if head[3] == 4 {
                    client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                    let _ = client.read(&mut [0; 4096]).await?;
                    return Ok(());
                }
                let mut upstream = tokio::net::TcpStream::connect(real).await?;
                upstream.write_all(&greeting).await?;
                let mut auth = [0; 2];
                upstream.read_exact(&mut auth).await?;
                if auth != [5, 0] {
                    return Err(std::io::Error::other("test proxy authentication failed"));
                }
                upstream.write_all(&head).await?;
                upstream.write_all(&tail).await?;
                tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
                Ok::<_, std::io::Error>(())
            });
        }
    });
    Ok(address)
}
