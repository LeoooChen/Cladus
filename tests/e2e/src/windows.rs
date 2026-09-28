//! End-to-end acceptance test for `cladus-engine` (Windows, administrator).
//!
//! The test runs the real engine with WinDivert and ETW against a local test
//! SOCKS5 server. Probe processes connect to TEST-NET-3 addresses
//! (203.0.113.0/24, never routed): a probe gets an answer only if the engine
//! redirected it to the test server, and a direct connection times out. The
//! server's answer names the target it was asked for, so the test also proves
//! the original destination survived the redirection.

#[path = "socks_server.rs"]
mod socks_server;

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, bail, ensure};
use cladus_core::config::{Config, ProxyGroup, Rule, RuleProtocol};
use cladus_core::model::GroupId;
use clap::{Args, Parser, Subcommand};

const MARKER: &str = "CLADUS-E2E";
const DIRECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Probe exit code when the connection failed, i.e. it was not redirected.
const EXIT_NOT_REDIRECTED: u8 = 3;
const EXIT_WRONG_ANSWER: u8 = 4;

#[derive(Parser)]
#[command(
    name = "cladus-e2e",
    about = "End-to-end acceptance test for cladus-engine"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Runs the acceptance test (default). Needs administrator rights.
    Run(RunArgs),
    /// Test helper: connects to a target, or starts the next program of a chain.
    Probe(ProbeArgs),
}

#[derive(Args, Default)]
struct RunArgs {
    /// cladus-engine executable [default: next to this program].
    #[arg(long)]
    engine: Option<PathBuf>,
    /// Directory with WinDivert.dll and WinDivert64.sys [default: third_party/windivert].
    #[arg(long)]
    windivert_dir: Option<PathBuf>,
    /// Also require IPv6 TCP and UDP interception (needs an IPv6 route).
    #[arg(long)]
    ipv6: bool,
}

#[derive(Args)]
struct ProbeArgs {
    #[arg(long)]
    target: SocketAddr,
    /// Write the outcome to this file instead of only returning it.
    #[arg(long)]
    result: Option<PathBuf>,
    /// Wait before connecting.
    #[arg(long, default_value_t = 0)]
    delay_ms: u64,
    /// Start the next program and exit without waiting for it.
    #[arg(long)]
    detach: bool,
    #[arg(long)]
    udp: bool,
    #[arg(long)]
    connected: bool,
    #[arg(long)]
    second_target: Option<SocketAddr>,
    #[arg(long, default_value_t = 64)]
    payload_size: usize,
    /// Programs to start as a chain of descendants; the last one connects.
    next: Vec<PathBuf>,
}

pub fn main() -> ExitCode {
    match Cli::parse().command.unwrap_or(Cmd::Run(RunArgs::default())) {
        Cmd::Probe(args) => ExitCode::from(probe(args)),
        Cmd::Run(args) => match run(args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("\nFAILED: {err:#}");
                ExitCode::FAILURE
            }
        },
    }
}

// ---- probe --------------------------------------------------------------------

fn probe(args: ProbeArgs) -> u8 {
    if let Some((next, rest)) = args.next.split_first() {
        let mut command = Command::new(next);
        command.args(["probe", "--target", &args.target.to_string()]);
        command.args(["--delay-ms", &args.delay_ms.to_string()]);
        if let Some(result) = &args.result {
            command.arg("--result").arg(result);
        }
        if args.detach {
            command.arg("--detach");
        }
        if args.udp {
            command.arg("--udp");
        }
        if args.connected {
            command.arg("--connected");
        }
        if let Some(target) = args.second_target {
            command.args(["--second-target", &target.to_string()]);
        }
        command.args(["--payload-size", &args.payload_size.to_string()]);
        command.args(rest);
        let Ok(mut child) = command.spawn() else {
            return 1;
        };
        if args.detach {
            return 0;
        }
        return child
            .wait()
            .ok()
            .and_then(|s| s.code())
            .map_or(1, |code| code as u8);
    }
    thread::sleep(Duration::from_millis(args.delay_ms));
    let response = if args.udp {
        fetch_udp(&args)
    } else {
        fetch(args.target)
    };
    let code = match response {
        Ok(body) if body == format!("{MARKER} {}", args.target) => 0,
        Ok(_) => EXIT_WRONG_ANSWER,
        Err(_) => EXIT_NOT_REDIRECTED,
    };
    if let Some(result) = &args.result {
        let _ = fs::write(result, code.to_string());
    }
    code
}

fn fetch_udp(args: &ProbeArgs) -> std::io::Result<String> {
    let socket = UdpSocket::bind(if args.target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    })?;
    socket.set_read_timeout(Some(DIRECT_TIMEOUT))?;
    socket.set_write_timeout(Some(DIRECT_TIMEOUT))?;
    let mut buffer = vec![0u8; 65_536];
    for target in std::iter::once(args.target).chain(args.second_target) {
        let payload = vec![b'a'; args.payload_size];
        if args.connected {
            socket.connect(target)?;
            socket.send(&payload)?;
        } else {
            socket.send_to(&payload, target)?;
        }
        let (len, source) = socket.recv_from(&mut buffer)?;
        let expected = format!("{MARKER} {target} {}", payload.len());
        if source != target || buffer[..len] != *expected.as_bytes() {
            return Ok("wrong UDP payload or source address".to_owned());
        }
    }
    Ok(format!("{MARKER} {}", args.target))
}

fn fetch(target: SocketAddr) -> std::io::Result<String> {
    let mut stream = TcpStream::connect_timeout(&target, DIRECT_TIMEOUT)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    write!(stream, "GET / HTTP/1.0\r\nHost: {target}\r\n\r\n")?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default())
}

// ---- acceptance test -----------------------------------------------------------

struct Env {
    dir: PathBuf,
    engine: PathBuf,
    windivert: PathBuf,
    config: PathBuf,
    matched: PathBuf,
    child: PathBuf,
    grandchild: PathBuf,
    unmatched: PathBuf,
    udp_only: PathBuf,
    server: socks_server::TestServer,
}

fn run(args: RunArgs) -> anyhow::Result<()> {
    ensure!(
        cladus_platform_windows::is_elevated(),
        "run this test from an administrator prompt"
    );
    let ipv6 = args.ipv6;
    let env = prepare(args)?;
    let mut results = Vec::new();
    let mut check = |name: &str, outcome: anyhow::Result<()>| {
        println!("{} {name}", if outcome.is_ok() { "PASS" } else { "FAIL" });
        if let Err(err) = &outcome {
            println!("     {err:#}");
        }
        results.push((name.to_owned(), outcome.is_ok()));
    };

    let engine = EngineProcess::start(&env, "run1")?;
    check(
        "a second engine cannot disturb the running engine",
        match EngineProcess::start(&env, "duplicate") {
            Err(err) if err.to_string().contains("another Cladus engine") => Ok(()),
            Err(err) => Err(err),
            Ok(_) => Err(anyhow::anyhow!("a second engine started")),
        },
    );
    check(
        "20 new processes, one after another, are proxied",
        sequential(&env, 20),
    );
    check("20 new processes at once are proxied", concurrent(&env, 20));
    check("a grandchild of a matched process is proxied", chain(&env));
    check(
        "a child still inherits after its matched parent exited",
        orphan(&env, 1500, 1),
    );
    check(
        "children connecting immediately after parent exit inherit (20 attempts)",
        (0..20).try_for_each(|i| orphan(&env, 0, i + 2)),
    );
    check("an unmatched process connects directly", unmatched(&env));
    check("a UDP-only rule leaves TCP direct", udp_only(&env));
    check(
        "UDP sends to multiple destinations preserve each reply source",
        udp_probe(
            &env,
            &env.udp_only,
            target(40, 1),
            true,
            &["--second-target", &target(41, 2).to_string()],
        ),
    );
    check(
        "connected UDP sockets are proxied",
        udp_probe(&env, &env.udp_only, target(42, 1), true, &["--connected"]),
    );
    check(
        "large UDP datagrams are proxied without leaking",
        udp_probe(
            &env,
            &env.udp_only,
            target(42, 2),
            true,
            &["--payload-size", "4096"],
        ),
    );
    check(
        "UDP inheritance reaches grandchildren",
        udp_probe(
            &env,
            &env.udp_only,
            target(43, 1),
            true,
            &[
                env.child.to_str().unwrap(),
                env.grandchild.to_str().unwrap(),
            ],
        ),
    );
    check(
        "a TCP-only rule leaves UDP direct",
        udp_probe(&env, &env.matched, target(44, 1), false, &[]),
    );
    check(
        "unmatched UDP is direct",
        udp_probe(&env, &env.unmatched, target(45, 1), false, &[]),
    );
    check(
        "UDP destination CIDR exclusions are respected",
        udp_probe(&env, &env.udp_only, target(99, 1), false, &[]),
    );
    check(
        "UDP destination port exclusions are respected",
        udp_probe(&env, &env.udp_only, target(46, 99), false, &[]),
    );
    check(
        "UDP destination include ports are respected",
        udp_probe(
            &env,
            &env.udp_only,
            "203.0.113.46:1234".parse()?,
            false,
            &[],
        ),
    );
    if ipv6 {
        let target = "[2001:db8::10]:20001".parse()?;
        check(
            "IPv6 TCP is proxied",
            wait_code(spawn_probe(&env.matched, target, &[])?)
                .and_then(|code| expect_proxied(&env, target, code)),
        );
        check(
            "IPv6 UDP is proxied",
            udp_probe(
                &env,
                &env.udp_only,
                "[2001:db8::40]:20001".parse()?,
                true,
                &[],
            ),
        );
    }
    let stats = engine.stop()?;
    check(
        "engine counters are consistent",
        counters(&stats, 62 + u64::from(ipv6)),
    );
    check(
        "after a clean stop, matched processes connect directly",
        expect_direct(&env, &env.matched, target(30, 1)),
    );

    let engine = EngineProcess::start(&env, "run2")?;
    check("proxying works after a restart", sequential(&env, 3));
    engine.kill()?;
    check(
        "after the engine is killed, traffic flows directly",
        expect_direct(&env, &env.matched, target(31, 1)),
    );
    let engine = EngineProcess::start(&env, "run3");
    check(
        "the engine starts again after being killed",
        engine.and_then(|engine| {
            sequential(&env, 3)?;
            engine.stop().map(drop)
        }),
    );

    let failed: Vec<_> = results
        .iter()
        .filter(|(_, ok)| !ok)
        .map(|(n, _)| n)
        .collect();
    println!(
        "\n{} of {} checks passed. Logs: {}",
        results.len() - failed.len(),
        results.len(),
        env.dir.display()
    );
    ensure!(failed.is_empty(), "{} check(s) failed", failed.len());
    Ok(())
}

fn prepare(args: RunArgs) -> anyhow::Result<Env> {
    let me = std::env::current_exe()?;
    let bin_dir = me.parent().context("no program directory")?.to_owned();
    let engine = args
        .engine
        .unwrap_or_else(|| bin_dir.join("cladus-engine.exe"));
    ensure!(
        engine.is_file(),
        "{} not found; build it first",
        engine.display()
    );
    let windivert = match args.windivert_dir {
        Some(dir) => dir,
        None => find_windivert(&bin_dir).context(
            "WinDivert not found; run scripts/bootstrap-windows.ps1 or pass --windivert-dir",
        )?,
    };
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("cladus-e2e-{}-{stamp}", std::process::id()));
    fs::create_dir_all(&dir)?;
    let copy = |name: &str| -> anyhow::Result<PathBuf> {
        let path = dir.join(name);
        fs::copy(&me, &path).with_context(|| format!("copying the probe to {}", path.display()))?;
        Ok(path)
    };
    let server = socks_server::start("127.0.0.1:0".parse()?, MARKER)?;
    let env = Env {
        engine,
        windivert,
        config: dir.join("config.json"),
        matched: copy("cladus_probe.exe")?,
        child: copy("cladus_child.exe")?,
        grandchild: copy("cladus_grandchild.exe")?,
        unmatched: copy("cladus_control.exe")?,
        udp_only: copy("cladus_udponly.exe")?,
        server,
        dir,
    };
    let rule = |id: &str, exe: &Path, protocol| Rule {
        id: id.to_owned(),
        name: id.to_owned(),
        process_name: exe.file_name().unwrap().to_string_lossy().into_owned(),
        protocol,
        ..Rule::default()
    };
    let config = Config {
        proxy_groups: vec![ProxyGroup {
            id: GroupId(0),
            name: "test".to_owned(),
            host: "127.0.0.1".to_owned(),
            port: env.server.addr.port(),
            ..ProxyGroup::default()
        }],
        rules: vec![
            rule("probe", &env.matched, RuleProtocol::Tcp),
            Rule {
                dst_filter: cladus_core::config::DestinationFilter {
                    exclude_cidrs: vec![
                        "203.0.113.99".parse().unwrap(),
                        "2001:db8::99".parse().unwrap(),
                    ],
                    include_ports: vec!["20000-30000".parse().unwrap()],
                    exclude_ports: vec!["20099".parse().unwrap()],
                    ..Default::default()
                },
                ..rule("udp-only", &env.udp_only, RuleProtocol::Udp)
            },
        ],
        ..Config::default()
    };
    fs::write(&env.config, config.to_json())?;
    println!(
        "test SOCKS5 server on {}, files in {}",
        env.server.addr,
        env.dir.display()
    );
    Ok(env)
}

fn find_windivert(start: &Path) -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok();
    start
        .ancestors()
        .chain(cwd.iter().flat_map(|d| d.ancestors()))
        .map(|dir| dir.join("third_party").join("windivert"))
        .find(|dir| dir.join("WinDivert64.sys").is_file())
}

struct EngineProcess {
    child: Child,
    stop_file: PathBuf,
    stats_file: PathBuf,
    log: PathBuf,
}

impl Drop for EngineProcess {
    fn drop(&mut self) {
        // Failed assertions or startup must not leave interception running.
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

impl EngineProcess {
    fn start(env: &Env, name: &str) -> anyhow::Result<Self> {
        let ready = env.dir.join(format!("{name}.ready"));
        let stop_file = env.dir.join(format!("{name}.stop"));
        let stats_file = env.dir.join(format!("{name}.stats.json"));
        let log = env.dir.join(format!("{name}.log"));
        let log_file = fs::File::create(&log)?;
        let child = Command::new(&env.engine)
            .arg("console")
            .arg("--config")
            .arg(&env.config)
            .arg("--windivert-dir")
            .arg(&env.windivert)
            .arg("--ready-file")
            .arg(&ready)
            .arg("--stop-file")
            .arg(&stop_file)
            .arg("--stats-file")
            .arg(&stats_file)
            .args(["--log-level", "debug"])
            .stdin(Stdio::null())
            .stdout(log_file.try_clone()?)
            .stderr(log_file)
            .spawn()
            .context("starting cladus-engine")?;
        let mut engine = Self {
            child,
            stop_file,
            stats_file,
            log,
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        while !ready.exists() {
            if let Some(status) = engine.child.try_wait()? {
                bail!(
                    "engine exited with {status} during startup:\n{}",
                    engine.log_tail()
                );
            }
            if Instant::now() > deadline {
                let _ = engine.child.kill();
                bail!("engine did not become ready:\n{}", engine.log_tail());
            }
            thread::sleep(Duration::from_millis(100));
        }
        // Let the initial process rundown arrive.
        thread::sleep(Duration::from_secs(1));
        Ok(engine)
    }

    /// Stops the engine gracefully and returns its final counters.
    fn stop(mut self) -> anyhow::Result<serde_json::Value> {
        fs::write(&self.stop_file, "stop")?;
        let deadline = Instant::now() + Duration::from_secs(15);
        let status = loop {
            if let Some(status) = self.child.try_wait()? {
                break status;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                bail!("engine did not stop in time:\n{}", self.log_tail());
            }
            thread::sleep(Duration::from_millis(100));
        };
        ensure!(
            status.success(),
            "engine exited with {status}:\n{}",
            self.log_tail()
        );
        Ok(serde_json::from_str(&fs::read_to_string(
            &self.stats_file,
        )?)?)
    }

    fn kill(mut self) -> anyhow::Result<()> {
        self.child.kill()?;
        self.child.wait()?;
        Ok(())
    }

    fn log_tail(&self) -> String {
        let text = fs::read_to_string(&self.log).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(30)..].join("\n")
    }
}

fn target(subnet_host: u8, index: u16) -> SocketAddr {
    SocketAddr::from(([203, 0, 113, subnet_host], 20_000 + index))
}

fn spawn_probe(exe: &Path, target: SocketAddr, extra: &[&Path]) -> anyhow::Result<Child> {
    Ok(Command::new(exe)
        .args(["probe", "--target", &target.to_string()])
        .args(extra)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?)
}

fn wait_code(mut child: Child) -> anyhow::Result<u8> {
    Ok(child.wait()?.code().unwrap_or(1) as u8)
}

fn expect_proxied(env: &Env, target: SocketAddr, code: u8) -> anyhow::Result<()> {
    ensure!(
        code == 0,
        "{target}: probe exited with {code} ({})",
        explain(code)
    );
    ensure!(
        env.server
            .targets
            .lock()
            .unwrap()
            .contains(&target.to_string()),
        "{target}: the proxy never saw this target"
    );
    Ok(())
}

fn explain(code: u8) -> &'static str {
    match code {
        0 => "proxied",
        EXIT_NOT_REDIRECTED => "not redirected",
        EXIT_WRONG_ANSWER => "wrong answer",
        _ => "probe failed",
    }
}

fn sequential(env: &Env, count: u16) -> anyhow::Result<()> {
    let base = env.server.targets.lock().unwrap().len() as u16;
    for i in 0..count {
        let target = target(10, base + i);
        expect_proxied(
            env,
            target,
            wait_code(spawn_probe(&env.matched, target, &[])?)?,
        )?;
    }
    Ok(())
}

fn concurrent(env: &Env, count: u16) -> anyhow::Result<()> {
    let probes: Vec<_> = (0..count)
        .map(|i| {
            let target = target(11, i);
            spawn_probe(&env.matched, target, &[]).map(|child| (target, child))
        })
        .collect::<Result<_, _>>()?;
    let mut failures = Vec::new();
    for (target, child) in probes {
        if let Err(err) = expect_proxied(env, target, wait_code(child)?) {
            failures.push(err.to_string());
        }
    }
    ensure!(failures.is_empty(), "{}", failures.join("; "));
    Ok(())
}

fn chain(env: &Env) -> anyhow::Result<()> {
    let target = target(12, 1);
    let child = spawn_probe(&env.matched, target, &[&env.child, &env.grandchild])?;
    expect_proxied(env, target, wait_code(child)?)
}

fn orphan(env: &Env, delay_ms: u64, index: u16) -> anyhow::Result<()> {
    let target = target(13, index);
    let result = env.dir.join("orphan.result");
    let _ = fs::remove_file(&result);
    let parent = Command::new(&env.matched)
        .args([
            "probe",
            "--target",
            &target.to_string(),
            "--detach",
            "--delay-ms",
            &delay_ms.to_string(),
        ])
        .arg("--result")
        .arg(&result)
        .arg(&env.child)
        .spawn()?;
    ensure!(
        wait_code(parent)? == 0,
        "the parent could not start its child"
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    while !result.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(100));
    }
    thread::sleep(Duration::from_millis(100));
    let code = fs::read_to_string(&result)
        .context("the child reported no result")?
        .trim()
        .parse()?;
    expect_proxied(env, target, code)
}

/// A direct connection to TEST-NET usually times out, but a transparent
/// proxy on the network may answer it; either way the test proxy must never
/// see the target.
fn expect_direct(env: &Env, exe: &Path, target: SocketAddr) -> anyhow::Result<()> {
    let code = wait_code(spawn_probe(exe, target, &[])?)?;
    ensure!(
        code != 0,
        "{target}: expected a direct connection, but the probe was proxied"
    );
    ensure!(
        !env.server
            .targets
            .lock()
            .unwrap()
            .contains(&target.to_string()),
        "{target}: the proxy was contacted"
    );
    Ok(())
}

fn unmatched(env: &Env) -> anyhow::Result<()> {
    expect_direct(env, &env.unmatched, target(14, 1))
}

fn udp_only(env: &Env) -> anyhow::Result<()> {
    expect_direct(env, &env.udp_only, target(15, 1))
}

fn udp_probe(
    env: &Env,
    exe: &Path,
    target: SocketAddr,
    proxied: bool,
    extra: &[&str],
) -> anyhow::Result<()> {
    let child = Command::new(exe)
        .args(["probe", "--udp", "--target", &target.to_string()])
        .args(extra)
        .spawn()?;
    let code = wait_code(child)?;
    let seen = env
        .server
        .udp_targets
        .lock()
        .unwrap()
        .contains(&target.to_string());
    if proxied {
        ensure!(
            code == 0 && seen,
            "{target}: UDP probe code={code}, proxy saw target={seen}"
        );
    } else {
        ensure!(
            code != 0 && !seen,
            "{target}: expected direct UDP, code={code}, proxy saw target={seen}"
        );
    }
    Ok(())
}

fn counters(stats: &serde_json::Value, tcp_expected: u64) -> anyhow::Result<()> {
    let get = |name: &str| stats.get(name).and_then(serde_json::Value::as_u64);
    println!("     counters: {stats}");
    for (name, expected) in [
        ("tcp.proxy_late_rejected", 0),
        ("syn.pool_in_use", 0),
        ("relay.failed", 0),
        ("relay.active", 0),
    ] {
        ensure!(
            get(name) == Some(expected),
            "{name} = {:?}, expected {expected}",
            get(name)
        );
    }
    ensure!(
        get("tcp.proxied") == Some(tcp_expected),
        "expected exactly {tcp_expected} proxied TCP connections"
    );
    ensure!(
        get("tcp.accepted") == Some(tcp_expected),
        "expected exactly {tcp_expected} accepted TCP connections"
    );
    Ok(())
}
