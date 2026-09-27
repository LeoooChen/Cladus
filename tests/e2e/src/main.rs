//! End-to-end acceptance test for `stemma-engine` (Windows, administrator).
//!
//! The test runs the real engine with WinDivert and ETW against a local test
//! SOCKS5 server. Probe processes connect to TEST-NET-3 addresses
//! (203.0.113.0/24, never routed): a probe gets an answer only if the engine
//! redirected it to the test server, and a direct connection times out. The
//! server's answer names the target it was asked for, so the test also proves
//! the original destination survived the redirection.

mod socks_server;

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, bail, ensure};
use clap::{Args, Parser, Subcommand};
use stemma_core::config::{Config, ProxyGroup, Rule, RuleProtocol};
use stemma_core::model::GroupId;

const MARKER: &str = "STEMMA-E2E";
const DIRECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Probe exit code when the connection failed, i.e. it was not redirected.
const EXIT_NOT_REDIRECTED: u8 = 3;
const EXIT_WRONG_ANSWER: u8 = 4;

#[derive(Parser)]
#[command(name = "stemma-e2e", about = "End-to-end acceptance test for stemma-engine")]
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
    /// stemma-engine executable [default: next to this program].
    #[arg(long)]
    engine: Option<PathBuf>,
    /// Directory with WinDivert.dll and WinDivert64.sys [default: third_party/windivert].
    #[arg(long)]
    windivert_dir: Option<PathBuf>,
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
    /// Programs to start as a chain of descendants; the last one connects.
    next: Vec<PathBuf>,
}

fn main() -> ExitCode {
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
    let code = match fetch(args.target) {
        Ok(body) if body == format!("{MARKER} {}", args.target) => 0,
        Ok(_) => EXIT_WRONG_ANSWER,
        Err(_) => EXIT_NOT_REDIRECTED,
    };
    if let Some(result) = &args.result {
        let _ = fs::write(result, code.to_string());
    }
    code
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
        stemma_platform_windows::is_elevated(),
        "run this test from an administrator prompt"
    );
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
    check("20 new processes, one after another, are proxied", sequential(&env, 20));
    check("20 new processes at once are proxied", concurrent(&env, 20));
    check("a grandchild of a matched process is proxied", chain(&env));
    check(
        "a child still inherits after its matched parent exited",
        orphan(&env),
    );
    check("an unmatched process connects directly", unmatched(&env));
    check("a UDP-only rule leaves TCP direct", udp_only(&env));
    let stats = engine.stop()?;
    check("engine counters are consistent", counters(&stats));
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

    let failed: Vec<_> = results.iter().filter(|(_, ok)| !ok).map(|(n, _)| n).collect();
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
    let engine = args.engine.unwrap_or_else(|| bin_dir.join("stemma-engine.exe"));
    ensure!(engine.is_file(), "{} not found; build it first", engine.display());
    let windivert = match args.windivert_dir {
        Some(dir) => dir,
        None => find_windivert(&bin_dir).context(
            "WinDivert not found; run scripts/bootstrap-windows.ps1 or pass --windivert-dir",
        )?,
    };
    let dir = std::env::temp_dir().join(format!("stemma-e2e-{}", std::process::id()));
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
        matched: copy("stemma_probe.exe")?,
        child: copy("stemma_child.exe")?,
        grandchild: copy("stemma_grandchild.exe")?,
        unmatched: copy("stemma_control.exe")?,
        udp_only: copy("stemma_udponly.exe")?,
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
            rule("udp-only", &env.udp_only, RuleProtocol::Udp),
        ],
        ..Config::default()
    };
    fs::write(&env.config, config.to_json())?;
    println!("test SOCKS5 server on {}, files in {}", env.server.addr, env.dir.display());
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
            .stdin(Stdio::null())
            .stdout(log_file.try_clone()?)
            .stderr(log_file)
            .spawn()
            .context("starting stemma-engine")?;
        let mut engine = Self {
            child,
            stop_file,
            stats_file,
            log,
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        while !ready.exists() {
            if let Some(status) = engine.child.try_wait()? {
                bail!("engine exited with {status} during startup:\n{}", engine.log_tail());
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
        ensure!(status.success(), "engine exited with {status}:\n{}", self.log_tail());
        Ok(serde_json::from_str(&fs::read_to_string(&self.stats_file)?)?)
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
        env.server.targets.lock().unwrap().contains(&target.to_string()),
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
        expect_proxied(env, target, wait_code(spawn_probe(&env.matched, target, &[])?)?)?;
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

fn orphan(env: &Env) -> anyhow::Result<()> {
    let target = target(13, 1);
    let result = env.dir.join("orphan.result");
    let _ = fs::remove_file(&result);
    let parent = Command::new(&env.matched)
        .args(["probe", "--target", &target.to_string(), "--detach", "--delay-ms", "1500"])
        .arg("--result")
        .arg(&result)
        .arg(&env.child)
        .spawn()?;
    ensure!(wait_code(parent)? == 0, "the parent could not start its child");
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
        !env.server.targets.lock().unwrap().contains(&target.to_string()),
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

fn counters(stats: &serde_json::Value) -> anyhow::Result<()> {
    let get = |name: &str| stats.get(name).and_then(serde_json::Value::as_u64);
    println!("     counters: {stats}");
    for (name, expected) in [
        ("tcp.late_rejected", 0),
        ("syn.pool_in_use", 0),
        ("relay.failed", 0),
        ("relay.active", 0),
    ] {
        ensure!(get(name) == Some(expected), "{name} = {:?}, expected {expected}", get(name));
    }
    ensure!(get("tcp.proxied") == Some(42), "expected exactly 42 proxied connections");
    Ok(())
}
