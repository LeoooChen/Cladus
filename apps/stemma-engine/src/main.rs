//! `stemma-engine`: the Stemma traffic engine.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand};
use stemma_core::config::Config;
use stemma_core::platform::Counter;
use stemma_engine::engine::Engine;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "stemma-engine", version, about = "The Stemma traffic engine")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Runs the engine in the foreground until Ctrl+C. Requires administrator rights.
    Console(ConsoleArgs),
}

#[derive(Args)]
struct ConsoleArgs {
    /// Configuration file.
    #[arg(long)]
    config: PathBuf,
    /// Directory with WinDivert.dll and WinDivert64.sys [default: next to this program].
    #[arg(long)]
    windivert_dir: Option<PathBuf>,
    /// Log level, overriding the configuration. STEMMA_LOG accepts full filter directives.
    #[arg(long)]
    log_level: Option<String>,
    /// Created once traffic interception is running.
    #[arg(long)]
    ready_file: Option<PathBuf>,
    /// The engine stops when this file appears.
    #[arg(long)]
    stop_file: Option<PathBuf>,
    /// The final counters are written here as JSON on exit.
    #[arg(long)]
    stats_file: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Console(args) => console(args),
    }
}

fn console(args: ConsoleArgs) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("cannot read {}", args.config.display()))?;
    let config = Config::from_json(&text)
        .with_context(|| format!("invalid configuration in {}", args.config.display()))?;
    let level = args.log_level.as_deref().unwrap_or(config.log_level.as_str());
    let filter = EnvFilter::try_from_env("STEMMA_LOG").unwrap_or_else(|_| EnvFilter::new(level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(std::io::stderr().is_terminal())
        .with_writer(std::io::stderr)
        .init();

    let engine = start(&config, args.windivert_dir.as_deref())?;
    if let Some(path) = &args.ready_file {
        std::fs::write(path, "ready")?;
    }
    info!("running; press Ctrl+C to stop");
    wait_for_stop(args.stop_file.as_deref(), &engine)?;
    let counters = engine.stop();
    log_counters(&counters);
    if let Some(path) = &args.stats_file {
        let map: serde_json::Map<_, _> = counters
            .iter()
            .map(|c| (c.name.to_owned(), c.value.into()))
            .collect();
        std::fs::write(path, serde_json::Value::Object(map).to_string())?;
    }
    Ok(())
}

#[cfg(windows)]
fn start(config: &Config, windivert_dir: Option<&Path>) -> anyhow::Result<Engine> {
    use std::sync::Arc;

    use stemma_engine::engine::Platform;
    use stemma_platform_windows::{
        EtwProcessSource, TcpInterceptor, WinDivert, WinProcessInspector, clew_is_running,
        is_elevated,
    };

    if !is_elevated() {
        bail!("stemma-engine must run as administrator");
    }
    if clew_is_running() {
        tracing::warn!(
            "Clew is running and redirects traffic too; Stemma sees packets first, \
             but rules of both must not cover the same programs"
        );
    }
    let dir = match windivert_dir {
        Some(dir) => dir.to_owned(),
        None => std::env::current_exe()?
            .parent()
            .context("the program has no directory")?
            .to_owned(),
    };
    let windivert = WinDivert::load(&dir)?;
    Engine::start(
        config,
        Platform {
            processes: Arc::new(EtwProcessSource::new()),
            inspector: Arc::new(WinProcessInspector),
            interceptor: Box::new(TcpInterceptor::new(windivert, config.tcp_syn_parking.clone())),
        },
    )
}

#[cfg(not(windows))]
fn start(_: &Config, _: Option<&Path>) -> anyhow::Result<Engine> {
    bail!("this platform is not supported yet")
}

fn wait_for_stop(stop_file: Option<&Path>, engine: &Engine) -> anyhow::Result<()> {
    let (tx, rx) = mpsc::channel();
    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })?;
    let mut last_report = Instant::now();
    let mut reported = Vec::new();
    loop {
        if !matches!(rx.recv_timeout(Duration::from_millis(200)), Err(mpsc::RecvTimeoutError::Timeout))
            || stop_file.is_some_and(Path::exists)
        {
            return Ok(());
        }
        if last_report.elapsed() >= Duration::from_secs(60) {
            last_report = Instant::now();
            let counters = engine.counters();
            if counters != reported {
                log_counters(&counters);
                reported = counters;
            }
        }
    }
}

fn log_counters(counters: &[Counter]) {
    let line: Vec<String> = counters.iter().map(|c| format!("{}={}", c.name, c.value)).collect();
    info!("counters: {}", line.join(" "));
}
