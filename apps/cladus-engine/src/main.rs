//! `cladus-engine`: the Cladus traffic engine.

#[cfg(windows)]
mod service_app;

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use cladus_core::config::Config;
use cladus_core::platform::Counter;
use cladus_engine::engine::Engine;
use clap::{Args, Parser, Subcommand};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "cladus-engine", version, about = "The Cladus traffic engine")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Runs the engine in the foreground until Ctrl+C. Requires administrator rights.
    Console(ConsoleArgs),
    #[cfg(windows)]
    /// Runs under the Windows Service Control Manager.
    Service(service_app::ServiceArgs),
    #[cfg(windows)]
    /// Restores system DNS settings left redirected by a crash (administrator).
    RestoreDns(DataArgs),
    #[cfg(windows)]
    /// Imports a compatible version 2 JSON file as service configuration (administrator).
    #[command(name = "import-config", alias = "import-clew")]
    ImportClew {
        /// The compatible configuration file; it is only read.
        #[arg(long)]
        from: PathBuf,
        #[command(flatten)]
        data: DataArgs,
    },
    #[cfg(windows)]
    /// Registers the Windows service (administrator).
    Install(service_app::ServiceArgs),
    #[cfg(windows)]
    #[command(hide = true)]
    SecureInstallDir {
        #[arg(long)]
        path: PathBuf,
    },
    #[cfg(windows)]
    /// Stops and unregisters the service (administrator).
    Uninstall,
    #[cfg(windows)]
    /// Starts the idle Windows service (administrator).
    Start,
    #[cfg(windows)]
    /// Stops the Windows service (administrator).
    Stop,
    #[cfg(windows)]
    /// Reports engine state through the authenticated service pipe.
    Status,
    #[cfg(windows)]
    /// Enables proxying.
    Engage,
    #[cfg(windows)]
    /// Stops proxying, leaving the service idle.
    Disengage,
    #[cfg(windows)]
    /// Lists tracked processes and assignments.
    Processes,
    #[cfg(windows)]
    /// Prints the service configuration.
    GetConfig,
    #[cfg(windows)]
    /// Measures HTTP(S) response time through a configured proxy group.
    TestProxy {
        #[arg(long, default_value_t = 0)]
        group: u32,
    },
    #[cfg(windows)]
    /// Validates and replaces the service configuration.
    SetConfig {
        #[arg(long)]
        config: PathBuf,
    },
}

#[derive(Args)]
struct DataArgs {
    /// Engine data directory [default: %ProgramData%\Cladus].
    #[arg(long)]
    data_dir: Option<PathBuf>,
}

impl DataArgs {
    fn dir(&self) -> anyhow::Result<PathBuf> {
        match &self.data_dir {
            Some(path) => Ok(std::path::absolute(path)?),
            None => default_data_dir(),
        }
    }
}

fn default_data_dir() -> anyhow::Result<PathBuf> {
    Ok(
        PathBuf::from(std::env::var_os("ProgramData").context("ProgramData is not set")?)
            .join("Cladus"),
    )
}

/// The DNS journal inside a data directory.
#[cfg(windows)]
fn dns_journal(data: &Path) -> PathBuf {
    data.join("state").join("dns-journal.json")
}

#[derive(Args)]
struct ConsoleArgs {
    #[command(flatten)]
    data: DataArgs,
    /// Configuration file.
    #[arg(long)]
    config: PathBuf,
    /// Directory with WinDivert.dll and WinDivert64.sys [default: next to this program].
    #[arg(long)]
    windivert_dir: Option<PathBuf>,
    /// Log level, overriding the configuration. CLADUS_LOG accepts full filter directives.
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
        #[cfg(windows)]
        Command::Service(args) => service_app::dispatch(args),
        #[cfg(windows)]
        Command::Install(args) => service_app::install(args),
        #[cfg(windows)]
        Command::SecureInstallDir { path } => {
            cladus_platform_windows::security::secure_install_directory(&std::path::absolute(
                path,
            )?)?;
            Ok(())
        }
        #[cfg(windows)]
        Command::RestoreDns(args) => restore_dns(&args.dir()?),
        #[cfg(windows)]
        Command::ImportClew { from, data } => import_clew(&from, &data.dir()?),
        #[cfg(windows)]
        Command::Uninstall => {
            let data = cladus_platform_windows::service::installed_data_dir()?
                .map(Ok)
                .unwrap_or_else(default_data_dir)?;
            cladus_platform_windows::service::stop()?;
            // Keep the service registration and journal if recovery fails.
            restore_dns(&data)?;
            cladus_platform_windows::divert::remove_stale_firewall_rule()?;
            Ok(cladus_platform_windows::service::delete()?)
        }
        #[cfg(windows)]
        Command::Start => Ok(cladus_platform_windows::service::start()?),
        #[cfg(windows)]
        Command::Stop => {
            let data = cladus_platform_windows::service::installed_data_dir()?
                .map(Ok)
                .unwrap_or_else(default_data_dir)?;
            cladus_platform_windows::service::stop()?;
            restore_dns(&data)
        }
        #[cfg(windows)]
        Command::Status => service_app::client(cladus_ipc::Request::Status),
        #[cfg(windows)]
        Command::Engage => service_app::client(cladus_ipc::Request::Engage),
        #[cfg(windows)]
        Command::Disengage => service_app::client(cladus_ipc::Request::Disengage),
        #[cfg(windows)]
        Command::Processes => service_app::client(cladus_ipc::Request::Processes),
        #[cfg(windows)]
        Command::GetConfig => service_app::client(cladus_ipc::Request::GetConfig),
        #[cfg(windows)]
        Command::TestProxy { group } => service_app::client(cladus_ipc::Request::TestProxy {
            group: cladus_core::model::GroupId(group),
        }),
        #[cfg(windows)]
        Command::SetConfig { config } => {
            let config = Config::from_json(&std::fs::read_to_string(config)?)?;
            service_app::client(cladus_ipc::Request::SetConfig {
                config: Box::new(config),
            })
        }
    }
}

fn console(args: ConsoleArgs) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("cannot read {}", args.config.display()))?;
    let config = Config::from_json(&text)
        .with_context(|| format!("invalid configuration in {}", args.config.display()))?;
    let level = args
        .log_level
        .as_deref()
        .unwrap_or(config.log_level.as_str());
    let filter = EnvFilter::try_from_env("CLADUS_LOG").unwrap_or_else(|_| EnvFilter::new(level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(std::io::stderr().is_terminal())
        .with_writer(std::io::stderr)
        .init();

    #[cfg(windows)]
    let _instance = cladus_platform_windows::EngineInstance::acquire()?;
    let data = args.data.dir()?;
    #[cfg(windows)]
    restore_dns(&data)?;
    let mut engine = start(&config, args.windivert_dir.as_deref(), &data)?;
    if let Some(path) = &args.ready_file {
        std::fs::write(path, "ready")?;
    }
    info!("running; press Ctrl+C to stop");
    wait_for_stop(args.stop_file.as_deref(), &engine)?;
    engine.prepare_stop()?;
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

/// Replaces the configuration (the old one is kept as `config.json.bak`).
/// A running service picks it up at once.
#[cfg(windows)]
fn import_clew(from: &Path, data: &Path) -> anyhow::Result<()> {
    let text =
        std::fs::read_to_string(from).with_context(|| format!("cannot read {}", from.display()))?;
    let imported = cladus_core::clew::import_clew(&text).map_err(anyhow::Error::msg)?;
    for warning in &imported.warnings {
        eprintln!("warning: {warning}");
    }
    cladus_platform_windows::security::secure_directory(data)?;
    if cladus_platform_windows::service::is_running()? {
        let installed = cladus_platform_windows::service::installed_data_dir()?
            .context("running service has no data directory")?;
        if std::fs::canonicalize(installed)? != std::fs::canonicalize(data)? {
            bail!("the running service uses another data directory; stop it before importing");
        }
        service_app::client(cladus_ipc::Request::SetConfig {
            config: Box::new(imported.config.clone()),
        })?;
    } else {
        let _instance = cladus_platform_windows::EngineInstance::acquire()?;
        cladus_engine::host::save_config(&data.join("config.json"), &imported.config)?;
    }
    println!(
        "Imported {} rule(s) and {} proxy group(s).",
        imported.config.rules.len(),
        imported.config.proxy_groups.len()
    );
    Ok(())
}

#[cfg(windows)]
fn restore_dns(data: &Path) -> anyhow::Result<()> {
    let journal = dns_journal(data);
    if cladus_engine::system_dns::recover(&cladus_platform_windows::WinSystemDns, &journal)? {
        info!("restored DNS settings left by an earlier run");
    }
    Ok(())
}

#[cfg(windows)]
fn start(config: &Config, windivert_dir: Option<&Path>, data: &Path) -> anyhow::Result<Engine> {
    use std::sync::Arc;

    use cladus_engine::engine::{DnsBackend, Platform};
    use cladus_platform_windows::{
        EtwProcessSource, Interceptor, WinDivert, WinProcessInspector, clew_is_running, is_elevated,
    };

    if !is_elevated() {
        bail!("cladus-engine must run as administrator");
    }
    if clew_is_running() {
        tracing::warn!(
            "Another traffic redirector is running; Cladus sees packets first, \
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
            interceptor: Box::new(Interceptor::new(windivert, config.tcp_syn_parking.clone())),
            dns: Some(DnsBackend {
                system: Arc::new(cladus_platform_windows::WinSystemDns),
                journal: dns_journal(data),
            }),
        },
    )
}

#[cfg(not(windows))]
fn start(_: &Config, _: Option<&Path>, _: &Path) -> anyhow::Result<Engine> {
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
        if !matches!(
            rx.recv_timeout(Duration::from_millis(200)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ) || stop_file.is_some_and(Path::exists)
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
    let line: Vec<String> = counters
        .iter()
        .map(|c| format!("{}={}", c.name, c.value))
        .collect();
    info!("counters: {}", line.join(" "));
}
