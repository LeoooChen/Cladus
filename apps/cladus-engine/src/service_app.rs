use std::path::PathBuf;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use anyhow::{Context, bail};
use cladus_core::config::Config;
use cladus_engine::{host::Controller, logs::RollingLog};
use cladus_ipc::{Request, Response};
use cladus_platform_windows::{EngineInstance, ipc, security, service};
use clap::Args;
use tracing_subscriber::EnvFilter;

#[derive(Args)]
pub struct ServiceArgs {
    /// Service data directory [default: %ProgramData%\Cladus].
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Directory containing the WinDivert DLL and driver [default: executable directory].
    #[arg(long)]
    windivert_dir: Option<PathBuf>,
    /// Engage even while Clew runs (for testing on machines that need Clew).
    #[arg(long, hide = true)]
    allow_clew: bool,
}

impl ServiceArgs {
    fn paths(&self) -> anyhow::Result<(PathBuf, PathBuf)> {
        let data = match &self.data_dir {
            Some(path) => path.clone(),
            None => {
                PathBuf::from(std::env::var_os("ProgramData").context("ProgramData is not set")?)
                    .join("Cladus")
            }
        };
        let divert = match &self.windivert_dir {
            Some(path) => path.clone(),
            None => std::env::current_exe()?
                .parent()
                .context("missing executable directory")?
                .to_owned(),
        };
        Ok((std::path::absolute(data)?, std::path::absolute(divert)?))
    }
}

pub fn install(args: ServiceArgs) -> anyhow::Result<()> {
    let (data, divert) = args.paths()?;
    security::secure_directory(&data)?;
    let path = data.join("config.json");
    if !path.exists() {
        cladus_engine::host::save_config(&path, &Config::default())?;
    } else {
        Config::from_json(&std::fs::read_to_string(&path)?)?;
    }
    let extra: &[&str] = if args.allow_clew {
        &["--allow-clew"]
    } else {
        &[]
    };
    service::install(&std::env::current_exe()?, &data, &divert, extra)?;
    println!("Cladus Engine installed. Run `cladus-engine start` to start the idle service.");
    Ok(())
}

pub fn dispatch(args: ServiceArgs) -> anyhow::Result<()> {
    let (data, divert) = args.paths()?;
    let allow_clew = args.allow_clew;
    service::dispatch(move |stop| {
        run(data, divert, allow_clew, stop).map_err(|err| format!("{err:#}"))
    })?;
    Ok(())
}

fn run(
    data: PathBuf,
    divert: PathBuf,
    allow_clew: bool,
    stopped: mpsc::Receiver<()>,
) -> anyhow::Result<()> {
    let _instance = EngineInstance::acquire()?;
    security::secure_directory(&data)?;
    let logs = data.join("logs");
    security::secure_directory(&logs)?;
    let writer = RollingLog::open(&logs.join("engine.log"))?;
    let from_env = std::env::var_os("CLADUS_LOG").is_some();
    let builder = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(Mutex::new(writer))
        .with_env_filter(
            EnvFilter::try_from_env("CLADUS_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_filter_reloading();
    let filter = builder.reload_handle();
    builder
        .try_init()
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    // The configured level applies at run time unless CLADUS_LOG overrides it.
    let set_level = move |config: &Config| {
        if !from_env {
            let _ = filter.reload(EnvFilter::new(config.log_level.as_str()));
        }
    };
    // A crash may have left the system's DNS pointing at the forwarder.
    super::restore_dns(&data)?;
    let state = data.clone();
    let mut controller = Controller::start(
        data.join("config.json"),
        move |config| {
            if !allow_clew && cladus_platform_windows::clew_is_running() {
                bail!(
                    "Another traffic redirector is running; exit it before engaging the Cladus service"
                );
            }
            super::start(config, Some(&divert), &state)
        },
        set_level,
    )?;
    let client = controller.client();
    // Reserve capacity for control requests while websites are unresponsive.
    let probes = Arc::new(tokio::sync::Semaphore::new(4));
    let handler: ipc::Handler = Arc::new(move |request| {
        let client = client.clone();
        let probes = Arc::clone(&probes);
        Box::pin(async move {
            let _permit = if matches!(
                request,
                Request::TestProxy { .. } | Request::CheckProxy { .. }
            ) {
                match probes.try_acquire_owned() {
                    Ok(permit) => Some(permit),
                    Err(_) => return Response::error("proxy checks are busy; retry shortly"),
                }
            } else {
                None
            };
            match request {
                Request::CheckProxy { group } => {
                    cladus_engine::host::check_proxy(client, group).await
                }
                Request::TestProxy { group } => {
                    cladus_engine::host::test_proxy(client, group).await
                }
                request => tokio::task::spawn_blocking(move || client.call(request))
                    .await
                    .unwrap_or_else(Response::error),
            }
        })
    });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    tracing::info!("service ready; proxying is idle");
    let result = runtime.block_on(async {
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let mut server = Box::pin(ipc::serve(handler, stop_rx));
        loop {
            tokio::select! {
                result = &mut server => break result,
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    if !matches!(stopped.try_recv(), Err(mpsc::TryRecvError::Empty)) {
                        let _ = stop_tx.send(());
                        break server.await;
                    }
                }
            }
        }
    });
    let shutdown = controller.shutdown();
    runtime.shutdown_timeout(Duration::from_secs(2));
    tracing::info!("service stopped");
    result?;
    shutdown?;
    Ok(())
}

pub fn client(request: Request) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let response = runtime.block_on(ipc::request(&request))?;
    if let Response::Error { message } = response {
        bail!("{message}");
    }
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}
