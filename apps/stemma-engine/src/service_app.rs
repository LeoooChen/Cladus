use std::path::PathBuf;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use anyhow::{Context, bail};
use clap::Args;
use stemma_core::config::Config;
use stemma_engine::{host::Controller, logs::RollingLog};
use stemma_ipc::{Request, Response};
use stemma_platform_windows::{EngineInstance, ipc, security, service};
use tracing_subscriber::EnvFilter;

#[derive(Args)]
pub struct ServiceArgs {
    /// Service data directory [default: %ProgramData%\Stemma].
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Directory containing the WinDivert DLL and driver [default: executable directory].
    #[arg(long)]
    windivert_dir: Option<PathBuf>,
}

impl ServiceArgs {
    fn paths(&self) -> anyhow::Result<(PathBuf, PathBuf)> {
        let data = match &self.data_dir {
            Some(path) => path.clone(),
            None => PathBuf::from(std::env::var_os("ProgramData").context("ProgramData is not set")?).join("Stemma"),
        };
        let divert = match &self.windivert_dir {
            Some(path) => path.clone(),
            None => std::env::current_exe()?.parent().context("missing executable directory")?.to_owned(),
        };
        Ok((std::path::absolute(data)?, std::path::absolute(divert)?))
    }
}

pub fn install(args: ServiceArgs) -> anyhow::Result<()> {
    let (data, divert) = args.paths()?;
    security::secure_directory(&data)?;
    let path = data.join("config.json");
    if !path.exists() {
        stemma_engine::host::save_config(&path, &Config::default())?;
    } else {
        Config::from_json(&std::fs::read_to_string(&path)?)?;
    }
    service::install(&std::env::current_exe()?, &data, &divert)?;
    println!("Stemma Engine installed. Run `stemma-engine start` to start the idle service.");
    Ok(())
}

pub fn dispatch(args: ServiceArgs) -> anyhow::Result<()> {
    let (data, divert) = args.paths()?;
    service::dispatch(move |stop| run(data, divert, stop).map_err(|err| format!("{err:#}")))?;
    Ok(())
}

fn run(data: PathBuf, divert: PathBuf, stopped: mpsc::Receiver<()>) -> anyhow::Result<()> {
    let _instance = EngineInstance::acquire()?;
    security::secure_directory(&data)?;
    let logs = data.join("logs");
    security::secure_directory(&logs)?;
    let writer = RollingLog::open(&logs.join("engine.log"))?;
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(Mutex::new(writer))
        .with_env_filter(EnvFilter::try_from_env("STEMMA_LOG").unwrap_or_else(|_| EnvFilter::new("info")))
        .try_init().map_err(|err| anyhow::anyhow!(err.to_string()))?;
    let controller = Controller::start(data.join("config.json"), move |config| {
        if stemma_platform_windows::clew_is_running() {
            bail!("Clew is running; exit it before engaging the Stemma service");
        }
        super::start(config, Some(&divert))
    })?;
    let client = controller.client();
    let handler: ipc::Handler = Arc::new(move |request| client.call(request));
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
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
    drop(controller);
    runtime.shutdown_timeout(Duration::from_secs(2));
    tracing::info!("service stopped");
    result?;
    Ok(())
}

pub fn client(request: Request) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let response = runtime.block_on(ipc::request(&request))?;
    if let Response::Error { message } = response {
        bail!("{message}");
    }
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}
