//! Windows Service Control Manager integration.

use std::ffi::OsString;
use std::path::Path;
use std::sync::{Mutex, mpsc};
use std::time::{Duration, Instant};

use stemma_core::platform::PlatformError;
use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceControl,
    ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceFailureActions,
    ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus,
    ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

pub const NAME: &str = "StemmaEngine";
type Runner = Box<dyn FnOnce(mpsc::Receiver<()>) -> Result<(), String> + Send>;
static RUNNER: Mutex<Option<Runner>> = Mutex::new(None);

fn error(err: impl std::fmt::Debug) -> PlatformError {
    PlatformError::Other(format!("{err:?}"))
}

fn open(access: ServiceAccess) -> Result<Service, PlatformError> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(error)?;
    manager.open_service(NAME, access).map_err(error)
}

pub fn install(executable: &Path, data: &Path, divert: &Path) -> Result<(), PlatformError> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    ).map_err(error)?;
    let info = ServiceInfo {
        name: NAME.into(),
        display_name: "Stemma Engine".into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: executable.to_owned(),
        launch_arguments: vec![
            "service".into(), "--data-dir".into(), data.into(),
            "--windivert-dir".into(), divert.into(),
        ],
        dependencies: Vec::new(),
        account_name: None,
        account_password: None,
    };
    let access = ServiceAccess::CHANGE_CONFIG | ServiceAccess::QUERY_STATUS | ServiceAccess::START;
    let service = match manager.open_service(NAME, access) {
        Ok(service) => {
            if service.query_status().map_err(error)?.current_state != ServiceState::Stopped {
                return Err(error("stop the Stemma service before updating its registration"));
            }
            service.change_config(&info).map_err(error)?;
            service
        }
        Err(windows_service::Error::Winapi(err)) if err.raw_os_error() == Some(1060) =>
            manager.create_service(&info, access).map_err(error)?,
        Err(err) => return Err(error(err)),
    };
    service.set_description("Per-process proxy engine for Stemma. Idle until engaged by a client.")
        .map_err(error)?;
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some([5, 10, 30].into_iter().map(|seconds| ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: Duration::from_secs(seconds),
        }).collect()),
    }).map_err(error)?;
    service.set_failure_actions_on_non_crash_failures(true).map_err(error)?;
    Ok(())
}

pub fn start() -> Result<(), PlatformError> {
    let service = open(ServiceAccess::START | ServiceAccess::QUERY_STATUS)?;
    if service.query_status().map_err(error)?.current_state == ServiceState::Running {
        return Ok(());
    }
    service.start::<&str>(&[]).map_err(error)?;
    wait_for(&service, ServiceState::Running)
}

pub fn stop() -> Result<(), PlatformError> {
    let service = open(ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?;
    if service.query_status().map_err(error)?.current_state == ServiceState::Stopped {
        return Ok(());
    }
    service.stop().map_err(error)?;
    wait_for(&service, ServiceState::Stopped)
}

pub fn uninstall() -> Result<(), PlatformError> {
    stop()?;
    open(ServiceAccess::DELETE)?.delete().map_err(error)
}

pub fn process_id() -> Result<u32, PlatformError> {
    let status = open(ServiceAccess::QUERY_STATUS)?.query_status().map_err(error)?;
    status.process_id.ok_or_else(|| error("Stemma Engine service is not running"))
}

fn wait_for(service: &Service, expected: ServiceState) -> Result<(), PlatformError> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let status = service.query_status().map_err(error)?;
        if status.current_state == expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(error(format!("timed out waiting for service state {expected:?}")));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub fn dispatch(runner: impl FnOnce(mpsc::Receiver<()>) -> Result<(), String> + Send + 'static) -> Result<(), PlatformError> {
    *RUNNER.lock().unwrap() = Some(Box::new(runner));
    service_dispatcher::start(NAME, ffi_main).map_err(error)
}

define_windows_service!(ffi_main, service_main);

fn status(state: ServiceState, code: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(code),
        checkpoint: 0,
        wait_hint: Duration::from_secs(30),
        process_id: None,
    }
}

fn service_main(_: Vec<OsString>) {
    let (tx, rx) = mpsc::channel();
    let handle = service_control_handler::register(NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    });
    let Ok(handle) = handle else { return };
    if handle.set_service_status(status(ServiceState::Running, 0)).is_err() {
        return;
    }
    let runner = RUNNER.lock().unwrap().take();
    let result = runner.ok_or_else(|| "missing service runner".to_owned()).and_then(|run| run(rx));
    if let Err(err) = &result {
        tracing::error!(%err, "service failed");
    }
    let _ = handle.set_service_status(status(ServiceState::Stopped, u32::from(result.is_err())));
}
