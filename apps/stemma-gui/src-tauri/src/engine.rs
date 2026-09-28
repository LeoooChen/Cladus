//! Requests to the engine service.

use stemma_core::config::Config;
use stemma_core::model::ProcessView;
use stemma_ipc::{Request, Response, Status};

/// Errors are user-facing messages.
pub async fn call(request: Request) -> Result<Response, String> {
    match stemma_platform_windows::ipc::request(&request).await {
        Ok(Response::Error { message }) => Err(message),
        Ok(response) => Ok(response),
        Err(err) => Err(unreachable_message(&err)),
    }
}

fn unreachable_message(err: &std::io::Error) -> String {
    match err.raw_os_error() {
        // ERROR_FILE_NOT_FOUND: nobody serves the pipe.
        Some(2) => "The Stemma Engine service is not running.".to_owned(),
        Some(5) => {
            "Access to the Stemma Engine service was denied. Only administrators may control it."
                .to_owned()
        }
        _ => format!("Cannot reach the Stemma Engine service: {err}"),
    }
}

pub async fn ok(request: Request) -> Result<(), String> {
    match call(request).await? {
        Response::Ok => Ok(()),
        other => Err(unexpected(&other)),
    }
}

pub async fn config() -> Result<Config, String> {
    match call(Request::GetConfig).await? {
        Response::Config(config) => Ok(*config),
        other => Err(unexpected(&other)),
    }
}

pub async fn set_config(config: Config) -> Result<(), String> {
    config.validate().map_err(|err| err.to_string())?;
    ok(Request::SetConfig {
        config: Box::new(config),
    })
    .await
}

pub async fn processes() -> Result<Vec<ProcessView>, String> {
    match call(Request::Processes).await? {
        Response::Processes(list) => Ok(list),
        other => Err(unexpected(&other)),
    }
}

pub async fn status() -> Result<Status, String> {
    match call(Request::Status).await? {
        Response::Status(status) => Ok(status),
        other => Err(unexpected(&other)),
    }
}

pub fn unexpected(response: &Response) -> String {
    format!("unexpected engine response: {response:?}")
}
