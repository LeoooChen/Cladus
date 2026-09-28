//! Local named-pipe transport. Authorization happens before engine commands.

use std::future::Future;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use stemma_ipc::{PIPE_NAME, Request, Response, VERSION, read_frame, write_frame};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer};
use tokio::sync::{Semaphore, oneshot};
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep, timeout};
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;

use crate::security::{authorize_client, create_pipe};

pub type Handler =
    Arc<dyn Fn(Request) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync>;

pub async fn serve(handler: Handler, mut stop: oneshot::Receiver<()>) -> io::Result<()> {
    let mut server = create_pipe(PIPE_NAME, true)?;
    let permits = Arc::new(Semaphore::new(16));
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut stop => break,
            connected = server.connect() => {
                connected?;
                let next = create_pipe(PIPE_NAME, false)?;
                let client = std::mem::replace(&mut server, next);
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    drop(client);
                    continue;
                };
                let handler = Arc::clone(&handler);
                clients.spawn(async move {
                    let _permit = permit;
                    if let Err(err) = serve_client(client, handler).await {
                        tracing::debug!(%err, "IPC client disconnected");
                    }
                });
            }
            Some(_) = clients.join_next(), if !clients.is_empty() => {}
        }
    }
    clients.shutdown().await;
    Ok(())
}

async fn serve_client(mut pipe: NamedPipeServer, handler: Handler) -> io::Result<()> {
    let hello: Request = timeout(Duration::from_secs(5), read_frame(&mut pipe)).await??;
    // This is synchronous: impersonation never crosses an await or thread hop.
    if let Err(err) = authorize_client(&pipe) {
        write_frame(&mut pipe, &Response::error(&err)).await?;
        return Err(err);
    }
    if !matches!(hello, Request::Hello { version: VERSION }) {
        write_frame(
            &mut pipe,
            &Response::error("incompatible IPC protocol version"),
        )
        .await?;
        return Ok(());
    }
    write_frame(&mut pipe, &Response::Hello { version: VERSION }).await?;
    loop {
        let request: Request = timeout(Duration::from_secs(60), read_frame(&mut pipe)).await??;
        // Async network operations remain cancellable when the server stops.
        // The handler isolates any synchronous controller calls itself.
        let response = handler(request).await;
        timeout(Duration::from_secs(10), write_frame(&mut pipe, &response)).await??;
    }
}

pub async fn request(request: &Request) -> io::Result<Response> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut pipe = loop {
        match ClientOptions::new().open(PIPE_NAME) {
            Ok(pipe) => break pipe,
            Err(err) if err.raw_os_error() == Some(231) && Instant::now() < deadline => {
                sleep(Duration::from_millis(50)).await;
            }
            Err(err) => return Err(err),
        }
    };
    let expected = crate::service::process_id().map_err(io::Error::other)?;
    let mut actual = 0;
    // SAFETY: pipe is open and `actual` is a valid out pointer.
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut actual) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "pipe server is not the Stemma Engine service",
        ));
    }
    timeout(Duration::from_secs(30), async {
        write_frame(&mut pipe, &Request::Hello { version: VERSION }).await?;
        let response: Response = read_frame(&mut pipe).await?;
        match response {
            Response::Hello { version: VERSION } => {}
            Response::Error { message } => {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, message));
            }
            _ => return Err(io::Error::other("incompatible engine handshake")),
        }
        write_frame(&mut pipe, request).await?;
        read_frame(&mut pipe).await
    })
    .await?
}
