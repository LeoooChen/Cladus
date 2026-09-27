//! Serialized service control and durable configuration.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{Context, bail};
use stemma_core::config::Config;
use stemma_ipc::{Request, Response, Status};

use crate::engine::Engine;

type Factory = Box<dyn Fn(&Config) -> anyhow::Result<Engine> + Send>;

enum Message {
    Request(Request, mpsc::Sender<Response>),
    Stop,
}

#[derive(Clone)]
pub struct Client(mpsc::SyncSender<Message>);

impl Client {
    pub fn call(&self, request: Request) -> Response {
        let (tx, rx) = mpsc::channel();
        if self.0.try_send(Message::Request(request, tx)).is_err() {
            return Response::error("engine is busy or stopping");
        }
        rx.recv_timeout(Duration::from_secs(30))
            .unwrap_or_else(|_| Response::error("engine request timed out"))
    }
}

pub struct Controller {
    client: Client,
    thread: Option<JoinHandle<()>>,
}

impl Controller {
    pub fn start(
        path: PathBuf,
        factory: impl Fn(&Config) -> anyhow::Result<Engine> + Send + 'static,
    ) -> anyhow::Result<Self> {
        let config = match fs::read_to_string(&path) {
            Ok(text) => Config::from_json(&text)?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let config = Config::default();
                save_config(&path, &config)?;
                config
            }
            Err(err) => return Err(err.into()),
        };
        let (tx, rx) = mpsc::sync_channel(64);
        let thread = std::thread::Builder::new()
            .name("stemma-control".into())
            .spawn(move || {
                let mut state = State {
                    config,
                    path,
                    factory: Box::new(factory),
                    engine: None,
                    counters: BTreeMap::new(),
                    last_error: None,
                };
                while let Ok(Message::Request(request, reply)) = rx.recv() {
                    let response = match state.handle(request) {
                        Ok(response) => response,
                        Err(err) => {
                            state.last_error = Some(err.to_string());
                            Response::error(err)
                        }
                    };
                    let _ = reply.send(response);
                }
                state.disengage();
            })?;
        Ok(Self {
            client: Client(tx),
            thread: Some(thread),
        })
    }

    pub fn client(&self) -> Client {
        self.client.clone()
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        let _ = self.client.0.send(Message::Stop);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct State {
    config: Config,
    path: PathBuf,
    factory: Factory,
    engine: Option<Engine>,
    counters: BTreeMap<String, u64>,
    last_error: Option<String>,
}

impl State {
    fn disengage(&mut self) {
        if let Some(engine) = self.engine.take() {
            self.counters = engine
                .stop()
                .into_iter()
                .map(|c| (c.name.to_owned(), c.value))
                .collect();
        }
    }

    fn handle(&mut self, request: Request) -> anyhow::Result<Response> {
        Ok(match request {
            Request::Hello { .. } => Response::error("handshake was already completed"),
            Request::Status => Response::Status(Status {
                engaged: self.engine.is_some(),
                counters: self
                    .engine
                    .as_ref()
                    .map(|engine| {
                        engine
                            .counters()
                            .into_iter()
                            .map(|c| (c.name.to_owned(), c.value))
                            .collect()
                    })
                    .unwrap_or_else(|| self.counters.clone()),
                last_error: self.last_error.clone(),
            }),
            Request::Engage => {
                if self.engine.is_none() {
                    self.engine = Some((self.factory)(&self.config)?);
                    self.last_error = None;
                }
                Response::Ok
            }
            Request::Disengage => {
                self.disengage();
                Response::Ok
            }
            Request::GetConfig => Response::Config(Box::new(self.config.clone())),
            Request::SetConfig { config } => {
                config.validate()?;
                if self.engine.is_some() && config.tcp_syn_parking != self.config.tcp_syn_parking {
                    bail!("disengage before changing SYN parking settings");
                }
                if let Some(engine) = &mut self.engine {
                    engine.reconfigure(&config)?;
                }
                save_config(&self.path, &config)?;
                self.config = *config;
                self.last_error = None;
                Response::Ok
            }
            Request::Processes => Response::Processes(
                self.engine
                    .as_ref()
                    .map(Engine::processes)
                    .unwrap_or_default(),
            ),
            Request::SetManual { process, group } => {
                if group.is_some_and(|id| self.config.group(id).is_none()) {
                    bail!("unknown proxy group");
                }
                if !self
                    .engine
                    .as_mut()
                    .context("engine is not engaged")?
                    .set_manual(process, group)
                {
                    bail!("process exited or its PID was reused");
                }
                Response::Ok
            }
            Request::SetExcluded {
                process,
                rule_id,
                excluded,
            } => {
                if !self.config.rules.iter().any(|rule| rule.id == rule_id) {
                    bail!("unknown rule");
                }
                if !self
                    .engine
                    .as_mut()
                    .context("engine is not engaged")?
                    .set_excluded(process, &rule_id, excluded)
                {
                    bail!("process exited or its PID was reused");
                }
                Response::Ok
            }
        })
    }
}

/// Both files are replaced from flushed siblings, never truncated in place.
pub fn save_config(path: &Path, config: &Config) -> anyhow::Result<()> {
    config.validate()?;
    if path.exists() {
        let old = fs::read(path)?;
        atomic_write(&path.with_extension("json.bak"), &old)?;
    }
    atomic_write(path, config.to_json().as_bytes())
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let temporary = path.with_extension(format!("new-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .with_context(|| format!("cannot create {}", temporary.display()))?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.with_context(|| format!("cannot replace {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_is_preserved_when_validation_fails() {
        let dir = std::env::temp_dir().join(format!("stemma-config-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        let mut config = Config::default();
        save_config(&path, &config).unwrap();
        config.proxy_groups[0].port = 1234;
        save_config(&path, &config).unwrap();
        assert_eq!(
            Config::from_json(&fs::read_to_string(path.with_extension("json.bak")).unwrap())
                .unwrap(),
            Config::default()
        );
        config.proxy_groups.clear();
        assert!(save_config(&path, &config).is_err());
        assert_eq!(
            Config::from_json(&fs::read_to_string(&path).unwrap())
                .unwrap()
                .proxy_groups[0]
                .port,
            1234
        );
        fs::remove_file(&path).unwrap();
        fs::remove_file(path.with_extension("json.bak")).unwrap();
        fs::remove_dir(dir).unwrap();
    }
}
