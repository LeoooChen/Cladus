//! The transport-independent engine control protocol.

use std::collections::BTreeMap;
use std::io;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use stemma_core::config::Config;
use stemma_core::model::{GroupId, ProcessKey, ProcessView};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const VERSION: u32 = 1;
pub const MAX_FRAME: usize = 4 * 1024 * 1024;
pub const PIPE_NAME: &str = r"\\.\pipe\StemmaEngine";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "command",
    content = "args",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Request {
    Hello {
        version: u32,
    },
    Status,
    Engage,
    Disengage,
    GetConfig,
    SetConfig {
        config: Box<Config>,
    },
    Processes,
    /// Image path and command line of a running process.
    ProcessDetail {
        process: ProcessKey,
    },
    SetManual {
        process: ProcessKey,
        group: Option<GroupId>,
    },
    /// Measures a proxy group's latency to its test URL.
    TestProxy {
        group: GroupId,
    },
    /// Checks SOCKS5 connection/authentication without contacting a website.
    CheckProxy {
        group: GroupId,
    },
    SetExcluded {
        process: ProcessKey,
        rule_id: String,
        excluded: bool,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Status {
    pub engaged: bool,
    pub counters: BTreeMap<String, u64>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProcessDetail {
    pub image_path: Option<String>,
    pub cmdline: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum Response {
    Hello { version: u32 },
    Ok,
    Status(Status),
    Config(Box<Config>),
    Processes(Vec<ProcessView>),
    ProcessDetail(ProcessDetail),
    ProxyTest { latency_ms: u64 },
    Error { message: String },
}

impl Response {
    pub fn error(message: impl ToString) -> Self {
        Self::Error {
            message: message.to_string(),
        }
    }
}

/// Big-endian u32 byte length followed by UTF-8 JSON. Validate before allocating.
pub async fn read_frame<R: AsyncRead + Unpin, T: DeserializeOwned>(
    reader: &mut R,
) -> io::Result<T> {
    let len = reader.read_u32().await? as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid IPC frame length",
        ));
    }
    let mut bytes = vec![0; len];
    reader.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    value: &T,
) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "IPC frame too large",
        ));
    }
    writer.write_u32(bytes.len() as u32).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn framed_messages_are_not_merged() {
        let (mut tx, mut rx) = tokio::io::duplex(256);
        write_frame(&mut tx, &Request::Hello { version: VERSION })
            .await
            .unwrap();
        write_frame(&mut tx, &Request::Status).await.unwrap();
        assert!(matches!(
            read_frame::<_, Request>(&mut rx).await.unwrap(),
            Request::Hello { version: VERSION }
        ));
        assert!(matches!(
            read_frame::<_, Request>(&mut rx).await.unwrap(),
            Request::Status
        ));
    }

    #[tokio::test]
    async fn oversized_frames_are_rejected_before_the_body_is_read() {
        let (mut tx, mut rx) = tokio::io::duplex(16);
        tx.write_u32(MAX_FRAME as u32 + 1).await.unwrap();
        assert_eq!(
            read_frame::<_, Request>(&mut rx).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn truncated_and_invalid_frames_are_rejected() {
        for bytes in [
            vec![0, 0, 0, 0],
            vec![0, 0, 0, 5, b'{'],
            vec![0, 0, 0, 1, b'?'],
        ] {
            let mut input = bytes.as_slice();
            assert!(read_frame::<_, Request>(&mut input).await.is_err());
        }
    }
}
