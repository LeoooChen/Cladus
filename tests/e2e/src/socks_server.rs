//! A SOCKS5 server for tests. It accepts every CONNECT without contacting the
//! target and answers with an HTTP response containing a marker and the
//! requested target.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub struct TestServer {
    pub addr: SocketAddr,
    /// Targets of the CONNECT requests answered so far.
    pub targets: Arc<Mutex<Vec<String>>>,
}

pub fn start(listen: SocketAddr, marker: &str) -> io::Result<TestServer> {
    let listener = TcpListener::bind(listen)?;
    let addr = listener.local_addr()?;
    let targets = Arc::new(Mutex::new(Vec::new()));
    let (seen, marker) = (Arc::clone(&targets), marker.to_owned());
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let (seen, marker) = (Arc::clone(&seen), marker.clone());
            thread::spawn(move || {
                if let Ok(target) = serve(stream, &marker) {
                    seen.lock().unwrap().push(target);
                }
            });
        }
    });
    Ok(TestServer { addr, targets })
}

fn serve(mut stream: TcpStream, marker: &str) -> io::Result<String> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut head = [0u8; 2];
    stream.read_exact(&mut head)?;
    let mut methods = vec![0u8; usize::from(head[1])];
    stream.read_exact(&mut methods)?;
    stream.write_all(&[5, 0])?;

    let mut request = [0u8; 4];
    stream.read_exact(&mut request)?;
    let host = match request[3] {
        1 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip)?;
            Ipv4Addr::from(ip).to_string()
        }
        4 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip)?;
            format!("[{}]", Ipv6Addr::from(ip))
        }
        3 => {
            let mut len = [0u8];
            stream.read_exact(&mut len)?;
            let mut name = vec![0u8; usize::from(len[0])];
            stream.read_exact(&mut name)?;
            String::from_utf8_lossy(&name).into_owned()
        }
        _ => return Err(io::ErrorKind::InvalidData.into()),
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port)?;
    let target = format!("{host}:{}", u16::from_be_bytes(port));
    stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;

    // Read the client's request, then answer and close.
    let mut buffer = [0u8; 1024];
    let _ = stream.read(&mut buffer)?;
    let body = format!("{marker} {target}");
    write!(
        stream,
        "HTTP/1.0 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    Ok(target)
}
