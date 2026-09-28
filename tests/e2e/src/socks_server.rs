//! A SOCKS5 server for tests. It accepts every CONNECT without contacting the
//! target and answers with an HTTP response containing a marker and the
//! requested target.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub struct TestServer {
    pub addr: SocketAddr,
    /// Targets of the CONNECT requests answered so far.
    pub targets: Arc<Mutex<Vec<String>>>,
    pub udp_targets: Arc<Mutex<Vec<String>>>,
}

pub fn start(listen: SocketAddr, marker: &str) -> io::Result<TestServer> {
    let listener = TcpListener::bind(listen)?;
    let addr = listener.local_addr()?;
    let targets = Arc::new(Mutex::new(Vec::new()));
    let udp_targets = Arc::new(Mutex::new(Vec::new()));
    let udp_seen = Arc::clone(&udp_targets);
    let (seen, marker) = (Arc::clone(&targets), marker.to_owned());
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let (seen, marker) = (Arc::clone(&seen), marker.clone());
            let udp_seen = Arc::clone(&udp_seen);
            thread::spawn(move || {
                let _ = serve(stream, &marker, &seen, &udp_seen);
            });
        }
    });
    Ok(TestServer {
        addr,
        targets,
        udp_targets,
    })
}

fn serve(
    mut stream: TcpStream,
    marker: &str,
    seen: &Mutex<Vec<String>>,
    udp_seen: &Mutex<Vec<String>>,
) -> io::Result<()> {
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
    if request[1] == 3 {
        return serve_udp(stream, marker, udp_seen);
    }
    if request[1] != 1 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;

    // TCP reads need not contain a full request. Closing with unread request
    // bytes can reset the socket on Windows and truncate our test response.
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte)?;
        request.push(byte[0]);
        if request.len() > 8192 {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    let body = format!("{marker} {target}");
    seen.lock().unwrap().push(target);
    let response = format!(
        "HTTP/1.0 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    Ok(())
}

fn serve_udp(mut control: TcpStream, marker: &str, seen: &Mutex<Vec<String>>) -> io::Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    let port = socket.local_addr()?.port().to_be_bytes();
    control.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, port[0], port[1]])?;
    control.set_nonblocking(true)?;
    let mut buffer = vec![0u8; 65_536];
    loop {
        match control.peek(&mut [0u8; 1]) {
            Ok(0) => return Ok(()),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
            Err(err) => return Err(err),
            _ => {}
        }
        let (len, client) = match socket.recv_from(&mut buffer) {
            Ok(received) => received,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(err) => return Err(err),
        };
        if len < 4 || buffer[..3] != [0, 0, 0] {
            continue;
        }
        let (host, header) = match buffer[3] {
            1 if len >= 10 => (
                Ipv4Addr::from(<[u8; 4]>::try_from(&buffer[4..8]).unwrap()).to_string(),
                10,
            ),
            4 if len >= 22 => (
                format!(
                    "[{}]",
                    Ipv6Addr::from(<[u8; 16]>::try_from(&buffer[4..20]).unwrap())
                ),
                22,
            ),
            _ => continue,
        };
        let port = u16::from_be_bytes([buffer[header - 2], buffer[header - 1]]);
        let target = format!("{host}:{port}");
        seen.lock().unwrap().push(target.clone());
        let mut response = buffer[..header].to_vec();
        response.extend(format!("{marker} {target} {}", len - header).bytes());
        socket.send_to(&response, client)?;
    }
}
