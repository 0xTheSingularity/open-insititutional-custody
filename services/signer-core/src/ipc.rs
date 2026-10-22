//! Bounded local IPC. The private DTOs cannot be reused as broadcast encoders.
//! The socket directory must be provisioned privately for the core/net pair;
//! neither participant nor chain private keys cross this interface.

use crate::{Outbound, SignedHalt, SignerCore};
use oic_canonical_encoding::{canonical_bytes, from_canonical_bytes};
use oic_domain_types::*;
use oic_peer_wire::{SessionControl, SessionReply, MAX_BODY_LEN};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    io::{Read, Write},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

const TIMEOUT: Duration = Duration::from_secs(2);
// A directed MPC frame includes its fixed header; controls share the same cap.
const MAX_IPC: usize = MAX_BODY_LEN + 1024;

#[derive(Serialize, Deserialize)]
enum Request {
    Control { from: NodeId, body: Box<SessionControl> },
    Deliver { from: NodeId, frame: Bytes },
    Outbound { offset: usize },
    Halt(SignedHalt),
}

#[derive(Serialize, Deserialize)]
enum Reply {
    Control(Box<SessionReply>),
    Outbound(Option<(NodeId, Bytes)>),
    Done,
}

fn failure() -> OicError {
    OicError::new(ErrorCode::AuthorityUnavailable, "signer-core IPC unavailable or invalid")
}

fn read<T: DeserializeOwned>(stream: &mut UnixStream) -> OicResult<T> {
    let mut length = [0; 4];
    stream.read_exact(&mut length).map_err(|_| failure())?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_IPC {
        return Err(failure());
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).map_err(|_| failure())?;
    from_canonical_bytes(&bytes).map_err(|_| failure())
}

fn write<T: Serialize>(stream: &mut UnixStream, value: &T) -> OicResult<()> {
    let bytes = canonical_bytes(value).map_err(|_| failure())?;
    if bytes.len() > MAX_IPC {
        return Err(failure());
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes()).and_then(|_| stream.write_all(&bytes)).map_err(|_| failure())
}

fn configure(stream: &UnixStream) -> OicResult<()> {
    stream.set_read_timeout(Some(TIMEOUT)).and_then(|_| stream.set_write_timeout(Some(TIMEOUT))).map_err(|_| failure())
}

/// macOS and the BSDs copy the listener's O_NONBLOCK flag to accepted sockets
/// (Linux does not). A non-blocking socket ignores the timeouts, so a client
/// slower than `accept` would fail with WouldBlock instead of being read.
fn accepted(stream: &UnixStream) -> OicResult<()> {
    stream.set_nonblocking(false).map_err(|_| failure())?;
    configure(stream)
}

/// Only a private, pre-existing directory is accepted. An existing socket is
/// never unlinked automatically: a second core must not steal its endpoint.
pub struct Server {
    listener: UnixListener,
    path: PathBuf,
    core: Arc<SignerCore>,
}

impl Server {
    pub fn bind(path: impl AsRef<Path>, core: Arc<SignerCore>) -> OicResult<Self> {
        let path = path.as_ref();
        let parent = path.parent().ok_or_else(failure)?;
        let metadata = std::fs::symlink_metadata(parent).map_err(|_| failure())?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(failure());
        }
        let listener = UnixListener::bind(path).map_err(|_| failure())?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|_| failure())?;
        listener.set_nonblocking(true).map_err(|_| failure())?;
        Ok(Self { listener, path: path.to_owned(), core })
    }

    pub fn serve(&self, stop: &AtomicBool) -> OicResult<()> {
        while !stop.load(Ordering::Acquire) {
            match self.listener.accept() {
                Ok((mut stream, _)) => {
                    // A malformed client loses this connection, not the server.
                    let _ = self.connection(&mut stream);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(5)),
                Err(_) => return Err(failure()),
            }
        }
        Ok(())
    }

    fn connection(&self, stream: &mut UnixStream) -> OicResult<()> {
        accepted(stream)?;
        let response = match read::<Request>(stream)? {
            Request::Control { from, body } => Ok(Reply::Control(Box::new(self.core.control(&from, &body)))),
            Request::Deliver { from, frame } => self.core.deliver(&from, frame.as_slice()).map(|_| Reply::Done),
            Request::Outbound { offset } => Ok(Reply::Outbound(self.core.outbound_at(offset).map(|m| (m.to, Bytes(m.frame))))),
            Request::Halt(command) => self.core.halt(&command).map(|_| Reply::Done),
        };
        write(stream, &response)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[derive(Clone)]
pub struct Client {
    path: PathBuf,
}

impl Client {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn call(&self, request: Request) -> OicResult<Reply> {
        let mut stream = UnixStream::connect(&self.path).map_err(|_| failure())?;
        configure(&stream)?;
        write(&mut stream, &request)?;
        read::<OicResult<Reply>>(&mut stream)?
    }

    pub fn control(&self, from: &NodeId, body: SessionControl) -> OicResult<SessionReply> {
        match self.call(Request::Control { from: from.clone(), body: Box::new(body) })? {
            Reply::Control(reply) => Ok(*reply),
            _ => Err(failure()),
        }
    }

    pub fn deliver(&self, from: &NodeId, frame: Vec<u8>) -> OicResult<()> {
        match self.call(Request::Deliver { from: from.clone(), frame: Bytes(frame) })? {
            Reply::Done => Ok(()),
            _ => Err(failure()),
        }
    }

    /// Poll from offset zero on every retransmission sweep. Each reply contains
    /// at most one directed frame, so session count never widens the IPC cap.
    pub fn outbound_at(&self, offset: usize) -> OicResult<Option<Outbound>> {
        match self.call(Request::Outbound { offset })? {
            Reply::Outbound(message) => Ok(message.map(|(to, frame)| Outbound { to, frame: frame.0 })),
            _ => Err(failure()),
        }
    }

    pub fn halt(&self, command: SignedHalt) -> OicResult<()> {
        match self.call(Request::Halt(command))? {
            Reply::Done => Ok(()),
            _ => Err(failure()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The server's listener is non-blocking. A client whose request arrives
    /// after `accept` must still be read within the connection timeout.
    #[test]
    fn accepted_connection_waits_for_a_slow_client() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("core.sock");
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let client = std::thread::spawn({
            let path = path.clone();
            move || {
                let mut stream = UnixStream::connect(&path).unwrap();
                std::thread::sleep(Duration::from_millis(200));
                stream.write_all(b"ping").unwrap();
            }
        });
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(5)),
                Err(e) => panic!("accept failed: {e}"),
            }
        };
        accepted(&stream).unwrap();
        let mut request = [0; 4];
        stream.read_exact(&mut request).expect("the accepted connection must wait for the client's bytes");
        assert_eq!(&request, b"ping");
        client.join().unwrap();
    }
}
