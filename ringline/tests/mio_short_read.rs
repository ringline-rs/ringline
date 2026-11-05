//! On Linux TCP the mio backend ends a drain at a read that leaves its buffer
//! unfilled (#395). A short read does not always mean the socket is empty, so
//! these are the cases it must not strand bytes in.

#![cfg(all(target_os = "linux", not(has_io_uring)))]
#![allow(clippy::manual_async_fn)]

mod common;

use std::future::Future;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::time::Duration;

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder};

const EACH_SIDE: usize = 100;

fn config() -> ConfigBuilder {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(64, 16384)
}

/// Blocks the worker until the client's bytes are queued, then answers once it
/// has read them all.
struct ReplyAfterAll;

impl AsyncEventHandler for ReplyAfterAll {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            std::thread::sleep(Duration::from_millis(50));
            let n = conn
                .with_data(|data| {
                    if data.len() < 2 * EACH_SIDE {
                        ParseResult::NeedMore
                    } else {
                        ParseResult::Consumed(data.len())
                    }
                })
                .await;
            assert_eq!(n, 2 * EACH_SIDE);
            let _ = conn.send_nowait(b"done");
            ringline::sleep(Duration::from_millis(50)).await;
            let _ = ringline::request_shutdown();
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        ReplyAfterAll
    }
}

/// Bytes, an urgent byte, and bytes. A read stops at the urgent mark, and the
/// urgent byte is out of band, so the server sees `2 * EACH_SIDE` bytes.
fn send_around_an_urgent_byte(fd: libc::c_int, write: &mut impl Write) {
    write.write_all(&[b'A'; EACH_SIDE]).unwrap();
    let sent = unsafe { libc::send(fd, b"X".as_ptr().cast(), 1, libc::MSG_OOB) };
    assert_eq!(sent, 1, "{}", std::io::Error::last_os_error());
    write.write_all(&[b'C'; EACH_SIDE]).unwrap();
}

#[test]
fn bytes_behind_a_tcp_urgent_mark_are_read() {
    let (runtime, handles) = RinglineBuilder::new(config().build().expect("valid config"))
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<ReplyAfterAll>()
        .expect("launch");
    let mut client = TcpStream::connect(runtime.bound_addr().expect("bound")).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    send_around_an_urgent_byte(client.as_raw_fd(), &mut client.try_clone().unwrap());
    let mut reply = [0u8; 4];
    client.read_exact(&mut reply).expect("the reply");
    assert_eq!(&reply, b"done");
    common::join_workers(&runtime, handles);
}

/// Send `data` with one fd attached. A Unix stream read stops at the end of a
/// message that carries fds, with no event for what follows.
fn send_with_an_fd(socket: &UnixStream, data: &[u8]) {
    let fd = socket.as_raw_fd();
    let mut iov = libc::iovec {
        iov_base: data.as_ptr().cast_mut().cast(),
        iov_len: data.len(),
    };
    #[repr(align(8))]
    struct Control([u8; 32]);
    let mut control = Control([0; 32]);
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.0.as_mut_ptr().cast();
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(4) } as _;
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(4) as _;
        libc::CMSG_DATA(cmsg)
            .cast::<libc::c_int>()
            .write_unaligned(fd);
    }
    let sent = unsafe { libc::sendmsg(fd, &msg, 0) };
    assert_eq!(sent, data.len() as isize);
}

#[test]
fn bytes_behind_a_message_carrying_an_fd_are_read() {
    let path = std::env::temp_dir().join(format!("ringline-short-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let (runtime, handles) = RinglineBuilder::new(config().build().expect("valid config"))
        .bind_unix(&path)
        .launch::<ReplyAfterAll>()
        .expect("launch");
    let mut client = UnixStream::connect(&path).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    send_with_an_fd(&client, &[b'A'; EACH_SIDE]);
    client.write_all(&[b'C'; EACH_SIDE]).unwrap();
    let mut reply = [0u8; 4];
    client.read_exact(&mut reply).expect("the reply");
    assert_eq!(&reply, b"done");
    common::join_workers(&runtime, handles);
    let _ = std::fs::remove_file(&path);
}

/// A forward delivers every byte and sees the FIN. The read that resumes a held
/// forward has no event behind it, so it does not stop at a short read. This
/// test does not reach that path: the sink's kernel buffers take these bytes.
#[test]
fn a_forward_delivers_every_byte_and_the_fin() {
    const TOTAL: usize = 1 << 20;
    static SINK: Mutex<Option<std::net::SocketAddr>> = Mutex::new(None);

    struct Forwarder;
    impl AsyncEventHandler for Forwarder {
        fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
            async move {
                let addr = SINK.lock().unwrap().expect("set before launch");
                let sink = ringline::connect(addr).await.unwrap();
                let (mut sink_send, _sink_recv) = sink.split();
                let (_send, mut recv) = conn.split();
                let _ = recv.forward_to_conn(&mut sink_send, 2 * TOTAL).await;
            }
        }
        fn create_for_worker(_id: usize) -> Self {
            Forwarder
        }
    }

    let sink = TcpListener::bind("127.0.0.1:0").unwrap();
    *SINK.lock().unwrap() = Some(sink.local_addr().unwrap());
    let config = config().forward_hold_cap(1).build().expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Forwarder>()
        .expect("launch");
    let mut client = TcpStream::connect(runtime.bound_addr().expect("bound")).unwrap();
    let (mut sink_side, _) = sink.accept().unwrap();
    // The forward arms before the first byte.
    std::thread::sleep(Duration::from_millis(50));
    let writer = std::thread::spawn(move || {
        client.write_all(&vec![7u8; TOTAL]).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        client
    });
    sink_side
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut received = 0;
    let mut buf = vec![0u8; 1 << 20];
    while received < TOTAL {
        match sink_side.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => received += n,
            Err(e) => panic!("read after {received} of {TOTAL} bytes: {e}"),
        }
    }
    assert_eq!(received, TOTAL);
    // The source's FIN ends the forward and its task, which closes the sink.
    assert_eq!(
        sink_side
            .read(&mut buf)
            .expect("the FIN reached the forward"),
        0
    );
    let _client = writer.join().expect("writer");
    runtime.shutdown();
    common::join_workers(&runtime, handles);
}
