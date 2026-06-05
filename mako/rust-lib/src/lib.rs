use bytes::Bytes;
use redis_protocol::resp3::{types::BytesFrame, types::DecodedFrame};
use socket2::{Domain, Protocol, Socket, Type};
use std::env;
use std::io::{BufWriter, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Barrier;

mod resp3_handler;
use resp3_handler::Resp3Handler;

// ===== FFI Types (must match transaction_ffi.h) =====

const TXN_OP_GET: u32 = 1;
const TXN_OP_SET: u32 = 2;
const TXN_OP_DEL: u32 = 3;
const TXN_OP_EXISTS: u32 = 4;

#[repr(C)]
struct TxnOperation {
    op: u32,
    key_ptr: *const u8,
    key_len: usize,
    val_ptr: *const u8,
    val_len: usize,
}

#[repr(C)]
struct TxnRequest {
    num_ops: usize,
    ops: *const TxnOperation,
}

#[repr(C)]
struct TxnOpResult {
    success: bool,
    value_present: bool,
    data_ptr: *mut u8,
    data_len: usize,
}

#[repr(C)]
struct TxnResponse {
    transaction_success: bool,
    num_results: usize,
    results: *mut TxnOpResult,
}

#[repr(C)]
#[derive(Default)]
struct MakoMetrics {
    txn_commits: u64,
    txn_aborts: u64,
    txn_retries: u64,
    uptime_seconds: u64,
}

#[cfg(not(test))]
extern "C" {
    fn cpp_worker_thread_init(thread_id: usize);

    // All operations (single or batched) go through the transaction interface
    fn cpp_execute_transaction(request: *const TxnRequest, response: *mut TxnResponse) -> bool;
    fn cpp_free_transaction_response(response: *mut TxnResponse);
    fn cpp_get_metrics(metrics: *mut MakoMetrics) -> bool;
}

#[cfg(test)]
unsafe fn cpp_worker_thread_init(_thread_id: usize) {}

#[cfg(test)]
unsafe fn cpp_execute_transaction(
    _request: *const TxnRequest,
    _response: *mut TxnResponse,
) -> bool {
    false
}

#[cfg(test)]
unsafe fn cpp_free_transaction_response(_response: *mut TxnResponse) {}

#[cfg(test)]
unsafe fn cpp_get_metrics(metrics: *mut MakoMetrics) -> bool {
    if metrics.is_null() {
        return false;
    }
    (*metrics).txn_commits = 11;
    (*metrics).txn_aborts = 2;
    (*metrics).txn_retries = 3;
    (*metrics).uptime_seconds = 42;
    true
}

// ===== OpCode and Command =====

#[derive(Copy, Clone, PartialEq)]
#[repr(u32)]
enum OpCode {
    Get = 1,
    Set = 2,
    Ping = 3,
    Multi = 4,
    Exec = 5,
    Discard = 6,
    Del = 7,
    Hello = 8,
    Client = 9,
    Command = 10,
    Reset = 11,
    Quit = 12,
    Select = 13,
    Auth = 14,
    Echo = 15,
    Info = 16,
    Exists = 17,
}

#[derive(Clone)]
struct Command {
    op: OpCode,
    keys: Vec<Bytes>,
    val: Option<Bytes>,
    args: Vec<Bytes>,
}

enum ParseError {
    Protocol(&'static str),
    UnknownCommand { name: Bytes, args: Vec<Bytes> },
    WrongArity { command: &'static str },
}

// ===== Transaction State =====

/// Per-connection transaction state
struct TransactionState {
    in_multi: bool,
    queued_commands: Vec<Command>,
}

impl TransactionState {
    fn new() -> Self {
        TransactionState {
            in_multi: false,
            queued_commands: Vec::new(),
        }
    }

    fn start_multi(&mut self) {
        self.in_multi = true;
        self.queued_commands.clear();
    }

    fn queue_command(&mut self, cmd: Command) {
        self.queued_commands.push(cmd);
    }

    fn discard(&mut self) {
        self.in_multi = false;
        self.queued_commands.clear();
    }

    fn take_commands(&mut self) -> Vec<Command> {
        self.in_multi = false;
        std::mem::take(&mut self.queued_commands)
    }
}

// ===== Client State =====

/// Per-connection client metadata for Redis handshake commands.
struct ClientState {
    protocol_version: u8,
    name: Option<Bytes>,
    close_after_reply: bool,
}

impl ClientState {
    fn new() -> Self {
        ClientState {
            protocol_version: 2,
            name: None,
            close_after_reply: false,
        }
    }

    fn reset(&mut self) {
        self.protocol_version = 2;
        self.name = None;
        self.close_after_reply = false;
    }
}

// ===== Helpers =====

#[inline]
fn ascii_eq_ci(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for (x, y) in a.iter().zip(b.iter()) {
        if x.to_ascii_lowercase() != y.to_ascii_lowercase() {
            return false;
        }
    }
    true
}

#[inline]
fn parse_opcode(name: &[u8]) -> Option<OpCode> {
    if ascii_eq_ci(name, b"GET") {
        Some(OpCode::Get)
    } else if ascii_eq_ci(name, b"SET") {
        Some(OpCode::Set)
    } else if ascii_eq_ci(name, b"DEL") {
        Some(OpCode::Del)
    } else if ascii_eq_ci(name, b"UNLINK") {
        Some(OpCode::Del)
    } else if ascii_eq_ci(name, b"EXISTS") {
        Some(OpCode::Exists)
    } else if ascii_eq_ci(name, b"PING") {
        Some(OpCode::Ping)
    } else if ascii_eq_ci(name, b"MULTI") {
        Some(OpCode::Multi)
    } else if ascii_eq_ci(name, b"EXEC") {
        Some(OpCode::Exec)
    } else if ascii_eq_ci(name, b"DISCARD") {
        Some(OpCode::Discard)
    } else if ascii_eq_ci(name, b"HELLO") {
        Some(OpCode::Hello)
    } else if ascii_eq_ci(name, b"CLIENT") {
        Some(OpCode::Client)
    } else if ascii_eq_ci(name, b"COMMAND") {
        Some(OpCode::Command)
    } else if ascii_eq_ci(name, b"RESET") {
        Some(OpCode::Reset)
    } else if ascii_eq_ci(name, b"QUIT") {
        Some(OpCode::Quit)
    } else if ascii_eq_ci(name, b"SELECT") {
        Some(OpCode::Select)
    } else if ascii_eq_ci(name, b"AUTH") {
        Some(OpCode::Auth)
    } else if ascii_eq_ci(name, b"ECHO") {
        Some(OpCode::Echo)
    } else if ascii_eq_ci(name, b"INFO") {
        Some(OpCode::Info)
    } else {
        None
    }
}

fn frame_to_bytes(frame: &BytesFrame) -> Option<Bytes> {
    use BytesFrame::*;
    match frame {
        BlobString { data, .. } | SimpleString { data, .. } => Some(Bytes::copy_from_slice(data)),
        Number { data, .. } => Some(Bytes::from(data.to_string())),
        _ => None,
    }
}

fn command_args(parts: &[BytesFrame]) -> Option<Vec<Bytes>> {
    let mut args = Vec::with_capacity(parts.len().saturating_sub(1));
    for part in parts.iter().skip(1) {
        args.push(frame_to_bytes(part)?);
    }
    Some(args)
}

fn wrong_arity(command: &'static str) -> ParseError {
    ParseError::WrongArity { command }
}

/// Parse RESP3 frame into Command
fn parse_resp3(frame: DecodedFrame<BytesFrame>) -> Result<Command, ParseError> {
    use BytesFrame::*;
    let f = frame
        .into_complete_frame()
        .map_err(|_| ParseError::Protocol("invalid frame"))?;
    let parts = match f {
        Array { data, .. } => data,
        _ => return Err(ParseError::Protocol("expected array")),
    };

    let name = match parts.get(0) {
        Some(BlobString { data, .. }) | Some(SimpleString { data, .. }) => data.as_ref(),
        _ => return Err(ParseError::Protocol("missing command")),
    };

    let Some(op) = parse_opcode(name) else {
        let args = command_args(&parts).unwrap_or_default();
        return Err(ParseError::UnknownCommand {
            name: Bytes::copy_from_slice(name),
            args,
        });
    };

    match op {
        OpCode::Get => {
            if parts.len() != 2 {
                return Err(wrong_arity("get"));
            }
            let key = match &parts[1] {
                BlobString { data, .. } | SimpleString { data, .. } => Bytes::copy_from_slice(data),
                _ => return Err(ParseError::Protocol("invalid argument")),
            };
            Ok(Command {
                op,
                keys: vec![key],
                val: None,
                args: command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            })
        }
        OpCode::Del | OpCode::Exists => {
            if parts.len() < 2 {
                return Err(wrong_arity(if op == OpCode::Del {
                    "del"
                } else {
                    "exists"
                }));
            }
            let mut keys = Vec::with_capacity(parts.len() - 1);
            for part in parts.iter().skip(1) {
                let key = match part {
                    BlobString { data, .. } | SimpleString { data, .. } => {
                        Bytes::copy_from_slice(data)
                    }
                    _ => return Err(ParseError::Protocol("invalid argument")),
                };
                keys.push(key);
            }
            Ok(Command {
                op,
                keys,
                val: None,
                args: command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            })
        }
        OpCode::Set => {
            if parts.len() != 3 {
                return Err(wrong_arity("set"));
            }
            let key = match &parts[1] {
                BlobString { data, .. } | SimpleString { data, .. } => Bytes::copy_from_slice(data),
                _ => return Err(ParseError::Protocol("invalid argument")),
            };
            let val = match &parts[2] {
                BlobString { data, .. } | SimpleString { data, .. } => Bytes::copy_from_slice(data),
                _ => return Err(ParseError::Protocol("invalid argument")),
            };
            Ok(Command {
                op,
                keys: vec![key],
                val: Some(val),
                args: command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            })
        }
        OpCode::Ping
        | OpCode::Multi
        | OpCode::Exec
        | OpCode::Discard
        | OpCode::Hello
        | OpCode::Client
        | OpCode::Command
        | OpCode::Reset
        | OpCode::Quit
        | OpCode::Select
        | OpCode::Auth
        | OpCode::Echo
        | OpCode::Info => {
            let command = match op {
                OpCode::Ping if parts.len() > 2 => Some("ping"),
                OpCode::Multi if parts.len() != 1 => Some("multi"),
                OpCode::Exec if parts.len() != 1 => Some("exec"),
                OpCode::Discard if parts.len() != 1 => Some("discard"),
                OpCode::Reset if parts.len() != 1 => Some("reset"),
                OpCode::Quit if parts.len() != 1 => Some("quit"),
                OpCode::Select if parts.len() != 2 => Some("select"),
                OpCode::Auth if parts.len() != 2 && parts.len() != 3 => Some("auth"),
                OpCode::Echo if parts.len() != 2 => Some("echo"),
                OpCode::Info if parts.len() > 2 => Some("info"),
                _ => None,
            };
            if let Some(command) = command {
                return Err(wrong_arity(command));
            }
            Ok(Command {
                op,
                keys: Vec::new(),
                val: None,
                args: command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            })
        }
    }
}

// ===== RESP Writers =====

#[inline]
fn write_simple_ok<W: Write>(w: &mut W) -> std::io::Result<()> {
    w.write_all(b"+OK\r\n")
}

#[inline]
fn write_simple_string<W: Write>(w: &mut W, data: &str) -> std::io::Result<()> {
    w.write_all(b"+")?;
    w.write_all(data.as_bytes())?;
    w.write_all(b"\r\n")
}

#[inline]
fn write_integer<W: Write>(w: &mut W, value: i64) -> std::io::Result<()> {
    let mut buf = itoa::Buffer::new();
    w.write_all(b":")?;
    w.write_all(buf.format(value).as_bytes())?;
    w.write_all(b"\r\n")
}

#[inline]
fn write_pong<W: Write>(w: &mut W) -> std::io::Result<()> {
    w.write_all(b"+PONG\r\n")
}

#[inline]
fn write_queued<W: Write>(w: &mut W) -> std::io::Result<()> {
    w.write_all(b"+QUEUED\r\n")
}

#[inline]
fn write_nil_bulk<W: Write>(w: &mut W) -> std::io::Result<()> {
    w.write_all(b"$-1\r\n")
}

#[inline]
fn write_bulk<W: Write>(w: &mut W, data: &[u8]) -> std::io::Result<()> {
    let mut buf = itoa::Buffer::new();
    w.write_all(b"$")?;
    w.write_all(buf.format(data.len()).as_bytes())?;
    w.write_all(b"\r\n")?;
    w.write_all(data)?;
    w.write_all(b"\r\n")
}

#[inline]
fn write_err<W: Write>(w: &mut W, msg: &str) -> std::io::Result<()> {
    w.write_all(b"-ERR ")?;
    w.write_all(msg.as_bytes())?;
    w.write_all(b"\r\n")
}

fn write_parse_error<W: Write>(w: &mut W, err: ParseError) -> std::io::Result<()> {
    match err {
        ParseError::Protocol(msg) => {
            w.write_all(b"-ERR protocol error: ")?;
            w.write_all(msg.as_bytes())?;
            w.write_all(b"\r\n")
        }
        ParseError::WrongArity { command } => {
            w.write_all(b"-ERR wrong number of arguments for '")?;
            w.write_all(command.as_bytes())?;
            w.write_all(b"' command\r\n")
        }
        ParseError::UnknownCommand { name, args } => {
            w.write_all(b"-ERR unknown command '")?;
            w.write_all(String::from_utf8_lossy(&name).as_bytes())?;
            w.write_all(b"'")?;
            if let Some(first) = args.first() {
                w.write_all(b", with args beginning with: '")?;
                w.write_all(String::from_utf8_lossy(first).as_bytes())?;
                w.write_all(b"'")?;
            }
            w.write_all(b"\r\n")
        }
    }
}

#[inline]
fn write_array_header<W: Write>(w: &mut W, len: usize) -> std::io::Result<()> {
    let mut buf = itoa::Buffer::new();
    w.write_all(b"*")?;
    w.write_all(buf.format(len).as_bytes())?;
    w.write_all(b"\r\n")
}

#[inline]
fn write_map_header<W: Write>(w: &mut W, len: usize) -> std::io::Result<()> {
    let mut buf = itoa::Buffer::new();
    w.write_all(b"%")?;
    w.write_all(buf.format(len).as_bytes())?;
    w.write_all(b"\r\n")
}

fn parse_protocol_version(arg: &[u8]) -> Option<u8> {
    if arg == b"2" {
        Some(2)
    } else if arg == b"3" {
        Some(3)
    } else {
        None
    }
}

// ===== Transaction FFI =====

/// Helper to build TxnOperation array from commands.
///
/// One Redis command can expand to multiple FFI operations. Variadic
/// DEL/UNLINK/EXISTS become one operation per key, then Rust aggregates
/// value_present back into one Redis integer reply.
fn build_txn_ops(commands: &[Command]) -> (Vec<TxnOperation>, Vec<(usize, usize)>) {
    let mut ops = Vec::new();
    let mut spans = Vec::with_capacity(commands.len());

    for cmd in commands {
        let start = ops.len();
        match cmd.op {
            OpCode::Get | OpCode::Set => {
                let Some(key) = cmd.keys.first() else {
                    spans.push((start, 0));
                    continue;
                };
                let (val_ptr, val_len) = if let Some(v) = &cmd.val {
                    (v.as_ptr(), v.len())
                } else {
                    (std::ptr::null(), 0)
                };
                ops.push(TxnOperation {
                    op: if cmd.op == OpCode::Get {
                        TXN_OP_GET
                    } else {
                        TXN_OP_SET
                    },
                    key_ptr: key.as_ptr(),
                    key_len: key.len(),
                    val_ptr,
                    val_len,
                });
            }
            OpCode::Del | OpCode::Exists => {
                let op = if cmd.op == OpCode::Del {
                    TXN_OP_DEL
                } else {
                    TXN_OP_EXISTS
                };
                for key in &cmd.keys {
                    ops.push(TxnOperation {
                        op,
                        key_ptr: key.as_ptr(),
                        key_len: key.len(),
                        val_ptr: std::ptr::null(),
                        val_len: 0,
                    });
                }
            }
            _ => {}
        }
        spans.push((start, ops.len() - start));
    }

    (ops, spans)
}

/// Execute a single command as a transaction (for non-MULTI operations)
/// Returns the result directly without array wrapper
fn ffi_execute_single<W: Write>(cmd: &Command, writer: &mut W) -> std::io::Result<()> {
    let single = [cmd.clone()];
    let (ops, spans) = build_txn_ops(&single);

    if ops.is_empty() {
        write_command_result(cmd, None, spans[0], writer)?;
        return Ok(());
    }

    let request = TxnRequest {
        num_ops: ops.len(),
        ops: ops.as_ptr(),
    };

    let mut response = TxnResponse {
        transaction_success: false,
        num_results: 0,
        results: std::ptr::null_mut(),
    };

    let call_ok = unsafe { cpp_execute_transaction(&request, &mut response) };

    if !call_ok || !response.transaction_success || response.num_results < ops.len() {
        unsafe { cpp_free_transaction_response(&mut response) };
        write_err(writer, "backend")?;
        return Ok(());
    }

    write_command_result(cmd, Some(&response), spans[0], writer)?;

    unsafe { cpp_free_transaction_response(&mut response) };
    Ok(())
}

/// Execute buffered commands as a single transaction (for MULTI/EXEC)
/// Returns results wrapped in an array
fn ffi_execute_transaction<W: Write>(commands: &[Command], writer: &mut W) -> std::io::Result<()> {
    if commands.is_empty() {
        // Empty transaction returns empty array
        write_array_header(writer, 0)?;
        return Ok(());
    }

    let (ops, spans) = build_txn_ops(commands);

    if ops.is_empty() {
        write_array_header(writer, commands.len())?;
        for (cmd, span) in commands.iter().zip(spans.iter().copied()) {
            write_command_result(cmd, None, span, writer)?;
        }
        return Ok(());
    }

    let request = TxnRequest {
        num_ops: ops.len(),
        ops: ops.as_ptr(),
    };

    let mut response = TxnResponse {
        transaction_success: false,
        num_results: 0,
        results: std::ptr::null_mut(),
    };

    let call_ok = unsafe { cpp_execute_transaction(&request, &mut response) };

    if !call_ok || !response.transaction_success || response.num_results < ops.len() {
        // Transaction failed - return nil (EXECABORT equivalent)
        unsafe { cpp_free_transaction_response(&mut response) };
        writer.write_all(b"*-1\r\n")?;
        return Ok(());
    }

    // Write one Redis array item per queued command, not per expanded FFI op.
    write_array_header(writer, commands.len())?;

    for (cmd, span) in commands.iter().zip(spans.iter().copied()) {
        write_command_result(cmd, Some(&response), span, writer)?;
    }

    // Free response resources
    unsafe { cpp_free_transaction_response(&mut response) };

    Ok(())
}

fn write_command_result<W: Write>(
    cmd: &Command,
    response: Option<&TxnResponse>,
    span: (usize, usize),
    writer: &mut W,
) -> std::io::Result<()> {
    if cmd.op == OpCode::Ping {
        if let Some(arg) = cmd.args.first() {
            write_bulk(writer, arg)?;
        } else {
            write_pong(writer)?;
        }
        return Ok(());
    }

    let Some(response) = response else {
        write_err(writer, "operation failed")?;
        return Ok(());
    };

    let (start, len) = span;
    if len == 0 || start + len > response.num_results {
        write_err(writer, "operation failed")?;
        return Ok(());
    }

    let first = unsafe { &*response.results.add(start) };
    match cmd.op {
        OpCode::Get => {
            if !first.success {
                write_err(writer, "operation failed")?;
            } else if first.value_present {
                if first.data_len > 0 {
                    if first.data_ptr.is_null() {
                        write_err(writer, "operation failed")?;
                    } else {
                        let data =
                            unsafe { std::slice::from_raw_parts(first.data_ptr, first.data_len) };
                        write_bulk(writer, data)?;
                    }
                } else {
                    write_bulk(writer, b"")?;
                }
            } else {
                write_nil_bulk(writer)?;
            }
        }
        OpCode::Set => {
            if first.success {
                write_simple_ok(writer)?;
            } else {
                write_err(writer, "operation failed")?;
            }
        }
        OpCode::Del | OpCode::Exists => {
            let mut count = 0i64;
            for index in start..start + len {
                let result = unsafe { &*response.results.add(index) };
                if !result.success {
                    write_err(writer, "operation failed")?;
                    return Ok(());
                }
                if result.value_present {
                    count += 1;
                }
            }
            write_integer(writer, count)?;
        }
        _ => write_err(writer, "operation failed")?,
    }
    Ok(())
}

// ===== Server =====

fn create_reuseport_listener(addr: &str) -> std::io::Result<TcpListener> {
    let addr: SocketAddr = addr
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(false)?;
    socket.set_nodelay(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;

    Ok(TcpListener::from(socket))
}

#[no_mangle]
pub extern "C" fn rust_init(n_threads: usize) -> bool {
    let host = env::var("MAKO_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("MAKO_PORT").unwrap_or_else(|_| "6380".to_string());
    let addr = format!("{host}:{port}");
    let barrier = Arc::new(Barrier::new(n_threads));
    let ready_count = Arc::new(AtomicUsize::new(0));

    println!(
        "Starting {} thread-per-core workers on {} (SO_REUSEPORT, 100% SYNC, MULTI/EXEC support)",
        n_threads, addr
    );

    for thread_id in 0..n_threads {
        let barrier = Arc::clone(&barrier);
        let ready_count = Arc::clone(&ready_count);
        let addr = addr.clone();

        std::thread::Builder::new()
            .name(format!("mako-worker-{}", thread_id))
            .spawn(move || {
                let listener = match create_reuseport_listener(&addr) {
                    Ok(l) => l,
                    Err(e) => {
                        eprintln!("[thread-{}] Failed to create listener: {e}", thread_id);
                        return;
                    }
                };

                unsafe {
                    cpp_worker_thread_init(thread_id);
                }

                let count = ready_count.fetch_add(1, Ordering::SeqCst) + 1;
                barrier.wait();

                if thread_id == 0 {
                    println!(
                        "All {} threads ready, accepting connections on {}",
                        count, addr
                    );
                }

                loop {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let _ = stream.set_nodelay(true);
                            if let Err(e) = handle_client_sync(&mut stream) {
                                eprintln!("Client handling error: {e}");
                            }
                        }
                        Err(e) => {
                            eprintln!("[thread-{}] Accept error: {e}", thread_id);
                        }
                    }
                }
            })
            .expect("Failed to spawn worker thread");
    }

    true
}

/// Handle client with MULTI/EXEC transaction support
fn handle_client_sync(stream: &mut TcpStream) -> std::io::Result<()> {
    let mut resp3 = Resp3Handler::new(10 * 1024 * 1024);
    let mut read_buf = [0u8; 16384];
    let mut writer = BufWriter::with_capacity(16384, stream.try_clone()?);
    let mut txn_state = TransactionState::new();
    let mut client_state = ClientState::new();

    loop {
        match stream.read(&mut read_buf) {
            Ok(0) => break,
            Ok(n) => resp3.read_bytes(&read_buf[..n]),
            Err(e) => return Err(e),
        }

        loop {
            match resp3.next_frame() {
                Ok(Some(frame)) => match parse_resp3(frame) {
                    Ok(cmd) => {
                        handle_command(&cmd, &mut txn_state, &mut client_state, &mut writer)?;
                    }
                    Err(err) => {
                        write_parse_error(&mut writer, err)?;
                    }
                },
                Ok(None) => break,
                Err(_) => {
                    write_err(&mut writer, "protocol error")?;
                    break;
                }
            }
        }

        writer.flush()?;
        if client_state.close_after_reply {
            break;
        }
    }

    Ok(())
}

fn write_hello_response<W: Write>(
    client_state: &ClientState,
    writer: &mut W,
) -> std::io::Result<()> {
    write_map_header(writer, 7)?;
    write_simple_string(writer, "server")?;
    write_simple_string(writer, "makoCon")?;
    write_simple_string(writer, "version")?;
    write_simple_string(writer, "0.1.0")?;
    write_simple_string(writer, "proto")?;
    write_integer(writer, client_state.protocol_version as i64)?;
    write_simple_string(writer, "id")?;
    write_integer(writer, 0)?;
    write_simple_string(writer, "mode")?;
    write_simple_string(writer, "standalone")?;
    write_simple_string(writer, "role")?;
    write_simple_string(writer, "master")?;
    write_simple_string(writer, "modules")?;
    write_array_header(writer, 0)
}

fn handle_hello<W: Write>(
    cmd: &Command,
    client_state: &mut ClientState,
    writer: &mut W,
) -> std::io::Result<()> {
    let mut index = 0;
    if let Some(first) = cmd.args.first() {
        let Some(proto) = parse_protocol_version(first) else {
            write_err(writer, "NOPROTO unsupported protocol version")?;
            return Ok(());
        };
        client_state.protocol_version = proto;
        index = 1;
    }

    while index < cmd.args.len() {
        let arg = cmd.args[index].as_ref();
        if ascii_eq_ci(arg, b"AUTH") {
            if index + 2 >= cmd.args.len() {
                write_err(writer, "syntax error")?;
                return Ok(());
            }
            index += 3;
        } else if ascii_eq_ci(arg, b"SETNAME") {
            if index + 1 >= cmd.args.len() {
                write_err(writer, "syntax error")?;
                return Ok(());
            }
            client_state.name = Some(cmd.args[index + 1].clone());
            index += 2;
        } else {
            write_err(writer, "syntax error")?;
            return Ok(());
        }
    }

    write_hello_response(client_state, writer)
}

fn handle_client_command<W: Write>(
    cmd: &Command,
    client_state: &mut ClientState,
    writer: &mut W,
) -> std::io::Result<()> {
    let Some(subcommand) = cmd.args.first() else {
        write_err(writer, "wrong number of arguments for 'client' command")?;
        return Ok(());
    };

    if ascii_eq_ci(subcommand, b"SETNAME") {
        if cmd.args.len() != 2 {
            write_err(
                writer,
                "wrong number of arguments for 'client setname' command",
            )?;
            return Ok(());
        }
        client_state.name = Some(cmd.args[1].clone());
        write_simple_ok(writer)
    } else if ascii_eq_ci(subcommand, b"GETNAME") {
        if cmd.args.len() != 1 {
            write_err(
                writer,
                "wrong number of arguments for 'client getname' command",
            )?;
            return Ok(());
        }
        match &client_state.name {
            Some(name) => write_bulk(writer, name),
            None => write_nil_bulk(writer),
        }
    } else if ascii_eq_ci(subcommand, b"ID") {
        if cmd.args.len() != 1 {
            write_err(writer, "wrong number of arguments for 'client id' command")?;
            return Ok(());
        }
        write_integer(writer, 0)
    } else if ascii_eq_ci(subcommand, b"SETINFO") {
        if cmd.args.len() < 3 {
            write_err(
                writer,
                "wrong number of arguments for 'client setinfo' command",
            )?;
            return Ok(());
        }
        write_simple_ok(writer)
    } else if ascii_eq_ci(subcommand, b"NO-EVICT") {
        if cmd.args.len() < 2 || cmd.args.len() > 3 {
            write_err(
                writer,
                "wrong number of arguments for 'client no-evict' command",
            )?;
            return Ok(());
        }
        write_simple_ok(writer)
    } else if ascii_eq_ci(subcommand, b"REPLY") {
        if cmd.args.len() != 2 {
            write_err(
                writer,
                "wrong number of arguments for 'client reply' command",
            )?;
            return Ok(());
        }
        write_simple_ok(writer)
    } else if ascii_eq_ci(subcommand, b"LIST") {
        if cmd.args.len() != 1 {
            write_err(
                writer,
                "wrong number of arguments for 'client list' command",
            )?;
            return Ok(());
        }
        let name = client_state
            .name
            .as_ref()
            .map(|n| String::from_utf8_lossy(n).into_owned())
            .unwrap_or_default();
        let line = format!("id=0 name={} flags=N db=0\r\n", name);
        write_bulk(writer, line.as_bytes())
    } else {
        write_err(writer, "unsupported CLIENT subcommand")
    }
}

fn handle_command_command<W: Write>(cmd: &Command, writer: &mut W) -> std::io::Result<()> {
    if cmd.args.is_empty() || ascii_eq_ci(cmd.args[0].as_ref(), b"INFO") {
        write_array_header(writer, 0)
    } else if ascii_eq_ci(cmd.args[0].as_ref(), b"DOCS") {
        write_map_header(writer, 0)
    } else if ascii_eq_ci(cmd.args[0].as_ref(), b"COUNT") {
        write_integer(writer, 0)
    } else {
        write_err(writer, "unsupported COMMAND subcommand")
    }
}

fn read_mako_metrics() -> MakoMetrics {
    let mut metrics = MakoMetrics::default();
    let ok = unsafe { cpp_get_metrics(&mut metrics) };
    if ok {
        metrics
    } else {
        MakoMetrics::default()
    }
}

fn append_server_info(out: &mut String, metrics: &MakoMetrics) {
    out.push_str("# Server\r\n");
    out.push_str("redis_version:7.2.0\r\n");
    out.push_str("mako_version:0.1.0\r\n");
    out.push_str("redis_mode:standalone\r\n");
    out.push_str("role:master\r\n");
    out.push_str("uptime_in_seconds:");
    out.push_str(&metrics.uptime_seconds.to_string());
    out.push_str("\r\n\r\n");
}

fn append_mako_info(out: &mut String, metrics: &MakoMetrics) {
    out.push_str("# Mako\r\n");
    out.push_str("mako_txn_commits:");
    out.push_str(&metrics.txn_commits.to_string());
    out.push_str("\r\n");
    out.push_str("mako_txn_aborts:");
    out.push_str(&metrics.txn_aborts.to_string());
    out.push_str("\r\n");
    out.push_str("mako_txn_retries:");
    out.push_str(&metrics.txn_retries.to_string());
    out.push_str("\r\n\r\n");
}

fn handle_info<W: Write>(cmd: &Command, writer: &mut W) -> std::io::Result<()> {
    let metrics = read_mako_metrics();
    let section = cmd
        .args
        .first()
        .map(|arg| arg.as_ref())
        .unwrap_or(b"default");
    let mut out = String::new();

    if ascii_eq_ci(section, b"default") || ascii_eq_ci(section, b"all") {
        append_server_info(&mut out, &metrics);
        append_mako_info(&mut out, &metrics);
    } else if ascii_eq_ci(section, b"server") {
        append_server_info(&mut out, &metrics);
    } else if ascii_eq_ci(section, b"mako") {
        append_mako_info(&mut out, &metrics);
    }

    write_bulk(writer, out.as_bytes())
}

/// Handle a single command, respecting transaction state
fn handle_command<W: Write>(
    cmd: &Command,
    txn_state: &mut TransactionState,
    client_state: &mut ClientState,
    writer: &mut W,
) -> std::io::Result<()> {
    match cmd.op {
        OpCode::Ping => {
            if txn_state.in_multi {
                txn_state.queue_command(cmd.clone());
                write_queued(writer)?;
            } else {
                if let Some(arg) = cmd.args.first() {
                    write_bulk(writer, arg)?;
                } else {
                    write_pong(writer)?;
                }
            }
        }
        OpCode::Hello => {
            handle_hello(cmd, client_state, writer)?;
        }
        OpCode::Client => {
            handle_client_command(cmd, client_state, writer)?;
        }
        OpCode::Command => {
            handle_command_command(cmd, writer)?;
        }
        OpCode::Reset => {
            txn_state.discard();
            client_state.reset();
            write_simple_string(writer, "RESET")?;
        }
        OpCode::Quit => {
            client_state.close_after_reply = true;
            write_simple_ok(writer)?;
        }
        OpCode::Select => {
            if cmd.args.len() == 1 && cmd.args[0].as_ref() == b"0" {
                write_simple_ok(writer)?;
            } else {
                write_err(writer, "DB index is out of range")?;
            }
        }
        OpCode::Auth => {
            if cmd.args.len() == 1 || cmd.args.len() == 2 {
                write_simple_ok(writer)?;
            } else {
                write_err(writer, "wrong number of arguments for 'auth' command")?;
            }
        }
        OpCode::Echo => {
            if cmd.args.len() == 1 {
                write_bulk(writer, &cmd.args[0])?;
            } else {
                write_err(writer, "wrong number of arguments for 'echo' command")?;
            }
        }
        OpCode::Info => {
            handle_info(cmd, writer)?;
        }
        OpCode::Multi => {
            if txn_state.in_multi {
                write_err(writer, "MULTI calls can not be nested")?;
            } else {
                txn_state.start_multi();
                write_simple_ok(writer)?;
            }
        }
        OpCode::Exec => {
            if !txn_state.in_multi {
                write_err(writer, "EXEC without MULTI")?;
            } else {
                let commands = txn_state.take_commands();
                ffi_execute_transaction(&commands, writer)?;
            }
        }
        OpCode::Discard => {
            if !txn_state.in_multi {
                write_err(writer, "DISCARD without MULTI")?;
            } else {
                txn_state.discard();
                write_simple_ok(writer)?;
            }
        }
        OpCode::Get | OpCode::Set | OpCode::Del | OpCode::Exists => {
            if txn_state.in_multi {
                // Queue command for later execution
                txn_state.queue_command(cmd.clone());
                write_queued(writer)?;
            } else {
                // Execute immediately as single-operation transaction
                // Uses ffi_execute_single which returns result without array wrapper
                ffi_execute_single(cmd, writer)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(op: OpCode, args: &[&[u8]]) -> Command {
        Command {
            op,
            keys: Vec::new(),
            val: None,
            args: args.iter().map(|arg| Bytes::copy_from_slice(arg)).collect(),
        }
    }

    fn data_command(op: OpCode, keys: &[&[u8]], val: Option<&[u8]>) -> Command {
        Command {
            op,
            keys: keys.iter().map(|key| Bytes::copy_from_slice(key)).collect(),
            val: val.map(Bytes::copy_from_slice),
            args: keys.iter().map(|key| Bytes::copy_from_slice(key)).collect(),
        }
    }

    fn run(
        cmd: Command,
        txn_state: &mut TransactionState,
        client_state: &mut ClientState,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        handle_command(&cmd, txn_state, client_state, &mut out).unwrap();
        out
    }

    fn run_raw(input: &[u8]) -> Vec<u8> {
        let mut resp3 = Resp3Handler::new(1024);
        let mut txn_state = TransactionState::new();
        let mut client_state = ClientState::new();
        let mut out = Vec::new();

        resp3.read_bytes(input);
        match resp3.next_frame().unwrap() {
            Some(frame) => match parse_resp3(frame) {
                Ok(cmd) => {
                    handle_command(&cmd, &mut txn_state, &mut client_state, &mut out).unwrap();
                }
                Err(err) => {
                    write_parse_error(&mut out, err).unwrap();
                }
            },
            None => write_err(&mut out, "protocol error").unwrap(),
        }

        out
    }

    #[test]
    fn hello_3_returns_resp3_capability_map() {
        let mut txn_state = TransactionState::new();
        let mut client_state = ClientState::new();

        let out = run(
            command(OpCode::Hello, &[b"3"]),
            &mut txn_state,
            &mut client_state,
        );
        let text = String::from_utf8(out).unwrap();

        assert!(text.starts_with("%"));
        assert!(text.contains("+server\r\n+makoCon\r\n"));
        assert!(text.contains("+proto\r\n:3\r\n"));
        assert_eq!(client_state.protocol_version, 3);
    }

    #[test]
    fn client_setname_and_getname_round_trip() {
        let mut txn_state = TransactionState::new();
        let mut client_state = ClientState::new();

        let set = run(
            command(OpCode::Client, &[b"SETNAME", b"phase2"]),
            &mut txn_state,
            &mut client_state,
        );
        let get = run(
            command(OpCode::Client, &[b"GETNAME"]),
            &mut txn_state,
            &mut client_state,
        );

        assert_eq!(set, b"+OK\r\n");
        assert_eq!(get, b"$6\r\nphase2\r\n");
    }

    #[test]
    fn documented_client_subcommands_return_parseable_replies() {
        let mut txn_state = TransactionState::new();
        let mut client_state = ClientState::new();
        client_state.name = Some(Bytes::from_static(b"phase2"));

        let no_evict = run(
            command(OpCode::Client, &[b"NO-EVICT", b"ON"]),
            &mut txn_state,
            &mut client_state,
        );
        let reply = run(
            command(OpCode::Client, &[b"REPLY", b"ON"]),
            &mut txn_state,
            &mut client_state,
        );
        let list = run(
            command(OpCode::Client, &[b"LIST"]),
            &mut txn_state,
            &mut client_state,
        );

        assert_eq!(no_evict, b"+OK\r\n");
        assert_eq!(reply, b"+OK\r\n");
        assert!(String::from_utf8(list).unwrap().contains("name=phase2"));
    }

    #[test]
    fn reset_clears_connection_state_and_transaction_queue() {
        let mut txn_state = TransactionState::new();
        let mut client_state = ClientState::new();
        txn_state.start_multi();
        client_state.name = Some(Bytes::from_static(b"phase2"));
        client_state.protocol_version = 3;

        let out = run(
            command(OpCode::Reset, &[]),
            &mut txn_state,
            &mut client_state,
        );

        assert_eq!(out, b"+RESET\r\n");
        assert!(!txn_state.in_multi);
        assert!(client_state.name.is_none());
        assert_eq!(client_state.protocol_version, 2);
    }

    #[test]
    fn quit_marks_connection_for_close() {
        let mut txn_state = TransactionState::new();
        let mut client_state = ClientState::new();

        let out = run(
            command(OpCode::Quit, &[]),
            &mut txn_state,
            &mut client_state,
        );

        assert_eq!(out, b"+OK\r\n");
        assert!(client_state.close_after_reply);
    }

    #[test]
    fn select_auth_and_echo_are_pure_connection_commands() {
        let mut txn_state = TransactionState::new();
        let mut client_state = ClientState::new();

        let select = run(
            command(OpCode::Select, &[b"0"]),
            &mut txn_state,
            &mut client_state,
        );
        let auth = run(
            command(OpCode::Auth, &[b"default", b"secret"]),
            &mut txn_state,
            &mut client_state,
        );
        let echo = run(
            command(OpCode::Echo, &[b"hello"]),
            &mut txn_state,
            &mut client_state,
        );

        assert_eq!(select, b"+OK\r\n");
        assert_eq!(auth, b"+OK\r\n");
        assert_eq!(echo, b"$5\r\nhello\r\n");
    }

    #[test]
    fn command_command_returns_a_parseable_reply() {
        let mut txn_state = TransactionState::new();
        let mut client_state = ClientState::new();

        let out = run(
            command(OpCode::Command, &[]),
            &mut txn_state,
            &mut client_state,
        );

        assert!(out.starts_with(b"*"));
    }

    #[test]
    fn info_server_returns_parseable_server_section() {
        let mut txn_state = TransactionState::new();
        let mut client_state = ClientState::new();

        let out = run(
            command(OpCode::Info, &[b"server"]),
            &mut txn_state,
            &mut client_state,
        );
        let text = String::from_utf8(out).unwrap();

        assert!(text.starts_with("$"));
        assert!(text.contains("# Server\r\n"));
        assert!(text.contains("redis_version:"));
        assert!(text.contains("mako_version:"));
        assert!(text.contains("uptime_in_seconds:42\r\n"));
    }

    #[test]
    fn info_mako_returns_transaction_metrics() {
        let mut txn_state = TransactionState::new();
        let mut client_state = ClientState::new();

        let out = run(
            command(OpCode::Info, &[b"mako"]),
            &mut txn_state,
            &mut client_state,
        );
        let text = String::from_utf8(out).unwrap();

        assert!(text.contains("# Mako\r\n"));
        assert!(text.contains("mako_txn_commits:11\r\n"));
        assert!(text.contains("mako_txn_aborts:2\r\n"));
        assert!(text.contains("mako_txn_retries:3\r\n"));
    }

    #[test]
    fn get_uses_value_present_for_empty_string() {
        let cmd = data_command(OpCode::Get, &[b"k"], None);
        let mut results = vec![TxnOpResult {
            success: true,
            value_present: true,
            data_ptr: std::ptr::null_mut(),
            data_len: 0,
        }];
        let response = TxnResponse {
            transaction_success: true,
            num_results: results.len(),
            results: results.as_mut_ptr(),
        };
        let mut out = Vec::new();

        write_command_result(&cmd, Some(&response), (0, 1), &mut out).unwrap();

        assert_eq!(out, b"$0\r\n\r\n");
    }

    #[test]
    fn get_missing_key_returns_nil_bulk() {
        let cmd = data_command(OpCode::Get, &[b"k"], None);
        let mut results = vec![TxnOpResult {
            success: true,
            value_present: false,
            data_ptr: std::ptr::null_mut(),
            data_len: 0,
        }];
        let response = TxnResponse {
            transaction_success: true,
            num_results: results.len(),
            results: results.as_mut_ptr(),
        };
        let mut out = Vec::new();

        write_command_result(&cmd, Some(&response), (0, 1), &mut out).unwrap();

        assert_eq!(out, b"$-1\r\n");
    }

    #[test]
    fn duplicate_exists_counts_each_matching_argument() {
        let cmd = data_command(OpCode::Exists, &[b"k", b"k", b"k"], None);
        let mut results = vec![
            TxnOpResult {
                success: true,
                value_present: true,
                data_ptr: std::ptr::null_mut(),
                data_len: 0,
            },
            TxnOpResult {
                success: true,
                value_present: true,
                data_ptr: std::ptr::null_mut(),
                data_len: 0,
            },
            TxnOpResult {
                success: true,
                value_present: true,
                data_ptr: std::ptr::null_mut(),
                data_len: 0,
            },
        ];
        let response = TxnResponse {
            transaction_success: true,
            num_results: results.len(),
            results: results.as_mut_ptr(),
        };
        let mut out = Vec::new();

        write_command_result(&cmd, Some(&response), (0, 3), &mut out).unwrap();

        assert_eq!(out, b":3\r\n");
    }

    #[test]
    fn unlink_parses_as_delete() {
        let out = run_raw(b"*2\r\n$6\r\nUNLINK\r\n$1\r\nk\r\n");

        assert_eq!(out, b"-ERR backend\r\n");
    }

    #[test]
    fn ping_inside_multi_is_queued_and_returned_by_exec() {
        let mut txn_state = TransactionState::new();
        let mut client_state = ClientState::new();

        let multi = run(
            command(OpCode::Multi, &[]),
            &mut txn_state,
            &mut client_state,
        );
        let ping = run(
            command(OpCode::Ping, &[]),
            &mut txn_state,
            &mut client_state,
        );
        let exec = run(
            command(OpCode::Exec, &[]),
            &mut txn_state,
            &mut client_state,
        );

        assert_eq!(multi, b"+OK\r\n");
        assert_eq!(ping, b"+QUEUED\r\n");
        assert_eq!(exec, b"*1\r\n+PONG\r\n");
    }

    #[test]
    fn unknown_command_reports_command_and_first_arg() {
        let out = run_raw(b"*2\r\n$3\r\nFOO\r\n$3\r\nbar\r\n");

        assert_eq!(
            out,
            b"-ERR unknown command 'FOO', with args beginning with: 'bar'\r\n"
        );
    }

    #[test]
    fn wrong_arity_reports_command_name() {
        let out = run_raw(b"*1\r\n$3\r\nGET\r\n");

        assert_eq!(out, b"-ERR wrong number of arguments for 'get' command\r\n");
    }

    #[test]
    fn non_array_frame_reports_protocol_error() {
        let out = run_raw(b"+PING\r\n");

        assert_eq!(out, b"-ERR protocol error: expected array\r\n");
    }
}
