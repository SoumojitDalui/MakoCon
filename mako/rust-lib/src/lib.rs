use bytes::Bytes;
use redis_protocol::resp3::{types::BytesFrame, types::DecodedFrame};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::env;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Barrier;
use std::sync::{Mutex, OnceLock};

mod resp3_handler;
use resp3_handler::Resp3Handler;

static CONNECTED_CLIENTS: AtomicUsize = AtomicUsize::new(0);
static TOTAL_CONNECTIONS_RECEIVED: AtomicUsize = AtomicUsize::new(0);
static NEXT_CLIENT_ID: AtomicUsize = AtomicUsize::new(1);
static NEXT_SCAN_CURSOR_ID: AtomicUsize = AtomicUsize::new(1);
static SCAN_CURSORS: OnceLock<Mutex<HashMap<usize, Bytes>>> = OnceLock::new();

// ===== FFI Types (must match transaction_ffi.h) =====
// Redis-visible keys must not use the 0x01 prefix. The C++ executor stores
// TTL metadata under "\x01TTL:<key>" and keeps expiry checks inside the same
// transaction as the user-key operation.

const TXN_OP_GET: u32 = 1;
const TXN_OP_SET: u32 = 2;
const TXN_OP_DEL: u32 = 3;
const TXN_OP_EXISTS: u32 = 4;
const TXN_OP_APPEND: u32 = 5;
const TXN_OP_STRLEN: u32 = 6;
const TXN_OP_INCRBY: u32 = 7;
const TXN_OP_INCRBYFLOAT: u32 = 8;
const TXN_OP_EXPIRE: u32 = 9;
const TXN_OP_TTL: u32 = 10;
const TXN_OP_PERSIST: u32 = 11;
const TXN_OP_SCAN: u32 = 12;
const TXN_OP_SADD: u32 = 13;
const TXN_OP_SREM: u32 = 14;
const TXN_OP_SISMEMBER: u32 = 15;
const TXN_OP_SCARD: u32 = 16;
const TXN_OP_SMEMBERS: u32 = 17;
const TXN_OP_SPOP: u32 = 18;
const TXN_OP_SRANDMEMBER: u32 = 19;
const TXN_OP_SMOVE: u32 = 20;
const TXN_OP_SET_ALGEBRA: u32 = 21;
const TXN_OP_TYPE: u32 = 22;
const TXN_OP_LPUSH: u32 = 23;
const TXN_OP_RPUSH: u32 = 24;
const TXN_OP_LPOP: u32 = 25;
const TXN_OP_RPOP: u32 = 26;
const TXN_OP_LLEN: u32 = 27;
const TXN_OP_LINDEX: u32 = 28;
const TXN_OP_LRANGE: u32 = 29;
const TXN_OP_LSET: u32 = 30;
const TXN_OP_LREM: u32 = 31;
const TXN_OP_LTRIM: u32 = 32;
const TXN_OP_LINSERT: u32 = 33;
const TXN_OP_LMOVE: u32 = 34;
const TXN_OP_LPOS: u32 = 35;
const TXN_OP_ZADD: u32 = 36;
const TXN_OP_ZSCORE: u32 = 37;
const TXN_OP_ZREM: u32 = 38;
const TXN_OP_ZCARD: u32 = 39;
const TXN_OP_ZRANGE: u32 = 40;
const TXN_OP_ZRANK: u32 = 41;
const TXN_OP_ZPOPMIN: u32 = 42;
const TXN_OP_ZCOUNT: u32 = 43;
const TXN_OP_ZSCAN: u32 = 44;

const TXN_FLAG_SET_NX: u32 = 1 << 0;
const TXN_FLAG_SET_XX: u32 = 1 << 1;
const TXN_FLAG_SET_RETURN_OLD: u32 = 1 << 2;
const TXN_FLAG_SET_INTEGER_REPLY: u32 = 1 << 3;
const TXN_FLAG_SET_REQUIRE_ABSENT_GROUP: u32 = 1 << 4;
const TXN_FLAG_SET_KEEP_TTL: u32 = 1 << 5;
const TXN_FLAG_TTL_MILLISECONDS: u32 = 1 << 6;
const TXN_FLAG_EXPIRE_NX: u32 = 1 << 7;
const TXN_FLAG_EXPIRE_XX: u32 = 1 << 8;
const TXN_FLAG_EXPIRE_GT: u32 = 1 << 9;
const TXN_FLAG_EXPIRE_LT: u32 = 1 << 10;
const TXN_FLAG_SCAN_COUNT_ONLY: u32 = 1 << 11;
const TXN_FLAG_SET_COUNT_GIVEN: u32 = 1 << 12;
const TXN_FLAG_SET_ALLOW_DUPLICATES: u32 = 1 << 13;
const TXN_FLAG_SET_ALGEBRA_UNION: u32 = 1 << 14;
const TXN_FLAG_SET_ALGEBRA_DIFF: u32 = 1 << 15;
const TXN_FLAG_SET_ALGEBRA_STORE: u32 = 1 << 16;
const TXN_FLAG_LIST_PUSH_IF_EXISTS: u32 = 1 << 17;
const TXN_FLAG_LIST_INSERT_BEFORE: u32 = 1 << 18;
const TXN_FLAG_LIST_SOURCE_LEFT: u32 = 1 << 19;
const TXN_FLAG_LIST_DEST_LEFT: u32 = 1 << 20;
const TXN_FLAG_LIST_COUNT_GIVEN: u32 = 1 << 21;
const TXN_FLAG_ZADD_NX: u32 = 1 << 22;
const TXN_FLAG_ZADD_XX: u32 = 1 << 23;
const TXN_FLAG_ZADD_CH: u32 = 1 << 24;
const TXN_FLAG_ZADD_INCR: u32 = 1 << 25;
const TXN_FLAG_ZADD_GT: u32 = 1 << 26;
const TXN_FLAG_ZADD_LT: u32 = 1 << 27;
const TXN_FLAG_Z_WITHSCORES: u32 = 1 << 28;
const TXN_FLAG_Z_REV: u32 = 1 << 29;
const TXN_FLAG_Z_BYSCORE: u32 = 1 << 30;
const TXN_FLAG_Z_COUNT_GIVEN: u32 = 1 << 31;

#[repr(C)]
struct TxnOperation {
    op: u32,
    key_ptr: *const u8,
    key_len: usize,
    val_ptr: *const u8,
    val_len: usize,
    flags: u32,
    expire_at_ms: i64,
    group_id: u32,
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
    int_value: i64,
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
    fn cpp_record_txn_retry();
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

#[cfg(test)]
unsafe fn cpp_record_txn_retry() {}

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
    MGet = 18,
    MSet = 19,
    MSetNx = 20,
    GetSet = 21,
    SetNx = 22,
    Append = 23,
    StrLen = 24,
    Incr = 25,
    IncrBy = 26,
    Decr = 27,
    DecrBy = 28,
    IncrByFloat = 29,
    Config = 30,
    Expire = 31,
    PExpire = 32,
    ExpireAt = 33,
    PExpireAt = 34,
    Ttl = 35,
    PTtl = 36,
    Persist = 37,
    Keys = 38,
    Scan = 39,
    DbSize = 40,
    HScan = 41,
    Type = 42,
    Wait = 43,
    SAdd = 44,
    SMembers = 45,
    SIsMember = 46,
    SRem = 47,
    SCard = 48,
    SMove = 49,
    SPop = 50,
    SRandMember = 51,
    SInter = 52,
    SUnion = 53,
    SDiff = 54,
    SInterStore = 55,
    SUnionStore = 56,
    SDiffStore = 57,
    LPush = 58,
    RPush = 59,
    LPop = 60,
    RPop = 61,
    LLen = 62,
    LIndex = 63,
    LRange = 64,
    LSet = 65,
    LRem = 66,
    LTrim = 67,
    LInsert = 68,
    LPushX = 69,
    RPushX = 70,
    LMove = 71,
    RPopLPush = 72,
    LPos = 73,
    ZAdd = 74,
    ZScore = 75,
    ZIncrBy = 76,
    ZRem = 77,
    ZCard = 78,
    ZRange = 79,
    ZRevRange = 80,
    ZRangeByScore = 81,
    ZRank = 82,
    ZRevRank = 83,
    ZCount = 84,
    ZPopMin = 85,
    ZPopMax = 86,
    ZScan = 87,
}

#[derive(Copy, Clone, PartialEq)]
enum SetCondition {
    None,
    Nx,
    Xx,
}

#[derive(Clone)]
struct Command {
    op: OpCode,
    keys: Vec<Bytes>,
    val: Option<Bytes>,
    values: Vec<Bytes>,
    args: Vec<Bytes>,
    set_condition: SetCondition,
    set_return_old: bool,
    set_integer_reply: bool,
    set_keep_ttl: bool,
    expire_at_ms: i64,
    expire_flags: u32,
    scan_count: i64,
    scan_prefix: Bytes,
    scan_type_matches: bool,
    set_count: Option<i64>,
}

impl Command {
    fn new(op: OpCode, keys: Vec<Bytes>, val: Option<Bytes>, args: Vec<Bytes>) -> Self {
        Command {
            op,
            keys,
            val,
            values: Vec::new(),
            args,
            set_condition: SetCondition::None,
            set_return_old: false,
            set_integer_reply: false,
            set_keep_ttl: false,
            expire_at_ms: -1,
            expire_flags: 0,
            scan_count: 10,
            scan_prefix: Bytes::new(),
            scan_type_matches: true,
            set_count: None,
        }
    }
}

enum ParseError {
    Protocol(&'static str),
    Error(&'static str),
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
    id: usize,
    protocol_version: u8,
    name: Option<Bytes>,
    close_after_reply: bool,
}

impl ClientState {
    fn new() -> Self {
        ClientState {
            id: NEXT_CLIENT_ID.fetch_add(1, Ordering::Relaxed),
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
    } else if ascii_eq_ci(name, b"MGET") {
        Some(OpCode::MGet)
    } else if ascii_eq_ci(name, b"MSET") {
        Some(OpCode::MSet)
    } else if ascii_eq_ci(name, b"MSETNX") {
        Some(OpCode::MSetNx)
    } else if ascii_eq_ci(name, b"GETSET") {
        Some(OpCode::GetSet)
    } else if ascii_eq_ci(name, b"SETNX") {
        Some(OpCode::SetNx)
    } else if ascii_eq_ci(name, b"APPEND") {
        Some(OpCode::Append)
    } else if ascii_eq_ci(name, b"STRLEN") {
        Some(OpCode::StrLen)
    } else if ascii_eq_ci(name, b"INCR") {
        Some(OpCode::Incr)
    } else if ascii_eq_ci(name, b"INCRBY") {
        Some(OpCode::IncrBy)
    } else if ascii_eq_ci(name, b"DECR") {
        Some(OpCode::Decr)
    } else if ascii_eq_ci(name, b"DECRBY") {
        Some(OpCode::DecrBy)
    } else if ascii_eq_ci(name, b"INCRBYFLOAT") {
        Some(OpCode::IncrByFloat)
    } else if ascii_eq_ci(name, b"EXPIRE") {
        Some(OpCode::Expire)
    } else if ascii_eq_ci(name, b"PEXPIRE") {
        Some(OpCode::PExpire)
    } else if ascii_eq_ci(name, b"EXPIREAT") {
        Some(OpCode::ExpireAt)
    } else if ascii_eq_ci(name, b"PEXPIREAT") {
        Some(OpCode::PExpireAt)
    } else if ascii_eq_ci(name, b"TTL") {
        Some(OpCode::Ttl)
    } else if ascii_eq_ci(name, b"PTTL") {
        Some(OpCode::PTtl)
    } else if ascii_eq_ci(name, b"PERSIST") {
        Some(OpCode::Persist)
    } else if ascii_eq_ci(name, b"KEYS") {
        Some(OpCode::Keys)
    } else if ascii_eq_ci(name, b"SCAN") {
        Some(OpCode::Scan)
    } else if ascii_eq_ci(name, b"DBSIZE") {
        Some(OpCode::DbSize)
    } else if ascii_eq_ci(name, b"HSCAN") {
        Some(OpCode::HScan)
    } else if ascii_eq_ci(name, b"TYPE") {
        Some(OpCode::Type)
    } else if ascii_eq_ci(name, b"WAIT") {
        Some(OpCode::Wait)
    } else if ascii_eq_ci(name, b"SADD") {
        Some(OpCode::SAdd)
    } else if ascii_eq_ci(name, b"SMEMBERS") {
        Some(OpCode::SMembers)
    } else if ascii_eq_ci(name, b"SISMEMBER") {
        Some(OpCode::SIsMember)
    } else if ascii_eq_ci(name, b"SREM") {
        Some(OpCode::SRem)
    } else if ascii_eq_ci(name, b"SCARD") {
        Some(OpCode::SCard)
    } else if ascii_eq_ci(name, b"SMOVE") {
        Some(OpCode::SMove)
    } else if ascii_eq_ci(name, b"SPOP") {
        Some(OpCode::SPop)
    } else if ascii_eq_ci(name, b"SRANDMEMBER") {
        Some(OpCode::SRandMember)
    } else if ascii_eq_ci(name, b"SINTER") {
        Some(OpCode::SInter)
    } else if ascii_eq_ci(name, b"SUNION") {
        Some(OpCode::SUnion)
    } else if ascii_eq_ci(name, b"SDIFF") {
        Some(OpCode::SDiff)
    } else if ascii_eq_ci(name, b"SINTERSTORE") {
        Some(OpCode::SInterStore)
    } else if ascii_eq_ci(name, b"SUNIONSTORE") {
        Some(OpCode::SUnionStore)
    } else if ascii_eq_ci(name, b"SDIFFSTORE") {
        Some(OpCode::SDiffStore)
    } else if ascii_eq_ci(name, b"LPUSH") {
        Some(OpCode::LPush)
    } else if ascii_eq_ci(name, b"RPUSH") {
        Some(OpCode::RPush)
    } else if ascii_eq_ci(name, b"LPOP") {
        Some(OpCode::LPop)
    } else if ascii_eq_ci(name, b"RPOP") {
        Some(OpCode::RPop)
    } else if ascii_eq_ci(name, b"LLEN") {
        Some(OpCode::LLen)
    } else if ascii_eq_ci(name, b"LINDEX") {
        Some(OpCode::LIndex)
    } else if ascii_eq_ci(name, b"LRANGE") {
        Some(OpCode::LRange)
    } else if ascii_eq_ci(name, b"LSET") {
        Some(OpCode::LSet)
    } else if ascii_eq_ci(name, b"LREM") {
        Some(OpCode::LRem)
    } else if ascii_eq_ci(name, b"LTRIM") {
        Some(OpCode::LTrim)
    } else if ascii_eq_ci(name, b"LINSERT") {
        Some(OpCode::LInsert)
    } else if ascii_eq_ci(name, b"LPUSHX") {
        Some(OpCode::LPushX)
    } else if ascii_eq_ci(name, b"RPUSHX") {
        Some(OpCode::RPushX)
    } else if ascii_eq_ci(name, b"LMOVE") {
        Some(OpCode::LMove)
    } else if ascii_eq_ci(name, b"RPOPLPUSH") {
        Some(OpCode::RPopLPush)
    } else if ascii_eq_ci(name, b"LPOS") {
        Some(OpCode::LPos)
    } else if ascii_eq_ci(name, b"ZADD") {
        Some(OpCode::ZAdd)
    } else if ascii_eq_ci(name, b"ZSCORE") {
        Some(OpCode::ZScore)
    } else if ascii_eq_ci(name, b"ZINCRBY") {
        Some(OpCode::ZIncrBy)
    } else if ascii_eq_ci(name, b"ZREM") {
        Some(OpCode::ZRem)
    } else if ascii_eq_ci(name, b"ZCARD") {
        Some(OpCode::ZCard)
    } else if ascii_eq_ci(name, b"ZRANGE") {
        Some(OpCode::ZRange)
    } else if ascii_eq_ci(name, b"ZREVRANGE") {
        Some(OpCode::ZRevRange)
    } else if ascii_eq_ci(name, b"ZRANGEBYSCORE") {
        Some(OpCode::ZRangeByScore)
    } else if ascii_eq_ci(name, b"ZRANK") {
        Some(OpCode::ZRank)
    } else if ascii_eq_ci(name, b"ZREVRANK") {
        Some(OpCode::ZRevRank)
    } else if ascii_eq_ci(name, b"ZCOUNT") {
        Some(OpCode::ZCount)
    } else if ascii_eq_ci(name, b"ZPOPMIN") {
        Some(OpCode::ZPopMin)
    } else if ascii_eq_ci(name, b"ZPOPMAX") {
        Some(OpCode::ZPopMax)
    } else if ascii_eq_ci(name, b"ZSCAN") {
        Some(OpCode::ZScan)
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
    } else if ascii_eq_ci(name, b"CONFIG") {
        Some(OpCode::Config)
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

fn part_to_bytes(part: &BytesFrame) -> Result<Bytes, ParseError> {
    match part {
        BytesFrame::BlobString { data, .. } | BytesFrame::SimpleString { data, .. } => {
            Ok(Bytes::copy_from_slice(data))
        }
        _ => Err(ParseError::Protocol("invalid argument")),
    }
}

fn validate_user_key(key: &Bytes) -> Result<(), ParseError> {
    if key.first() == Some(&0x01) {
        Err(ParseError::Error("invalid key: reserved internal prefix"))
    } else {
        Ok(())
    }
}

fn checked_abs_ms_from_seconds(amount: i64) -> Result<i64, ParseError> {
    amount
        .checked_mul(1000)
        .ok_or(ParseError::Protocol("invalid expire time"))
}

fn checked_relative_ms(now_ms: i64, amount_ms: i64) -> Result<i64, ParseError> {
    now_ms
        .checked_add(amount_ms)
        .ok_or(ParseError::Protocol("invalid expire time"))
}

fn ttl_ms_from_args(unit: &[u8], value: &[u8]) -> Result<i64, ParseError> {
    let text = std::str::from_utf8(value).map_err(|_| ParseError::Protocol("invalid argument"))?;
    let amount: i64 = text
        .parse()
        .map_err(|_| ParseError::Protocol("invalid argument"))?;
    if amount <= 0 {
        return Err(ParseError::Protocol("invalid argument"));
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ParseError::Protocol("invalid argument"))?
        .as_millis() as i64;
    if ascii_eq_ci(unit, b"EX") {
        checked_relative_ms(now_ms, checked_abs_ms_from_seconds(amount)?)
    } else if ascii_eq_ci(unit, b"PX") {
        checked_relative_ms(now_ms, amount)
    } else if ascii_eq_ci(unit, b"EXAT") {
        checked_abs_ms_from_seconds(amount)
    } else {
        Ok(amount)
    }
}

fn expire_at_ms_from_args(unit: &[u8], value: &[u8]) -> Result<i64, ParseError> {
    let text = std::str::from_utf8(value).map_err(|_| ParseError::Protocol("invalid argument"))?;
    let amount: i64 = text
        .parse()
        .map_err(|_| ParseError::Protocol("invalid argument"))?;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ParseError::Protocol("invalid argument"))?
        .as_millis() as i64;
    if ascii_eq_ci(unit, b"EXPIRE") {
        checked_relative_ms(now_ms, checked_abs_ms_from_seconds(amount)?)
    } else if ascii_eq_ci(unit, b"PEXPIRE") {
        checked_relative_ms(now_ms, amount)
    } else if ascii_eq_ci(unit, b"EXPIREAT") {
        checked_abs_ms_from_seconds(amount)
    } else {
        Ok(amount)
    }
}

fn parse_expire_modifier(arg: &[u8]) -> Result<u32, ParseError> {
    if ascii_eq_ci(arg, b"NX") {
        Ok(TXN_FLAG_EXPIRE_NX)
    } else if ascii_eq_ci(arg, b"XX") {
        Ok(TXN_FLAG_EXPIRE_XX)
    } else if ascii_eq_ci(arg, b"GT") {
        Ok(TXN_FLAG_EXPIRE_GT)
    } else if ascii_eq_ci(arg, b"LT") {
        Ok(TXN_FLAG_EXPIRE_LT)
    } else {
        Err(ParseError::Protocol("syntax error"))
    }
}

fn validate_expire_flags(flags: u32) -> Result<(), ParseError> {
    if (flags & TXN_FLAG_EXPIRE_NX) != 0
        && (flags & (TXN_FLAG_EXPIRE_XX | TXN_FLAG_EXPIRE_GT | TXN_FLAG_EXPIRE_LT)) != 0
    {
        return Err(ParseError::Error(
            "NX and XX, GT or LT options at the same time are not compatible",
        ));
    }
    if (flags & TXN_FLAG_EXPIRE_GT) != 0 && (flags & TXN_FLAG_EXPIRE_LT) != 0 {
        return Err(ParseError::Error(
            "GT and LT options at the same time are not compatible",
        ));
    }
    Ok(())
}

fn parse_positive_i64(arg: &[u8]) -> Result<i64, ParseError> {
    let text = std::str::from_utf8(arg).map_err(|_| ParseError::Protocol("invalid argument"))?;
    let value: i64 = text
        .parse()
        .map_err(|_| ParseError::Protocol("invalid argument"))?;
    if value <= 0 {
        Err(ParseError::Protocol("invalid argument"))
    } else {
        Ok(value)
    }
}

fn parse_i64_arg(arg: &[u8]) -> Result<i64, ParseError> {
    let text = std::str::from_utf8(arg).map_err(|_| ParseError::Protocol("invalid argument"))?;
    text.parse()
        .map_err(|_| ParseError::Protocol("invalid argument"))
}

fn parse_f64_arg(arg: &[u8]) -> Result<f64, ParseError> {
    let text = std::str::from_utf8(arg).map_err(|_| ParseError::Protocol("invalid argument"))?;
    let value: f64 = text
        .parse()
        .map_err(|_| ParseError::Protocol("invalid argument"))?;
    if value.is_nan() {
        Err(ParseError::Protocol("invalid argument"))
    } else {
        Ok(value)
    }
}

fn parse_zadd_score_arg(arg: &[u8]) -> Result<(), ParseError> {
    let value = parse_f64_arg(arg)?;
    if value.is_finite() {
        Ok(())
    } else {
        Err(ParseError::Protocol("invalid argument"))
    }
}

fn parse_zrange_bound_arg(arg: &[u8]) -> Result<(), ParseError> {
    let raw = if arg.first() == Some(&b'(') {
        &arg[1..]
    } else {
        arg
    };
    if ascii_eq_ci(raw, b"-inf") || ascii_eq_ci(raw, b"+inf") || ascii_eq_ci(raw, b"inf") {
        return Ok(());
    }
    parse_f64_arg(raw).map(|_| ())
}

fn parse_list_side(arg: &[u8]) -> Result<bool, ParseError> {
    if ascii_eq_ci(arg, b"LEFT") {
        Ok(true)
    } else if ascii_eq_ci(arg, b"RIGHT") {
        Ok(false)
    } else {
        Err(ParseError::Protocol("syntax error"))
    }
}

fn literal_prefix(pattern: &[u8]) -> Bytes {
    let mut out = Vec::new();
    let mut escaped = false;
    for &byte in pattern {
        if escaped {
            out.push(byte);
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if matches!(byte, b'*' | b'?' | b'[') {
            break;
        } else {
            out.push(byte);
        }
    }
    Bytes::from(out)
}

fn scan_cursor_from_arg(arg: &[u8]) -> Result<Bytes, ParseError> {
    if arg == b"0" {
        return Ok(Bytes::new());
    }
    let text = std::str::from_utf8(arg).map_err(|_| ParseError::Protocol("invalid cursor"))?;
    let cursor_id: usize = text
        .parse()
        .map_err(|_| ParseError::Protocol("invalid cursor"))?;
    let cursors = SCAN_CURSORS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cursors
        .lock()
        .map_err(|_| ParseError::Protocol("invalid cursor"))?;
    guard
        .remove(&cursor_id)
        .ok_or(ParseError::Protocol("invalid cursor"))
}

fn store_scan_cursor(cursor: &[u8]) -> String {
    if cursor.is_empty() {
        return "0".to_string();
    }
    let id = NEXT_SCAN_CURSOR_ID.fetch_add(1, Ordering::Relaxed);
    let cursors = SCAN_CURSORS.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = cursors.lock() {
        guard.insert(id, Bytes::copy_from_slice(cursor));
        id.to_string()
    } else {
        "0".to_string()
    }
}

fn glob_class_matches(pattern: &[u8], start: usize, value: u8) -> Option<(bool, usize)> {
    let mut index = start + 1;
    if index >= pattern.len() {
        return None;
    }
    let negated = matches!(pattern[index], b'^' | b'!');
    if negated {
        index += 1;
    }

    let mut matched = false;
    let mut saw_end = false;
    let mut previous: Option<u8> = None;
    while index < pattern.len() {
        let byte = pattern[index];
        if byte == b']' && previous.is_some() {
            saw_end = true;
            index += 1;
            break;
        }
        if byte == b'\\' && index + 1 < pattern.len() {
            let escaped = pattern[index + 1];
            if escaped == value {
                matched = true;
            }
            previous = Some(escaped);
            index += 2;
            continue;
        }
        if byte == b'-'
            && previous.is_some()
            && index + 1 < pattern.len()
            && pattern[index + 1] != b']'
        {
            let end = pattern[index + 1];
            let begin = previous.unwrap();
            if begin <= value && value <= end {
                matched = true;
            }
            previous = Some(end);
            index += 2;
            continue;
        }
        if byte == value {
            matched = true;
        }
        previous = Some(byte);
        index += 1;
    }

    if saw_end {
        Some((if negated { !matched } else { matched }, index))
    } else {
        None
    }
}

fn glob_matches(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star, mut match_after_star) = (None, 0usize);
    while t < text.len() {
        if p < pattern.len() && pattern[p] == b'[' {
            if let Some((matched, next_p)) = glob_class_matches(pattern, p, text[t]) {
                if matched {
                    p = next_p;
                    t += 1;
                } else if let Some(star_pos) = star {
                    p = star_pos + 1;
                    match_after_star += 1;
                    t = match_after_star;
                } else {
                    return false;
                }
            } else if pattern[p] == text[t] {
                p += 1;
                t += 1;
            } else if let Some(star_pos) = star {
                p = star_pos + 1;
                match_after_star += 1;
                t = match_after_star;
            } else {
                return false;
            }
        } else if p < pattern.len() && pattern[p] == b'\\' && p + 1 < pattern.len() {
            p += 1;
            if pattern[p] == text[t] {
                p += 1;
                t += 1;
            } else if let Some(star_pos) = star {
                p = star_pos + 1;
                match_after_star += 1;
                t = match_after_star;
            } else {
                return false;
            }
        } else if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            match_after_star = t;
        } else if let Some(star_pos) = star {
            p = star_pos + 1;
            match_after_star += 1;
            t = match_after_star;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
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
            let key = part_to_bytes(&parts[1])?;
            validate_user_key(&key)?;
            Ok(Command::new(
                op,
                vec![key],
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            ))
        }
        OpCode::MGet => {
            if parts.len() < 2 {
                return Err(wrong_arity("mget"));
            }
            let mut keys = Vec::with_capacity(parts.len() - 1);
            for part in parts.iter().skip(1) {
                let key = part_to_bytes(part)?;
                validate_user_key(&key)?;
                keys.push(key);
            }
            Ok(Command::new(
                op,
                keys,
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            ))
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
                let key = part_to_bytes(part)?;
                validate_user_key(&key)?;
                keys.push(key);
            }
            Ok(Command::new(
                op,
                keys,
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            ))
        }
        OpCode::Set => {
            if parts.len() < 3 {
                return Err(wrong_arity("set"));
            }
            let key = part_to_bytes(&parts[1])?;
            validate_user_key(&key)?;
            let val = part_to_bytes(&parts[2])?;
            let mut cmd = Command::new(
                op,
                vec![key],
                Some(val),
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            );
            let mut index = 3;
            let mut saw_expiry = false;
            while index < parts.len() {
                let arg = part_to_bytes(&parts[index])?;
                if ascii_eq_ci(arg.as_ref(), b"NX") {
                    if cmd.set_condition != SetCondition::None {
                        return Err(ParseError::Protocol("syntax error"));
                    }
                    cmd.set_condition = SetCondition::Nx;
                    index += 1;
                } else if ascii_eq_ci(arg.as_ref(), b"XX") {
                    if cmd.set_condition != SetCondition::None {
                        return Err(ParseError::Protocol("syntax error"));
                    }
                    cmd.set_condition = SetCondition::Xx;
                    index += 1;
                } else if ascii_eq_ci(arg.as_ref(), b"GET") {
                    cmd.set_return_old = true;
                    index += 1;
                } else if ascii_eq_ci(arg.as_ref(), b"KEEPTTL") {
                    if saw_expiry {
                        return Err(ParseError::Protocol("syntax error"));
                    }
                    cmd.set_keep_ttl = true;
                    index += 1;
                } else if ascii_eq_ci(arg.as_ref(), b"EX")
                    || ascii_eq_ci(arg.as_ref(), b"PX")
                    || ascii_eq_ci(arg.as_ref(), b"EXAT")
                    || ascii_eq_ci(arg.as_ref(), b"PXAT")
                {
                    if index + 1 >= parts.len() {
                        return Err(ParseError::Protocol("syntax error"));
                    }
                    let ttl = part_to_bytes(&parts[index + 1])?;
                    cmd.expire_at_ms = ttl_ms_from_args(arg.as_ref(), ttl.as_ref())?;
                    if cmd.set_keep_ttl || saw_expiry {
                        return Err(ParseError::Protocol("syntax error"));
                    }
                    saw_expiry = true;
                    index += 2;
                } else {
                    return Err(ParseError::Protocol("syntax error"));
                }
            }
            Ok(cmd)
        }
        OpCode::MSet | OpCode::MSetNx => {
            if parts.len() < 3 || parts.len() % 2 == 0 {
                return Err(wrong_arity(if op == OpCode::MSet {
                    "mset"
                } else {
                    "msetnx"
                }));
            }
            let mut keys = Vec::with_capacity((parts.len() - 1) / 2);
            let mut values = Vec::with_capacity((parts.len() - 1) / 2);
            for pair in parts[1..].chunks_exact(2) {
                let key = part_to_bytes(&pair[0])?;
                validate_user_key(&key)?;
                keys.push(key);
                values.push(part_to_bytes(&pair[1])?);
            }
            let mut cmd = Command::new(
                op,
                keys,
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            );
            cmd.values = values;
            Ok(cmd)
        }
        OpCode::GetSet
        | OpCode::SetNx
        | OpCode::Append
        | OpCode::IncrBy
        | OpCode::DecrBy
        | OpCode::IncrByFloat => {
            if parts.len() != 3 {
                return Err(wrong_arity(match op {
                    OpCode::GetSet => "getset",
                    OpCode::SetNx => "setnx",
                    OpCode::Append => "append",
                    OpCode::IncrBy => "incrby",
                    OpCode::DecrBy => "decrby",
                    OpCode::IncrByFloat => "incrbyfloat",
                    _ => "command",
                }));
            }
            let key = part_to_bytes(&parts[1])?;
            validate_user_key(&key)?;
            let mut val = part_to_bytes(&parts[2])?;
            if op == OpCode::DecrBy {
                let text = std::str::from_utf8(val.as_ref())
                    .map_err(|_| ParseError::Protocol("invalid argument"))?;
                let amount: i64 = text
                    .parse()
                    .map_err(|_| ParseError::Protocol("invalid argument"))?;
                let negated = amount.checked_neg().ok_or(ParseError::Protocol(
                    "increment or decrement would overflow",
                ))?;
                val = Bytes::from(negated.to_string());
            }
            let mut cmd = Command::new(
                op,
                vec![key],
                Some(val),
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            );
            if op == OpCode::GetSet {
                cmd.set_return_old = true;
            } else if op == OpCode::SetNx {
                cmd.set_condition = SetCondition::Nx;
                cmd.set_integer_reply = true;
            }
            Ok(cmd)
        }
        OpCode::StrLen | OpCode::Incr | OpCode::Decr => {
            if parts.len() != 2 {
                return Err(wrong_arity(match op {
                    OpCode::StrLen => "strlen",
                    OpCode::Incr => "incr",
                    OpCode::Decr => "decr",
                    _ => "command",
                }));
            }
            let key = part_to_bytes(&parts[1])?;
            validate_user_key(&key)?;
            let mut cmd = Command::new(
                op,
                vec![key],
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            );
            if op == OpCode::Incr {
                cmd.val = Some(Bytes::from_static(b"1"));
            } else if op == OpCode::Decr {
                cmd.val = Some(Bytes::from_static(b"-1"));
            }
            Ok(cmd)
        }
        OpCode::Expire | OpCode::PExpire | OpCode::ExpireAt | OpCode::PExpireAt => {
            if parts.len() < 3 {
                return Err(wrong_arity(match op {
                    OpCode::Expire => "expire",
                    OpCode::PExpire => "pexpire",
                    OpCode::ExpireAt => "expireat",
                    OpCode::PExpireAt => "pexpireat",
                    _ => "command",
                }));
            }
            let key = part_to_bytes(&parts[1])?;
            validate_user_key(&key)?;
            let ttl = part_to_bytes(&parts[2])?;
            let mut cmd = Command::new(
                op,
                vec![key],
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            );
            let unit = match op {
                OpCode::Expire => b"EXPIRE".as_slice(),
                OpCode::PExpire => b"PEXPIRE".as_slice(),
                OpCode::ExpireAt => b"EXPIREAT".as_slice(),
                OpCode::PExpireAt => b"PEXPIREAT".as_slice(),
                _ => b"",
            };
            cmd.expire_at_ms = expire_at_ms_from_args(unit, ttl.as_ref())?;
            let mut index = 3;
            while index < parts.len() {
                let arg = part_to_bytes(&parts[index])?;
                let flag = parse_expire_modifier(arg.as_ref())?;
                if (cmd.expire_flags & flag) != 0 {
                    return Err(ParseError::Protocol("syntax error"));
                }
                cmd.expire_flags |= flag;
                validate_expire_flags(cmd.expire_flags)?;
                index += 1;
            }
            Ok(cmd)
        }
        OpCode::Ttl | OpCode::PTtl | OpCode::Persist => {
            if parts.len() != 2 {
                return Err(wrong_arity(match op {
                    OpCode::Ttl => "ttl",
                    OpCode::PTtl => "pttl",
                    OpCode::Persist => "persist",
                    _ => "command",
                }));
            }
            let key = part_to_bytes(&parts[1])?;
            validate_user_key(&key)?;
            Ok(Command::new(
                op,
                vec![key],
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            ))
        }
        OpCode::Keys => {
            if parts.len() != 2 {
                return Err(wrong_arity("keys"));
            }
            let pattern = part_to_bytes(&parts[1])?;
            let mut cmd = Command::new(
                op,
                Vec::new(),
                Some(pattern),
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            );
            cmd.scan_prefix = literal_prefix(cmd.val.as_ref().unwrap().as_ref());
            cmd.scan_count = 1_000_000;
            Ok(cmd)
        }
        OpCode::Scan => {
            if parts.len() < 2 {
                return Err(wrong_arity("scan"));
            }
            let cursor_arg = part_to_bytes(&parts[1])?;
            let cursor = scan_cursor_from_arg(cursor_arg.as_ref())?;
            let mut cmd = Command::new(
                op,
                vec![cursor],
                Some(Bytes::from_static(b"*")),
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            );
            let mut index = 2;
            while index < parts.len() {
                let option = part_to_bytes(&parts[index])?;
                if ascii_eq_ci(option.as_ref(), b"MATCH") {
                    if index + 1 >= parts.len() {
                        return Err(ParseError::Protocol("syntax error"));
                    }
                    cmd.val = Some(part_to_bytes(&parts[index + 1])?);
                    cmd.scan_prefix = literal_prefix(cmd.val.as_ref().unwrap().as_ref());
                    index += 2;
                } else if ascii_eq_ci(option.as_ref(), b"COUNT") {
                    if index + 1 >= parts.len() {
                        return Err(ParseError::Protocol("syntax error"));
                    }
                    let count_arg = part_to_bytes(&parts[index + 1])?;
                    cmd.scan_count = parse_positive_i64(count_arg.as_ref())?;
                    index += 2;
                } else if ascii_eq_ci(option.as_ref(), b"TYPE") {
                    if index + 1 >= parts.len() {
                        return Err(ParseError::Protocol("syntax error"));
                    }
                    let type_arg = part_to_bytes(&parts[index + 1])?;
                    if !ascii_eq_ci(type_arg.as_ref(), b"string") {
                        cmd.scan_type_matches = false;
                    }
                    index += 2;
                } else {
                    return Err(ParseError::Protocol("syntax error"));
                }
            }
            if cmd.scan_prefix.is_empty() {
                cmd.scan_prefix = literal_prefix(cmd.val.as_ref().unwrap().as_ref());
            }
            if !cmd.scan_type_matches {
                cmd.scan_prefix = Bytes::from_static(b"\x01");
            }
            Ok(cmd)
        }
        OpCode::DbSize => {
            if parts.len() != 1 {
                return Err(wrong_arity("dbsize"));
            }
            Ok(Command::new(
                op,
                Vec::new(),
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            ))
        }
        OpCode::Type => {
            if parts.len() != 2 {
                return Err(wrong_arity("type"));
            }
            let key = part_to_bytes(&parts[1])?;
            validate_user_key(&key)?;
            Ok(Command::new(
                op,
                vec![key],
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            ))
        }
        OpCode::HScan => {
            if parts.len() < 3 {
                return Err(wrong_arity("hscan"));
            }
            Ok(Command::new(
                op,
                Vec::new(),
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            ))
        }
        OpCode::SAdd | OpCode::SRem => {
            if parts.len() < 3 {
                return Err(wrong_arity(if op == OpCode::SAdd {
                    "sadd"
                } else {
                    "srem"
                }));
            }
            let key = part_to_bytes(&parts[1])?;
            validate_user_key(&key)?;
            let mut members = Vec::with_capacity(parts.len() - 2);
            for part in parts.iter().skip(2) {
                members.push(part_to_bytes(part)?);
            }
            let mut cmd = Command::new(
                op,
                vec![key],
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            );
            cmd.values = members;
            Ok(cmd)
        }
        OpCode::SMembers | OpCode::SCard => {
            if parts.len() != 2 {
                return Err(wrong_arity(if op == OpCode::SMembers {
                    "smembers"
                } else {
                    "scard"
                }));
            }
            let key = part_to_bytes(&parts[1])?;
            validate_user_key(&key)?;
            Ok(Command::new(
                op,
                vec![key],
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            ))
        }
        OpCode::SIsMember => {
            if parts.len() != 3 {
                return Err(wrong_arity("sismember"));
            }
            let key = part_to_bytes(&parts[1])?;
            validate_user_key(&key)?;
            let member = part_to_bytes(&parts[2])?;
            Ok(Command::new(
                op,
                vec![key],
                Some(member),
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            ))
        }
        OpCode::SMove => {
            if parts.len() != 4 {
                return Err(wrong_arity("smove"));
            }
            let source = part_to_bytes(&parts[1])?;
            let destination = part_to_bytes(&parts[2])?;
            validate_user_key(&source)?;
            validate_user_key(&destination)?;
            let member = part_to_bytes(&parts[3])?;
            let mut cmd = Command::new(
                op,
                vec![source, destination],
                Some(member),
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            );
            cmd.values = vec![cmd.keys[1].clone(), cmd.val.clone().unwrap()];
            Ok(cmd)
        }
        OpCode::SPop | OpCode::SRandMember => {
            if parts.len() < 2 || parts.len() > 3 {
                return Err(wrong_arity(if op == OpCode::SPop {
                    "spop"
                } else {
                    "srandmember"
                }));
            }
            let key = part_to_bytes(&parts[1])?;
            validate_user_key(&key)?;
            let mut cmd = Command::new(
                op,
                vec![key],
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            );
            if parts.len() == 3 {
                let count_arg = part_to_bytes(&parts[2])?;
                let count = parse_i64_arg(count_arg.as_ref())?;
                if op == OpCode::SPop && count < 0 {
                    return Err(ParseError::Protocol("value is out of range"));
                }
                if count == i64::MIN || count.saturating_abs() > SET_RANDOM_COUNT_LIMIT {
                    return Err(ParseError::Protocol("value is out of range"));
                }
                cmd.set_count = Some(count);
            }
            Ok(cmd)
        }
        OpCode::SInter | OpCode::SUnion | OpCode::SDiff => {
            if parts.len() < 2 {
                return Err(wrong_arity(match op {
                    OpCode::SInter => "sinter",
                    OpCode::SUnion => "sunion",
                    OpCode::SDiff => "sdiff",
                    _ => "setop",
                }));
            }
            let mut keys = Vec::with_capacity(parts.len() - 1);
            for part in parts.iter().skip(1) {
                let key = part_to_bytes(part)?;
                validate_user_key(&key)?;
                keys.push(key);
            }
            Ok(Command::new(
                op,
                keys,
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            ))
        }
        OpCode::SInterStore | OpCode::SUnionStore | OpCode::SDiffStore => {
            if parts.len() < 3 {
                return Err(wrong_arity(match op {
                    OpCode::SInterStore => "sinterstore",
                    OpCode::SUnionStore => "sunionstore",
                    OpCode::SDiffStore => "sdiffstore",
                    _ => "setopstore",
                }));
            }
            let destination = part_to_bytes(&parts[1])?;
            validate_user_key(&destination)?;
            let mut keys = Vec::with_capacity(parts.len() - 1);
            keys.push(destination);
            for part in parts.iter().skip(2) {
                let key = part_to_bytes(part)?;
                validate_user_key(&key)?;
                keys.push(key);
            }
            Ok(Command::new(
                op,
                keys,
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            ))
        }
        OpCode::LPush | OpCode::RPush | OpCode::LPushX | OpCode::RPushX => {
            if parts.len() < 3 {
                return Err(wrong_arity(match op {
                    OpCode::LPush => "lpush",
                    OpCode::RPush => "rpush",
                    OpCode::LPushX => "lpushx",
                    OpCode::RPushX => "rpushx",
                    _ => "push",
                }));
            }
            let key = part_to_bytes(&parts[1])?;
            validate_user_key(&key)?;
            let mut values = Vec::with_capacity(parts.len() - 2);
            for part in parts.iter().skip(2) {
                values.push(part_to_bytes(part)?);
            }
            let mut cmd = Command::new(
                op,
                vec![key],
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            );
            cmd.values = values;
            Ok(cmd)
        }
        OpCode::LPop | OpCode::RPop => {
            if parts.len() < 2 || parts.len() > 3 {
                return Err(wrong_arity(if op == OpCode::LPop {
                    "lpop"
                } else {
                    "rpop"
                }));
            }
            let key = part_to_bytes(&parts[1])?;
            validate_user_key(&key)?;
            let mut cmd = Command::new(
                op,
                vec![key],
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            );
            if parts.len() == 3 {
                let count_arg = part_to_bytes(&parts[2])?;
                let count = parse_i64_arg(count_arg.as_ref())?;
                if count < 0 {
                    return Err(ParseError::Protocol("value is out of range"));
                }
                cmd.set_count = Some(count);
            }
            Ok(cmd)
        }
        OpCode::LLen => {
            if parts.len() != 2 {
                return Err(wrong_arity("llen"));
            }
            let key = part_to_bytes(&parts[1])?;
            validate_user_key(&key)?;
            Ok(Command::new(
                op,
                vec![key],
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            ))
        }
        OpCode::LIndex => {
            if parts.len() != 3 {
                return Err(wrong_arity("lindex"));
            }
            let key = part_to_bytes(&parts[1])?;
            validate_user_key(&key)?;
            let index = part_to_bytes(&parts[2])?;
            let mut cmd = Command::new(
                op,
                vec![key],
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            );
            cmd.expire_at_ms = parse_i64_arg(index.as_ref())?;
            Ok(cmd)
        }
        OpCode::LRange | OpCode::LTrim => {
            if parts.len() != 4 {
                return Err(wrong_arity(if op == OpCode::LRange {
                    "lrange"
                } else {
                    "ltrim"
                }));
            }
            let key = part_to_bytes(&parts[1])?;
            validate_user_key(&key)?;
            let start = part_to_bytes(&parts[2])?;
            let stop = part_to_bytes(&parts[3])?;
            parse_i64_arg(start.as_ref())?;
            parse_i64_arg(stop.as_ref())?;
            let mut cmd = Command::new(
                op,
                vec![key],
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            );
            cmd.values = vec![start, stop];
            Ok(cmd)
        }
        OpCode::LSet | OpCode::LRem => {
            if parts.len() != 4 {
                return Err(wrong_arity(if op == OpCode::LSet {
                    "lset"
                } else {
                    "lrem"
                }));
            }
            let key = part_to_bytes(&parts[1])?;
            validate_user_key(&key)?;
            let number = part_to_bytes(&parts[2])?;
            parse_i64_arg(number.as_ref())?;
            let value = part_to_bytes(&parts[3])?;
            let mut cmd = Command::new(
                op,
                vec![key],
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            );
            cmd.values = vec![number, value];
            Ok(cmd)
        }
        OpCode::LInsert => {
            if parts.len() != 5 {
                return Err(wrong_arity("linsert"));
            }
            let key = part_to_bytes(&parts[1])?;
            validate_user_key(&key)?;
            let position = part_to_bytes(&parts[2])?;
            let before = if ascii_eq_ci(position.as_ref(), b"BEFORE") {
                true
            } else if ascii_eq_ci(position.as_ref(), b"AFTER") {
                false
            } else {
                return Err(ParseError::Protocol("syntax error"));
            };
            let pivot = part_to_bytes(&parts[3])?;
            let value = part_to_bytes(&parts[4])?;
            let mut cmd = Command::new(
                op,
                vec![key],
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            );
            cmd.values = vec![pivot, value];
            if before {
                cmd.expire_flags |= TXN_FLAG_LIST_INSERT_BEFORE;
            }
            Ok(cmd)
        }
        OpCode::LMove => {
            if parts.len() != 5 {
                return Err(wrong_arity("lmove"));
            }
            let source = part_to_bytes(&parts[1])?;
            let destination = part_to_bytes(&parts[2])?;
            validate_user_key(&source)?;
            validate_user_key(&destination)?;
            let source_left = parse_list_side(part_to_bytes(&parts[3])?.as_ref())?;
            let dest_left = parse_list_side(part_to_bytes(&parts[4])?.as_ref())?;
            let mut cmd = Command::new(
                op,
                vec![source],
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            );
            cmd.values = vec![destination];
            if source_left {
                cmd.expire_flags |= TXN_FLAG_LIST_SOURCE_LEFT;
            }
            if dest_left {
                cmd.expire_flags |= TXN_FLAG_LIST_DEST_LEFT;
            }
            Ok(cmd)
        }
        OpCode::RPopLPush => {
            if parts.len() != 3 {
                return Err(wrong_arity("rpoplpush"));
            }
            let source = part_to_bytes(&parts[1])?;
            let destination = part_to_bytes(&parts[2])?;
            validate_user_key(&source)?;
            validate_user_key(&destination)?;
            let mut cmd = Command::new(
                op,
                vec![source],
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            );
            cmd.values = vec![destination];
            cmd.expire_flags |= TXN_FLAG_LIST_DEST_LEFT;
            Ok(cmd)
        }
        OpCode::LPos => {
            if parts.len() != 3 {
                return Err(wrong_arity("lpos"));
            }
            let key = part_to_bytes(&parts[1])?;
            validate_user_key(&key)?;
            let element = part_to_bytes(&parts[2])?;
            Ok(Command::new(
                op,
                vec![key],
                Some(element),
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            ))
        }
        OpCode::ZAdd => {
            if parts.len() < 4 {
                return Err(wrong_arity("zadd"));
            }
            let key = part_to_bytes(&parts[1])?;
            validate_user_key(&key)?;
            let mut flags = 0u32;
            let mut index = 2usize;
            while index < parts.len() {
                let arg = part_to_bytes(&parts[index])?;
                if ascii_eq_ci(arg.as_ref(), b"NX") {
                    flags |= TXN_FLAG_ZADD_NX;
                } else if ascii_eq_ci(arg.as_ref(), b"XX") {
                    flags |= TXN_FLAG_ZADD_XX;
                } else if ascii_eq_ci(arg.as_ref(), b"CH") {
                    flags |= TXN_FLAG_ZADD_CH;
                } else if ascii_eq_ci(arg.as_ref(), b"INCR") {
                    flags |= TXN_FLAG_ZADD_INCR;
                } else if ascii_eq_ci(arg.as_ref(), b"GT") {
                    flags |= TXN_FLAG_ZADD_GT;
                } else if ascii_eq_ci(arg.as_ref(), b"LT") {
                    flags |= TXN_FLAG_ZADD_LT;
                } else {
                    break;
                }
                index += 1;
            }
            if (flags & TXN_FLAG_ZADD_NX) != 0
                && (flags & (TXN_FLAG_ZADD_XX | TXN_FLAG_ZADD_GT | TXN_FLAG_ZADD_LT)) != 0
            {
                return Err(ParseError::Protocol("syntax error"));
            }
            if (flags & TXN_FLAG_ZADD_GT) != 0 && (flags & TXN_FLAG_ZADD_LT) != 0 {
                return Err(ParseError::Protocol("syntax error"));
            }
            if index >= parts.len() || (parts.len() - index) % 2 != 0 {
                return Err(wrong_arity("zadd"));
            }
            if (flags & TXN_FLAG_ZADD_INCR) != 0 && parts.len() - index != 2 {
                return Err(ParseError::Protocol("syntax error"));
            }
            let mut values = Vec::with_capacity(parts.len() - index);
            for pair in parts[index..].chunks_exact(2) {
                let score = part_to_bytes(&pair[0])?;
                parse_zadd_score_arg(score.as_ref())?;
                values.push(score);
                values.push(part_to_bytes(&pair[1])?);
            }
            let mut cmd = Command::new(
                op,
                vec![key],
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            );
            cmd.values = values;
            cmd.expire_flags = flags;
            Ok(cmd)
        }
        OpCode::ZIncrBy => {
            if parts.len() != 4 {
                return Err(wrong_arity("zincrby"));
            }
            let key = part_to_bytes(&parts[1])?;
            validate_user_key(&key)?;
            let increment = part_to_bytes(&parts[2])?;
            parse_zadd_score_arg(increment.as_ref())?;
            let member = part_to_bytes(&parts[3])?;
            let mut cmd = Command::new(
                op,
                vec![key],
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            );
            cmd.values = vec![increment, member];
            Ok(cmd)
        }
        OpCode::ZScore | OpCode::ZRank | OpCode::ZRevRank => {
            if parts.len() != 3 {
                return Err(wrong_arity(match op {
                    OpCode::ZScore => "zscore",
                    OpCode::ZRank => "zrank",
                    OpCode::ZRevRank => "zrevrank",
                    _ => "zop",
                }));
            }
            let key = part_to_bytes(&parts[1])?;
            validate_user_key(&key)?;
            let member = part_to_bytes(&parts[2])?;
            Ok(Command::new(
                op,
                vec![key],
                Some(member),
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            ))
        }
        OpCode::ZRem => {
            if parts.len() < 3 {
                return Err(wrong_arity("zrem"));
            }
            let key = part_to_bytes(&parts[1])?;
            validate_user_key(&key)?;
            let mut members = Vec::with_capacity(parts.len() - 2);
            for part in parts.iter().skip(2) {
                members.push(part_to_bytes(part)?);
            }
            let mut cmd = Command::new(
                op,
                vec![key],
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            );
            cmd.values = members;
            Ok(cmd)
        }
        OpCode::ZCard => {
            if parts.len() != 2 {
                return Err(wrong_arity("zcard"));
            }
            let key = part_to_bytes(&parts[1])?;
            validate_user_key(&key)?;
            Ok(Command::new(
                op,
                vec![key],
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            ))
        }
        OpCode::ZRange | OpCode::ZRevRange | OpCode::ZRangeByScore => {
            if parts.len() < 4 {
                return Err(wrong_arity(match op {
                    OpCode::ZRange => "zrange",
                    OpCode::ZRevRange => "zrevrange",
                    OpCode::ZRangeByScore => "zrangebyscore",
                    _ => "zrange",
                }));
            }
            let key = part_to_bytes(&parts[1])?;
            validate_user_key(&key)?;
            let first = part_to_bytes(&parts[2])?;
            let second = part_to_bytes(&parts[3])?;
            let mut flags = 0u32;
            if op == OpCode::ZRangeByScore {
                parse_zrange_bound_arg(first.as_ref())?;
                parse_zrange_bound_arg(second.as_ref())?;
                flags |= TXN_FLAG_Z_BYSCORE;
            }
            let mut values = vec![first, second];
            let mut index = 4usize;
            while index < parts.len() {
                let arg = part_to_bytes(&parts[index])?;
                if ascii_eq_ci(arg.as_ref(), b"WITHSCORES") {
                    flags |= TXN_FLAG_Z_WITHSCORES;
                    index += 1;
                } else if ascii_eq_ci(arg.as_ref(), b"REV") && op == OpCode::ZRange {
                    flags |= TXN_FLAG_Z_REV;
                    index += 1;
                } else if ascii_eq_ci(arg.as_ref(), b"BYSCORE") && op == OpCode::ZRange {
                    flags |= TXN_FLAG_Z_BYSCORE;
                    parse_zrange_bound_arg(values[0].as_ref())?;
                    parse_zrange_bound_arg(values[1].as_ref())?;
                    index += 1;
                } else if ascii_eq_ci(arg.as_ref(), b"LIMIT")
                    && ((flags & TXN_FLAG_Z_BYSCORE) != 0 || op == OpCode::ZRangeByScore)
                {
                    if index + 2 >= parts.len() {
                        return Err(ParseError::Protocol("syntax error"));
                    }
                    let offset = part_to_bytes(&parts[index + 1])?;
                    let count = part_to_bytes(&parts[index + 2])?;
                    parse_i64_arg(offset.as_ref())?;
                    parse_i64_arg(count.as_ref())?;
                    values.push(offset);
                    values.push(count);
                    index += 3;
                } else {
                    return Err(ParseError::Protocol("syntax error"));
                }
            }
            if (flags & TXN_FLAG_Z_BYSCORE) == 0 {
                parse_i64_arg(values[0].as_ref())?;
                parse_i64_arg(values[1].as_ref())?;
            }
            let mut cmd = Command::new(
                op,
                vec![key],
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            );
            cmd.values = values;
            cmd.expire_flags = flags;
            Ok(cmd)
        }
        OpCode::ZCount => {
            if parts.len() != 4 {
                return Err(wrong_arity("zcount"));
            }
            let key = part_to_bytes(&parts[1])?;
            validate_user_key(&key)?;
            let min = part_to_bytes(&parts[2])?;
            let max = part_to_bytes(&parts[3])?;
            parse_zrange_bound_arg(min.as_ref())?;
            parse_zrange_bound_arg(max.as_ref())?;
            let mut cmd = Command::new(
                op,
                vec![key],
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            );
            cmd.values = vec![min, max];
            Ok(cmd)
        }
        OpCode::ZPopMin | OpCode::ZPopMax => {
            if parts.len() < 2 || parts.len() > 3 {
                return Err(wrong_arity(if op == OpCode::ZPopMin {
                    "zpopmin"
                } else {
                    "zpopmax"
                }));
            }
            let key = part_to_bytes(&parts[1])?;
            validate_user_key(&key)?;
            let mut cmd = Command::new(
                op,
                vec![key],
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            );
            if parts.len() == 3 {
                let count = parse_i64_arg(part_to_bytes(&parts[2])?.as_ref())?;
                if count < 0 {
                    return Err(ParseError::Protocol("value is out of range"));
                }
                cmd.set_count = Some(count);
            }
            Ok(cmd)
        }
        OpCode::ZScan => {
            if parts.len() < 3 {
                return Err(wrong_arity("zscan"));
            }
            let key = part_to_bytes(&parts[1])?;
            validate_user_key(&key)?;
            let cursor = part_to_bytes(&parts[2])?;
            if cursor.as_ref() != b"0" {
                return Err(ParseError::Protocol("invalid cursor"));
            }
            let mut cmd = Command::new(
                op,
                vec![key],
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            );
            cmd.scan_count = 10;
            let mut index = 3usize;
            while index < parts.len() {
                let arg = part_to_bytes(&parts[index])?;
                if ascii_eq_ci(arg.as_ref(), b"MATCH") {
                    if index + 1 >= parts.len() {
                        return Err(ParseError::Protocol("syntax error"));
                    }
                    cmd.scan_prefix = part_to_bytes(&parts[index + 1])?;
                    index += 2;
                } else if ascii_eq_ci(arg.as_ref(), b"COUNT") {
                    if index + 1 >= parts.len() {
                        return Err(ParseError::Protocol("syntax error"));
                    }
                    cmd.scan_count =
                        parse_positive_i64(part_to_bytes(&parts[index + 1])?.as_ref())?;
                    index += 2;
                } else {
                    return Err(ParseError::Protocol("syntax error"));
                }
            }
            Ok(cmd)
        }
        OpCode::Ping
        | OpCode::Multi
        | OpCode::Exec
        | OpCode::Discard
        | OpCode::Hello
        | OpCode::Client
        | OpCode::Command
        | OpCode::Config
        | OpCode::Reset
        | OpCode::Quit
        | OpCode::Select
        | OpCode::Auth
        | OpCode::Echo
        | OpCode::Info
        | OpCode::Wait => {
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
                OpCode::Wait if parts.len() != 3 => Some("wait"),
                _ => None,
            };
            if let Some(command) = command {
                return Err(wrong_arity(command));
            }
            Ok(Command::new(
                op,
                Vec::new(),
                None,
                command_args(&parts).ok_or(ParseError::Protocol("invalid argument"))?,
            ))
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
        ParseError::Error(msg) => {
            w.write_all(b"-ERR ")?;
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

fn read_u64_le(input: &[u8], pos: &mut usize) -> Option<u64> {
    if input.len().saturating_sub(*pos) < 8 {
        return None;
    }
    let mut value = 0u64;
    for shift in 0..8 {
        value |= (input[*pos + shift] as u64) << (shift * 8);
    }
    *pos += 8;
    Some(value)
}

fn append_u64_le(out: &mut Vec<u8>, value: u64) {
    for shift in (0..64).step_by(8) {
        out.push(((value >> shift) & 0xff) as u8);
    }
}

fn pack_bytes_list(items: &[Bytes]) -> Bytes {
    let mut out = Vec::new();
    append_u64_le(&mut out, items.len() as u64);
    for item in items {
        append_u64_le(&mut out, item.len() as u64);
        out.extend_from_slice(item);
    }
    Bytes::from(out)
}

fn parse_list_payload(input: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut pos = 0usize;
    let item_count = read_u64_le(input, &mut pos)? as usize;
    let mut items = Vec::with_capacity(item_count);
    for _ in 0..item_count {
        let item_len = read_u64_le(input, &mut pos)? as usize;
        if input.len().saturating_sub(pos) < item_len {
            return None;
        }
        items.push(input[pos..pos + item_len].to_vec());
        pos += item_len;
    }
    if pos == input.len() {
        Some(items)
    } else {
        None
    }
}

fn parse_scan_payload(input: &[u8]) -> Option<(Vec<u8>, Vec<Vec<u8>>)> {
    let mut pos = 0usize;
    let cursor_len = read_u64_le(input, &mut pos)? as usize;
    if input.len().saturating_sub(pos) < cursor_len {
        return None;
    }
    let cursor = input[pos..pos + cursor_len].to_vec();
    pos += cursor_len;

    let key_count = read_u64_le(input, &mut pos)? as usize;
    let mut keys = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        let key_len = read_u64_le(input, &mut pos)? as usize;
        if input.len().saturating_sub(pos) < key_len {
            return None;
        }
        keys.push(input[pos..pos + key_len].to_vec());
        pos += key_len;
    }
    if pos == input.len() {
        Some((cursor, keys))
    } else {
        None
    }
}

fn scan_result_from_response(result: &TxnOpResult) -> Option<(Vec<u8>, Vec<Vec<u8>>)> {
    if !result.success || !result.value_present || result.data_ptr.is_null() {
        return None;
    }
    let data = unsafe { std::slice::from_raw_parts(result.data_ptr, result.data_len) };
    parse_scan_payload(data)
}

fn write_keys_array<W: Write>(
    writer: &mut W,
    keys: Vec<Vec<u8>>,
    pattern: &[u8],
) -> std::io::Result<()> {
    let matched: Vec<Vec<u8>> = keys
        .into_iter()
        .filter(|key| glob_matches(pattern, key))
        .collect();
    write_array_header(writer, matched.len())?;
    for key in matched {
        write_bulk(writer, &key)?;
    }
    Ok(())
}

// ===== Transaction FFI =====

/// Helper to build TxnOperation array from commands.
///
/// One Redis command can expand to multiple FFI operations. Variadic
/// DEL/UNLINK/EXISTS become one operation per key, then Rust aggregates
/// value_present back into one Redis integer reply.
fn build_txn_ops(commands: &[Command]) -> (Vec<TxnOperation>, Vec<(usize, usize)>, Vec<Bytes>) {
    let mut ops = Vec::new();
    let mut spans = Vec::with_capacity(commands.len());
    let mut payloads = Vec::new();
    let mut next_group_id = 1u32;

    for cmd in commands {
        let start = ops.len();
        match cmd.op {
            OpCode::Get | OpCode::Set | OpCode::GetSet | OpCode::SetNx => {
                let Some(key) = cmd.keys.first() else {
                    spans.push((start, 0));
                    continue;
                };
                let (val_ptr, val_len) = if let Some(v) = &cmd.val {
                    (v.as_ptr(), v.len())
                } else {
                    (std::ptr::null(), 0)
                };
                let mut flags = 0;
                if cmd.set_condition == SetCondition::Nx {
                    flags |= TXN_FLAG_SET_NX;
                } else if cmd.set_condition == SetCondition::Xx {
                    flags |= TXN_FLAG_SET_XX;
                }
                if cmd.set_return_old {
                    flags |= TXN_FLAG_SET_RETURN_OLD;
                }
                if cmd.set_integer_reply {
                    flags |= TXN_FLAG_SET_INTEGER_REPLY;
                }
                if cmd.set_keep_ttl {
                    flags |= TXN_FLAG_SET_KEEP_TTL;
                }
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
                    flags,
                    expire_at_ms: cmd.expire_at_ms,
                    group_id: 0,
                });
            }
            OpCode::MGet => {
                for key in &cmd.keys {
                    ops.push(TxnOperation {
                        op: TXN_OP_GET,
                        key_ptr: key.as_ptr(),
                        key_len: key.len(),
                        val_ptr: std::ptr::null(),
                        val_len: 0,
                        flags: 0,
                        expire_at_ms: -1,
                        group_id: 0,
                    });
                }
            }
            OpCode::MSet | OpCode::MSetNx => {
                let group_id = if cmd.op == OpCode::MSetNx {
                    let id = next_group_id;
                    next_group_id += 1;
                    id
                } else {
                    0
                };
                for (key, val) in cmd.keys.iter().zip(cmd.values.iter()) {
                    let mut flags = 0;
                    if cmd.op == OpCode::MSetNx {
                        flags |= TXN_FLAG_SET_NX
                            | TXN_FLAG_SET_INTEGER_REPLY
                            | TXN_FLAG_SET_REQUIRE_ABSENT_GROUP;
                    }
                    ops.push(TxnOperation {
                        op: TXN_OP_SET,
                        key_ptr: key.as_ptr(),
                        key_len: key.len(),
                        val_ptr: val.as_ptr(),
                        val_len: val.len(),
                        flags,
                        expire_at_ms: -1,
                        group_id,
                    });
                }
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
                        flags: 0,
                        expire_at_ms: -1,
                        group_id: 0,
                    });
                }
            }
            OpCode::Append
            | OpCode::IncrBy
            | OpCode::DecrBy
            | OpCode::IncrByFloat
            | OpCode::Incr
            | OpCode::Decr => {
                let Some(key) = cmd.keys.first() else {
                    spans.push((start, 0));
                    continue;
                };
                let Some(val) = cmd.val.as_ref() else {
                    spans.push((start, 0));
                    continue;
                };
                let op = match cmd.op {
                    OpCode::Append => TXN_OP_APPEND,
                    OpCode::IncrByFloat => TXN_OP_INCRBYFLOAT,
                    _ => TXN_OP_INCRBY,
                };
                ops.push(TxnOperation {
                    op,
                    key_ptr: key.as_ptr(),
                    key_len: key.len(),
                    val_ptr: val.as_ptr(),
                    val_len: val.len(),
                    flags: 0,
                    expire_at_ms: -1,
                    group_id: 0,
                });
            }
            OpCode::StrLen => {
                let Some(key) = cmd.keys.first() else {
                    spans.push((start, 0));
                    continue;
                };
                ops.push(TxnOperation {
                    op: TXN_OP_STRLEN,
                    key_ptr: key.as_ptr(),
                    key_len: key.len(),
                    val_ptr: std::ptr::null(),
                    val_len: 0,
                    flags: 0,
                    expire_at_ms: -1,
                    group_id: 0,
                });
            }
            OpCode::Expire | OpCode::PExpire | OpCode::ExpireAt | OpCode::PExpireAt => {
                let Some(key) = cmd.keys.first() else {
                    spans.push((start, 0));
                    continue;
                };
                ops.push(TxnOperation {
                    op: TXN_OP_EXPIRE,
                    key_ptr: key.as_ptr(),
                    key_len: key.len(),
                    val_ptr: std::ptr::null(),
                    val_len: 0,
                    flags: cmd.expire_flags,
                    expire_at_ms: cmd.expire_at_ms,
                    group_id: 0,
                });
            }
            OpCode::Ttl | OpCode::PTtl => {
                let Some(key) = cmd.keys.first() else {
                    spans.push((start, 0));
                    continue;
                };
                let flags = if cmd.op == OpCode::PTtl {
                    TXN_FLAG_TTL_MILLISECONDS
                } else {
                    0
                };
                ops.push(TxnOperation {
                    op: TXN_OP_TTL,
                    key_ptr: key.as_ptr(),
                    key_len: key.len(),
                    val_ptr: std::ptr::null(),
                    val_len: 0,
                    flags,
                    expire_at_ms: -1,
                    group_id: 0,
                });
            }
            OpCode::Persist => {
                let Some(key) = cmd.keys.first() else {
                    spans.push((start, 0));
                    continue;
                };
                ops.push(TxnOperation {
                    op: TXN_OP_PERSIST,
                    key_ptr: key.as_ptr(),
                    key_len: key.len(),
                    val_ptr: std::ptr::null(),
                    val_len: 0,
                    flags: 0,
                    expire_at_ms: -1,
                    group_id: 0,
                });
            }
            OpCode::Keys | OpCode::Scan => {
                let cursor = cmd.keys.first();
                let (key_ptr, key_len) = cursor
                    .map(|c| (c.as_ptr(), c.len()))
                    .unwrap_or((std::ptr::null(), 0));
                ops.push(TxnOperation {
                    op: TXN_OP_SCAN,
                    key_ptr,
                    key_len,
                    val_ptr: cmd.scan_prefix.as_ptr(),
                    val_len: cmd.scan_prefix.len(),
                    flags: 0,
                    expire_at_ms: cmd.scan_count,
                    group_id: 0,
                });
            }
            OpCode::DbSize => {
                ops.push(TxnOperation {
                    op: TXN_OP_SCAN,
                    key_ptr: std::ptr::null(),
                    key_len: 0,
                    val_ptr: std::ptr::null(),
                    val_len: 0,
                    flags: TXN_FLAG_SCAN_COUNT_ONLY,
                    expire_at_ms: -1,
                    group_id: 0,
                });
            }
            OpCode::Type => {
                let Some(key) = cmd.keys.first() else {
                    spans.push((start, 0));
                    continue;
                };
                ops.push(TxnOperation {
                    op: TXN_OP_TYPE,
                    key_ptr: key.as_ptr(),
                    key_len: key.len(),
                    val_ptr: std::ptr::null(),
                    val_len: 0,
                    flags: 0,
                    expire_at_ms: -1,
                    group_id: 0,
                });
            }
            OpCode::SAdd | OpCode::SRem => {
                let Some(key) = cmd.keys.first() else {
                    spans.push((start, 0));
                    continue;
                };
                let payload = pack_bytes_list(&cmd.values);
                payloads.push(payload);
                let payload = payloads.last().unwrap();
                let op = if cmd.op == OpCode::SAdd {
                    TXN_OP_SADD
                } else {
                    TXN_OP_SREM
                };
                ops.push(TxnOperation {
                    op,
                    key_ptr: key.as_ptr(),
                    key_len: key.len(),
                    val_ptr: payload.as_ptr(),
                    val_len: payload.len(),
                    flags: 0,
                    expire_at_ms: -1,
                    group_id: 0,
                });
            }
            OpCode::SIsMember => {
                let Some(key) = cmd.keys.first() else {
                    spans.push((start, 0));
                    continue;
                };
                let Some(member) = cmd.val.as_ref() else {
                    spans.push((start, 0));
                    continue;
                };
                ops.push(TxnOperation {
                    op: TXN_OP_SISMEMBER,
                    key_ptr: key.as_ptr(),
                    key_len: key.len(),
                    val_ptr: member.as_ptr(),
                    val_len: member.len(),
                    flags: 0,
                    expire_at_ms: -1,
                    group_id: 0,
                });
            }
            OpCode::SCard | OpCode::SMembers => {
                let Some(key) = cmd.keys.first() else {
                    spans.push((start, 0));
                    continue;
                };
                ops.push(TxnOperation {
                    op: if cmd.op == OpCode::SCard {
                        TXN_OP_SCARD
                    } else {
                        TXN_OP_SMEMBERS
                    },
                    key_ptr: key.as_ptr(),
                    key_len: key.len(),
                    val_ptr: std::ptr::null(),
                    val_len: 0,
                    flags: 0,
                    expire_at_ms: -1,
                    group_id: 0,
                });
            }
            OpCode::SMove => {
                let Some(source) = cmd.keys.first() else {
                    spans.push((start, 0));
                    continue;
                };
                let payload = pack_bytes_list(&cmd.values);
                payloads.push(payload);
                let payload = payloads.last().unwrap();
                ops.push(TxnOperation {
                    op: TXN_OP_SMOVE,
                    key_ptr: source.as_ptr(),
                    key_len: source.len(),
                    val_ptr: payload.as_ptr(),
                    val_len: payload.len(),
                    flags: 0,
                    expire_at_ms: -1,
                    group_id: 0,
                });
            }
            OpCode::SPop | OpCode::SRandMember => {
                let Some(key) = cmd.keys.first() else {
                    spans.push((start, 0));
                    continue;
                };
                let mut flags = 0;
                let mut count = 1;
                if let Some(raw_count) = cmd.set_count {
                    flags |= TXN_FLAG_SET_COUNT_GIVEN;
                    if raw_count < 0 {
                        flags |= TXN_FLAG_SET_ALLOW_DUPLICATES;
                        count = raw_count.saturating_abs();
                    } else {
                        count = raw_count;
                    }
                }
                ops.push(TxnOperation {
                    op: if cmd.op == OpCode::SPop {
                        TXN_OP_SPOP
                    } else {
                        TXN_OP_SRANDMEMBER
                    },
                    key_ptr: key.as_ptr(),
                    key_len: key.len(),
                    val_ptr: std::ptr::null(),
                    val_len: 0,
                    flags,
                    expire_at_ms: count,
                    group_id: 0,
                });
            }
            OpCode::SInter
            | OpCode::SUnion
            | OpCode::SDiff
            | OpCode::SInterStore
            | OpCode::SUnionStore
            | OpCode::SDiffStore => {
                let Some(key) = cmd.keys.first() else {
                    spans.push((start, 0));
                    continue;
                };
                let payload = if matches!(
                    cmd.op,
                    OpCode::SInterStore | OpCode::SUnionStore | OpCode::SDiffStore
                ) {
                    pack_bytes_list(&cmd.keys[1..])
                } else {
                    pack_bytes_list(&cmd.keys)
                };
                payloads.push(payload);
                let payload = payloads.last().unwrap();
                let mut flags = 0;
                if matches!(cmd.op, OpCode::SUnion | OpCode::SUnionStore) {
                    flags |= TXN_FLAG_SET_ALGEBRA_UNION;
                } else if matches!(cmd.op, OpCode::SDiff | OpCode::SDiffStore) {
                    flags |= TXN_FLAG_SET_ALGEBRA_DIFF;
                }
                if matches!(
                    cmd.op,
                    OpCode::SInterStore | OpCode::SUnionStore | OpCode::SDiffStore
                ) {
                    flags |= TXN_FLAG_SET_ALGEBRA_STORE;
                }
                ops.push(TxnOperation {
                    op: TXN_OP_SET_ALGEBRA,
                    key_ptr: key.as_ptr(),
                    key_len: key.len(),
                    val_ptr: payload.as_ptr(),
                    val_len: payload.len(),
                    flags,
                    expire_at_ms: -1,
                    group_id: 0,
                });
            }
            OpCode::LPush | OpCode::RPush | OpCode::LPushX | OpCode::RPushX => {
                let Some(key) = cmd.keys.first() else {
                    spans.push((start, 0));
                    continue;
                };
                let payload = pack_bytes_list(&cmd.values);
                payloads.push(payload);
                let payload = payloads.last().unwrap();
                let mut flags = 0;
                if matches!(cmd.op, OpCode::LPushX | OpCode::RPushX) {
                    flags |= TXN_FLAG_LIST_PUSH_IF_EXISTS;
                }
                ops.push(TxnOperation {
                    op: if matches!(cmd.op, OpCode::LPush | OpCode::LPushX) {
                        TXN_OP_LPUSH
                    } else {
                        TXN_OP_RPUSH
                    },
                    key_ptr: key.as_ptr(),
                    key_len: key.len(),
                    val_ptr: payload.as_ptr(),
                    val_len: payload.len(),
                    flags,
                    expire_at_ms: -1,
                    group_id: 0,
                });
            }
            OpCode::LPop | OpCode::RPop => {
                let Some(key) = cmd.keys.first() else {
                    spans.push((start, 0));
                    continue;
                };
                let mut flags = 0;
                let mut count = 1;
                if let Some(raw_count) = cmd.set_count {
                    flags |= TXN_FLAG_LIST_COUNT_GIVEN;
                    count = raw_count;
                }
                ops.push(TxnOperation {
                    op: if cmd.op == OpCode::LPop {
                        TXN_OP_LPOP
                    } else {
                        TXN_OP_RPOP
                    },
                    key_ptr: key.as_ptr(),
                    key_len: key.len(),
                    val_ptr: std::ptr::null(),
                    val_len: 0,
                    flags,
                    expire_at_ms: count,
                    group_id: 0,
                });
            }
            OpCode::LLen | OpCode::LIndex | OpCode::LRange | OpCode::LTrim | OpCode::LPos => {
                let Some(key) = cmd.keys.first() else {
                    spans.push((start, 0));
                    continue;
                };
                let packed_range = if matches!(cmd.op, OpCode::LRange | OpCode::LTrim) {
                    Some(pack_bytes_list(&cmd.values))
                } else {
                    None
                };
                if let Some(payload) = packed_range {
                    payloads.push(payload);
                }
                let (val_ptr, val_len) = if matches!(cmd.op, OpCode::LRange | OpCode::LTrim) {
                    let payload = payloads.last().unwrap();
                    (payload.as_ptr(), payload.len())
                } else if cmd.op == OpCode::LPos {
                    let Some(element) = cmd.val.as_ref() else {
                        spans.push((start, 0));
                        continue;
                    };
                    (element.as_ptr(), element.len())
                } else {
                    (std::ptr::null(), 0)
                };
                let op = match cmd.op {
                    OpCode::LLen => TXN_OP_LLEN,
                    OpCode::LIndex => TXN_OP_LINDEX,
                    OpCode::LRange => TXN_OP_LRANGE,
                    OpCode::LTrim => TXN_OP_LTRIM,
                    OpCode::LPos => TXN_OP_LPOS,
                    _ => TXN_OP_LLEN,
                };
                ops.push(TxnOperation {
                    op,
                    key_ptr: key.as_ptr(),
                    key_len: key.len(),
                    val_ptr,
                    val_len,
                    flags: 0,
                    expire_at_ms: cmd.expire_at_ms,
                    group_id: 0,
                });
            }
            OpCode::LSet | OpCode::LRem | OpCode::LInsert => {
                let Some(key) = cmd.keys.first() else {
                    spans.push((start, 0));
                    continue;
                };
                let payload = pack_bytes_list(&cmd.values);
                payloads.push(payload);
                let payload = payloads.last().unwrap();
                ops.push(TxnOperation {
                    op: match cmd.op {
                        OpCode::LSet => TXN_OP_LSET,
                        OpCode::LRem => TXN_OP_LREM,
                        OpCode::LInsert => TXN_OP_LINSERT,
                        _ => TXN_OP_LSET,
                    },
                    key_ptr: key.as_ptr(),
                    key_len: key.len(),
                    val_ptr: payload.as_ptr(),
                    val_len: payload.len(),
                    flags: cmd.expire_flags,
                    expire_at_ms: -1,
                    group_id: 0,
                });
            }
            OpCode::LMove | OpCode::RPopLPush => {
                let Some(source) = cmd.keys.first() else {
                    spans.push((start, 0));
                    continue;
                };
                let payload = pack_bytes_list(&cmd.values);
                payloads.push(payload);
                let payload = payloads.last().unwrap();
                ops.push(TxnOperation {
                    op: TXN_OP_LMOVE,
                    key_ptr: source.as_ptr(),
                    key_len: source.len(),
                    val_ptr: payload.as_ptr(),
                    val_len: payload.len(),
                    flags: cmd.expire_flags,
                    expire_at_ms: -1,
                    group_id: 0,
                });
            }
            OpCode::ZAdd | OpCode::ZIncrBy => {
                let Some(key) = cmd.keys.first() else {
                    spans.push((start, 0));
                    continue;
                };
                let payload = pack_bytes_list(&cmd.values);
                payloads.push(payload);
                let payload = payloads.last().unwrap();
                let mut flags = cmd.expire_flags;
                if cmd.op == OpCode::ZIncrBy {
                    flags |= TXN_FLAG_ZADD_INCR;
                }
                ops.push(TxnOperation {
                    op: TXN_OP_ZADD,
                    key_ptr: key.as_ptr(),
                    key_len: key.len(),
                    val_ptr: payload.as_ptr(),
                    val_len: payload.len(),
                    flags,
                    expire_at_ms: -1,
                    group_id: 0,
                });
            }
            OpCode::ZScore | OpCode::ZRank | OpCode::ZRevRank => {
                let Some(key) = cmd.keys.first() else {
                    spans.push((start, 0));
                    continue;
                };
                let Some(member) = cmd.val.as_ref() else {
                    spans.push((start, 0));
                    continue;
                };
                let flags = if cmd.op == OpCode::ZRevRank {
                    TXN_FLAG_Z_REV
                } else {
                    0
                };
                ops.push(TxnOperation {
                    op: if cmd.op == OpCode::ZScore {
                        TXN_OP_ZSCORE
                    } else {
                        TXN_OP_ZRANK
                    },
                    key_ptr: key.as_ptr(),
                    key_len: key.len(),
                    val_ptr: member.as_ptr(),
                    val_len: member.len(),
                    flags,
                    expire_at_ms: -1,
                    group_id: 0,
                });
            }
            OpCode::ZRem => {
                let Some(key) = cmd.keys.first() else {
                    spans.push((start, 0));
                    continue;
                };
                let payload = pack_bytes_list(&cmd.values);
                payloads.push(payload);
                let payload = payloads.last().unwrap();
                ops.push(TxnOperation {
                    op: TXN_OP_ZREM,
                    key_ptr: key.as_ptr(),
                    key_len: key.len(),
                    val_ptr: payload.as_ptr(),
                    val_len: payload.len(),
                    flags: 0,
                    expire_at_ms: -1,
                    group_id: 0,
                });
            }
            OpCode::ZCard => {
                let Some(key) = cmd.keys.first() else {
                    spans.push((start, 0));
                    continue;
                };
                ops.push(TxnOperation {
                    op: TXN_OP_ZCARD,
                    key_ptr: key.as_ptr(),
                    key_len: key.len(),
                    val_ptr: std::ptr::null(),
                    val_len: 0,
                    flags: 0,
                    expire_at_ms: -1,
                    group_id: 0,
                });
            }
            OpCode::ZRange | OpCode::ZRevRange | OpCode::ZRangeByScore => {
                let Some(key) = cmd.keys.first() else {
                    spans.push((start, 0));
                    continue;
                };
                let payload = pack_bytes_list(&cmd.values);
                payloads.push(payload);
                let payload = payloads.last().unwrap();
                let mut flags = cmd.expire_flags;
                if cmd.op == OpCode::ZRevRange {
                    flags |= TXN_FLAG_Z_REV;
                } else if cmd.op == OpCode::ZRangeByScore {
                    flags |= TXN_FLAG_Z_BYSCORE;
                }
                ops.push(TxnOperation {
                    op: TXN_OP_ZRANGE,
                    key_ptr: key.as_ptr(),
                    key_len: key.len(),
                    val_ptr: payload.as_ptr(),
                    val_len: payload.len(),
                    flags,
                    expire_at_ms: -1,
                    group_id: 0,
                });
            }
            OpCode::ZCount => {
                let Some(key) = cmd.keys.first() else {
                    spans.push((start, 0));
                    continue;
                };
                let payload = pack_bytes_list(&cmd.values);
                payloads.push(payload);
                let payload = payloads.last().unwrap();
                ops.push(TxnOperation {
                    op: TXN_OP_ZCOUNT,
                    key_ptr: key.as_ptr(),
                    key_len: key.len(),
                    val_ptr: payload.as_ptr(),
                    val_len: payload.len(),
                    flags: 0,
                    expire_at_ms: -1,
                    group_id: 0,
                });
            }
            OpCode::ZPopMin | OpCode::ZPopMax => {
                let Some(key) = cmd.keys.first() else {
                    spans.push((start, 0));
                    continue;
                };
                let mut flags = 0;
                if cmd.op == OpCode::ZPopMax {
                    flags |= TXN_FLAG_Z_REV;
                }
                if cmd.set_count.is_some() {
                    flags |= TXN_FLAG_Z_COUNT_GIVEN;
                }
                ops.push(TxnOperation {
                    op: TXN_OP_ZPOPMIN,
                    key_ptr: key.as_ptr(),
                    key_len: key.len(),
                    val_ptr: std::ptr::null(),
                    val_len: 0,
                    flags,
                    expire_at_ms: cmd.set_count.unwrap_or(1),
                    group_id: 0,
                });
            }
            OpCode::ZScan => {
                let Some(key) = cmd.keys.first() else {
                    spans.push((start, 0));
                    continue;
                };
                ops.push(TxnOperation {
                    op: TXN_OP_ZSCAN,
                    key_ptr: key.as_ptr(),
                    key_len: key.len(),
                    val_ptr: cmd.scan_prefix.as_ptr(),
                    val_len: cmd.scan_prefix.len(),
                    flags: 0,
                    expire_at_ms: cmd.scan_count,
                    group_id: 0,
                });
            }
            _ => {}
        }
        spans.push((start, ops.len() - start));
    }

    (ops, spans, payloads)
}

fn command_needs_retry(cmd: &Command) -> bool {
    matches!(
        cmd.op,
        OpCode::Set
            | OpCode::MSet
            | OpCode::MSetNx
            | OpCode::GetSet
            | OpCode::SetNx
            | OpCode::Append
            | OpCode::Incr
            | OpCode::IncrBy
            | OpCode::Decr
            | OpCode::DecrBy
            | OpCode::IncrByFloat
            | OpCode::Expire
            | OpCode::PExpire
            | OpCode::ExpireAt
            | OpCode::PExpireAt
            | OpCode::Persist
            | OpCode::Keys
            | OpCode::Scan
            | OpCode::DbSize
            | OpCode::Type
            | OpCode::SAdd
            | OpCode::SMembers
            | OpCode::SIsMember
            | OpCode::SRem
            | OpCode::SCard
            | OpCode::SMove
            | OpCode::SPop
            | OpCode::SRandMember
            | OpCode::SInter
            | OpCode::SUnion
            | OpCode::SDiff
            | OpCode::SInterStore
            | OpCode::SUnionStore
            | OpCode::SDiffStore
            | OpCode::LPush
            | OpCode::RPush
            | OpCode::LPop
            | OpCode::RPop
            | OpCode::LLen
            | OpCode::LIndex
            | OpCode::LRange
            | OpCode::LSet
            | OpCode::LRem
            | OpCode::LTrim
            | OpCode::LInsert
            | OpCode::LPushX
            | OpCode::RPushX
            | OpCode::LMove
            | OpCode::RPopLPush
            | OpCode::LPos
            | OpCode::ZAdd
            | OpCode::ZScore
            | OpCode::ZIncrBy
            | OpCode::ZRem
            | OpCode::ZCard
            | OpCode::ZRange
            | OpCode::ZRevRange
            | OpCode::ZRangeByScore
            | OpCode::ZRank
            | OpCode::ZRevRank
            | OpCode::ZCount
            | OpCode::ZPopMin
            | OpCode::ZPopMax
            | OpCode::ZScan
    )
}

const WRITING_TXN_MAX_ATTEMPTS: usize = 32;
const SET_RANDOM_COUNT_LIMIT: i64 = 1_000_000;

fn sleep_for_retry(attempt: usize) {
    let delay_ms = match attempt {
        0 => 1,
        1 => 2,
        _ => 4,
    };
    std::thread::sleep(std::time::Duration::from_millis(delay_ms));
}

/// Execute a single command as a transaction (for non-MULTI operations)
/// Returns the result directly without array wrapper
fn ffi_execute_single<W: Write>(cmd: &Command, writer: &mut W) -> std::io::Result<()> {
    let single = [cmd.clone()];
    let (ops, spans, _payloads) = build_txn_ops(&single);

    if ops.is_empty() {
        write_command_result(cmd, None, spans[0], writer)?;
        return Ok(());
    }

    let request = TxnRequest {
        num_ops: ops.len(),
        ops: ops.as_ptr(),
    };

    let max_attempts = if command_needs_retry(cmd) {
        WRITING_TXN_MAX_ATTEMPTS
    } else {
        1
    };
    let mut response = TxnResponse {
        transaction_success: false,
        num_results: 0,
        results: std::ptr::null_mut(),
    };
    let mut call_ok = false;

    for attempt in 0..max_attempts {
        response = TxnResponse {
            transaction_success: false,
            num_results: 0,
            results: std::ptr::null_mut(),
        };
        call_ok = unsafe { cpp_execute_transaction(&request, &mut response) };
        if call_ok && response.transaction_success && response.num_results >= ops.len() {
            break;
        }
        unsafe { cpp_free_transaction_response(&mut response) };
        if attempt + 1 < max_attempts {
            unsafe { cpp_record_txn_retry() };
            sleep_for_retry(attempt);
        }
    }

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

    let (ops, spans, _payloads) = build_txn_ops(commands);

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

    let max_attempts = if commands.iter().any(command_needs_retry) {
        WRITING_TXN_MAX_ATTEMPTS
    } else {
        1
    };
    let mut response = TxnResponse {
        transaction_success: false,
        num_results: 0,
        results: std::ptr::null_mut(),
    };
    let mut call_ok = false;

    for attempt in 0..max_attempts {
        response = TxnResponse {
            transaction_success: false,
            num_results: 0,
            results: std::ptr::null_mut(),
        };
        call_ok = unsafe { cpp_execute_transaction(&request, &mut response) };
        if call_ok && response.transaction_success && response.num_results >= ops.len() {
            break;
        }
        unsafe { cpp_free_transaction_response(&mut response) };
        if attempt + 1 < max_attempts {
            unsafe { cpp_record_txn_retry() };
            sleep_for_retry(attempt);
        }
    }

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
    if cmd.op == OpCode::Wait {
        write_integer(writer, 0)?;
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
        OpCode::Get | OpCode::GetSet => {
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
        OpCode::MGet => {
            write_array_header(writer, len)?;
            for index in start..start + len {
                let result = unsafe { &*response.results.add(index) };
                if !result.success {
                    write_err(writer, "operation failed")?;
                    return Ok(());
                }
                if result.value_present {
                    if result.data_len > 0 {
                        if result.data_ptr.is_null() {
                            write_err(writer, "operation failed")?;
                            return Ok(());
                        }
                        let data =
                            unsafe { std::slice::from_raw_parts(result.data_ptr, result.data_len) };
                        write_bulk(writer, data)?;
                    } else {
                        write_bulk(writer, b"")?;
                    }
                } else {
                    write_nil_bulk(writer)?;
                }
            }
        }
        OpCode::Set => {
            if !first.success {
                write_err(writer, "operation failed")?;
            } else if cmd.set_return_old {
                if first.value_present {
                    if first.data_len > 0 {
                        if first.data_ptr.is_null() {
                            write_err(writer, "operation failed")?;
                        } else {
                            let data = unsafe {
                                std::slice::from_raw_parts(first.data_ptr, first.data_len)
                            };
                            write_bulk(writer, data)?;
                        }
                    } else {
                        write_bulk(writer, b"")?;
                    }
                } else {
                    write_nil_bulk(writer)?;
                }
            } else if cmd.set_condition == SetCondition::None {
                write_simple_ok(writer)?;
            } else if first.value_present {
                write_simple_ok(writer)?;
            } else {
                write_nil_bulk(writer)?;
            }
        }
        OpCode::MSet => {
            for index in start..start + len {
                let result = unsafe { &*response.results.add(index) };
                if !result.success {
                    write_err(writer, "operation failed")?;
                    return Ok(());
                }
            }
            write_simple_ok(writer)?;
        }
        OpCode::MSetNx => {
            let mut wrote_all = len > 0;
            for index in start..start + len {
                let result = unsafe { &*response.results.add(index) };
                if !result.success {
                    write_err(writer, "operation failed")?;
                    return Ok(());
                }
                wrote_all &= result.value_present;
            }
            write_integer(writer, if wrote_all { 1 } else { 0 })?;
        }
        OpCode::SetNx => {
            if first.success {
                write_integer(writer, if first.value_present { 1 } else { 0 })?;
            } else {
                write_err(writer, "operation failed")?;
            }
        }
        OpCode::Append
        | OpCode::StrLen
        | OpCode::Incr
        | OpCode::IncrBy
        | OpCode::Decr
        | OpCode::DecrBy
        | OpCode::Expire
        | OpCode::PExpire
        | OpCode::ExpireAt
        | OpCode::PExpireAt
        | OpCode::Ttl
        | OpCode::PTtl
        | OpCode::Persist => {
            if first.success {
                write_integer(writer, first.int_value)?;
            } else {
                write_err(writer, "operation failed")?;
            }
        }
        OpCode::DbSize => {
            if first.success {
                write_integer(writer, first.int_value)?;
            } else {
                write_err(writer, "operation failed")?;
            }
        }
        OpCode::Type => {
            if first.success {
                match first.int_value {
                    1 => write_simple_string(writer, "string")?,
                    2 => write_simple_string(writer, "set")?,
                    3 => write_simple_string(writer, "list")?,
                    4 => write_simple_string(writer, "zset")?,
                    _ => write_simple_string(writer, "none")?,
                }
            } else {
                write_err(writer, "operation failed")?;
            }
        }
        OpCode::Keys => {
            let pattern = cmd.val.as_ref().map(|v| v.as_ref()).unwrap_or(b"*");
            if let Some((_, keys)) = scan_result_from_response(first) {
                write_keys_array(writer, keys, pattern)?;
            } else {
                write_err(writer, "operation failed")?;
            }
        }
        OpCode::Scan => {
            let pattern = cmd.val.as_ref().map(|v| v.as_ref()).unwrap_or(b"*");
            if let Some((cursor, keys)) = scan_result_from_response(first) {
                let matched: Vec<Vec<u8>> = keys
                    .into_iter()
                    .filter(|key| glob_matches(pattern, key))
                    .collect();
                write_array_header(writer, 2)?;
                write_bulk(writer, store_scan_cursor(&cursor).as_bytes())?;
                write_array_header(writer, matched.len())?;
                for key in matched {
                    write_bulk(writer, &key)?;
                }
            } else {
                write_err(writer, "operation failed")?;
            }
        }
        OpCode::IncrByFloat => {
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
        OpCode::SAdd | OpCode::SRem | OpCode::SCard | OpCode::SIsMember | OpCode::SMove => {
            if first.success {
                write_integer(writer, first.int_value)?;
            } else {
                write_err(writer, "operation failed")?;
            }
        }
        OpCode::SMembers | OpCode::SInter | OpCode::SUnion | OpCode::SDiff => {
            if !first.success || !first.value_present || first.data_ptr.is_null() {
                write_err(writer, "operation failed")?;
            } else {
                let data = unsafe { std::slice::from_raw_parts(first.data_ptr, first.data_len) };
                if let Some(items) = parse_list_payload(data) {
                    write_array_header(writer, items.len())?;
                    for item in items {
                        write_bulk(writer, &item)?;
                    }
                } else {
                    write_err(writer, "operation failed")?;
                }
            }
        }
        OpCode::SInterStore | OpCode::SUnionStore | OpCode::SDiffStore => {
            if first.success {
                write_integer(writer, first.int_value)?;
            } else {
                write_err(writer, "operation failed")?;
            }
        }
        OpCode::SPop | OpCode::SRandMember => {
            if !first.success {
                write_err(writer, "operation failed")?;
            } else if !first.value_present {
                if cmd.set_count.is_some() {
                    write_array_header(writer, 0)?;
                } else {
                    write_nil_bulk(writer)?;
                }
            } else if first.data_ptr.is_null() {
                write_err(writer, "operation failed")?;
            } else {
                let data = unsafe { std::slice::from_raw_parts(first.data_ptr, first.data_len) };
                if let Some(items) = parse_list_payload(data) {
                    if cmd.set_count.is_some() {
                        write_array_header(writer, items.len())?;
                        for item in items {
                            write_bulk(writer, &item)?;
                        }
                    } else if let Some(item) = items.first() {
                        write_bulk(writer, item)?;
                    } else {
                        write_nil_bulk(writer)?;
                    }
                } else {
                    write_err(writer, "operation failed")?;
                }
            }
        }
        OpCode::LPush
        | OpCode::RPush
        | OpCode::LPushX
        | OpCode::RPushX
        | OpCode::LLen
        | OpCode::LRem
        | OpCode::LInsert => {
            if first.success {
                write_integer(writer, first.int_value)?;
            } else {
                write_err(writer, "operation failed")?;
            }
        }
        OpCode::LSet | OpCode::LTrim => {
            if first.success {
                write_simple_ok(writer)?;
            } else {
                write_err(writer, "operation failed")?;
            }
        }
        OpCode::LIndex | OpCode::LMove | OpCode::RPopLPush => {
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
        OpCode::LPop | OpCode::RPop => {
            if !first.success {
                write_err(writer, "operation failed")?;
            } else if !first.value_present {
                if cmd.set_count.is_some() {
                    write_array_header(writer, 0)?;
                } else {
                    write_nil_bulk(writer)?;
                }
            } else if first.data_ptr.is_null() {
                write_err(writer, "operation failed")?;
            } else {
                let data = unsafe { std::slice::from_raw_parts(first.data_ptr, first.data_len) };
                if let Some(items) = parse_list_payload(data) {
                    if cmd.set_count.is_some() {
                        write_array_header(writer, items.len())?;
                        for item in items {
                            write_bulk(writer, &item)?;
                        }
                    } else if let Some(item) = items.first() {
                        write_bulk(writer, item)?;
                    } else {
                        write_nil_bulk(writer)?;
                    }
                } else {
                    write_err(writer, "operation failed")?;
                }
            }
        }
        OpCode::LRange => {
            if !first.success || !first.value_present || first.data_ptr.is_null() {
                write_err(writer, "operation failed")?;
            } else {
                let data = unsafe { std::slice::from_raw_parts(first.data_ptr, first.data_len) };
                if let Some(items) = parse_list_payload(data) {
                    write_array_header(writer, items.len())?;
                    for item in items {
                        write_bulk(writer, &item)?;
                    }
                } else {
                    write_err(writer, "operation failed")?;
                }
            }
        }
        OpCode::LPos => {
            if !first.success {
                write_err(writer, "operation failed")?;
            } else if first.value_present {
                write_integer(writer, first.int_value)?;
            } else {
                write_nil_bulk(writer)?;
            }
        }
        OpCode::ZAdd => {
            if !first.success {
                write_err(writer, "operation failed")?;
            } else if (cmd.expire_flags & TXN_FLAG_ZADD_INCR) != 0 {
                if first.value_present {
                    if first.data_len > 0 {
                        if first.data_ptr.is_null() {
                            write_err(writer, "operation failed")?;
                        } else {
                            let data = unsafe {
                                std::slice::from_raw_parts(first.data_ptr, first.data_len)
                            };
                            write_bulk(writer, data)?;
                        }
                    } else {
                        write_bulk(writer, b"")?;
                    }
                } else {
                    write_nil_bulk(writer)?;
                }
            } else {
                write_integer(writer, first.int_value)?;
            }
        }
        OpCode::ZIncrBy | OpCode::ZScore => {
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
        OpCode::ZRem | OpCode::ZCard | OpCode::ZCount => {
            if first.success {
                write_integer(writer, first.int_value)?;
            } else {
                write_err(writer, "operation failed")?;
            }
        }
        OpCode::ZRank | OpCode::ZRevRank => {
            if !first.success {
                write_err(writer, "operation failed")?;
            } else if first.value_present {
                write_integer(writer, first.int_value)?;
            } else {
                write_nil_bulk(writer)?;
            }
        }
        OpCode::ZRange
        | OpCode::ZRevRange
        | OpCode::ZRangeByScore
        | OpCode::ZPopMin
        | OpCode::ZPopMax => {
            if !first.success || !first.value_present || first.data_ptr.is_null() {
                write_err(writer, "operation failed")?;
            } else {
                let data = unsafe { std::slice::from_raw_parts(first.data_ptr, first.data_len) };
                if let Some(items) = parse_list_payload(data) {
                    write_array_header(writer, items.len())?;
                    for item in items {
                        write_bulk(writer, &item)?;
                    }
                } else {
                    write_err(writer, "operation failed")?;
                }
            }
        }
        OpCode::ZScan => {
            if !first.success || !first.value_present || first.data_ptr.is_null() {
                write_err(writer, "operation failed")?;
            } else {
                let data = unsafe { std::slice::from_raw_parts(first.data_ptr, first.data_len) };
                if let Some(items) = parse_list_payload(data) {
                    write_array_header(writer, 2)?;
                    write_bulk(writer, b"0")?;
                    write_array_header(writer, items.len())?;
                    for item in items {
                        write_bulk(writer, &item)?;
                    }
                } else {
                    write_err(writer, "operation failed")?;
                }
            }
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
    socket.set_nonblocking(true)?;
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
        "Starting {} thread-per-core workers on {} (SO_REUSEPORT, nonblocking clients, MULTI/EXEC support)",
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

                let mut clients = Vec::new();
                loop {
                    let mut made_progress = false;

                    loop {
                        match listener.accept() {
                            Ok((stream, _)) => {
                                let _ = stream.set_nodelay(true);
                                if let Err(e) = stream.set_nonblocking(true) {
                                    eprintln!(
                                        "[thread-{}] Client nonblocking error: {e}",
                                        thread_id
                                    );
                                    continue;
                                }
                                TOTAL_CONNECTIONS_RECEIVED.fetch_add(1, Ordering::Relaxed);
                                CONNECTED_CLIENTS.fetch_add(1, Ordering::Relaxed);
                                clients.push(ClientConn::new(stream));
                                made_progress = true;
                            }
                            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                            Err(e) => {
                                eprintln!("[thread-{}] Accept error: {e}", thread_id);
                                break;
                            }
                        }
                    }

                    let mut idx = 0;
                    while idx < clients.len() {
                        match service_client(&mut clients[idx]) {
                            Ok(ClientEvent::Keep) => {
                                idx += 1;
                            }
                            Ok(ClientEvent::Progress) => {
                                made_progress = true;
                                idx += 1;
                            }
                            Ok(ClientEvent::Close) => {
                                clients.swap_remove(idx);
                                CONNECTED_CLIENTS.fetch_sub(1, Ordering::Relaxed);
                                made_progress = true;
                            }
                            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                                idx += 1;
                            }
                            Err(e) => {
                                eprintln!("Client handling error: {e}");
                                clients.swap_remove(idx);
                                CONNECTED_CLIENTS.fetch_sub(1, Ordering::Relaxed);
                                made_progress = true;
                            }
                        }
                    }

                    if !made_progress {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                }
            })
            .expect("Failed to spawn worker thread");
    }

    true
}

struct ClientConn {
    stream: TcpStream,
    resp3: Resp3Handler,
    read_buf: [u8; 16384],
    write_buf: Vec<u8>,
    txn_state: TransactionState,
    client_state: ClientState,
    close_after_write: bool,
}

impl ClientConn {
    fn new(stream: TcpStream) -> Self {
        ClientConn {
            stream,
            resp3: Resp3Handler::new(10 * 1024 * 1024),
            read_buf: [0u8; 16384],
            write_buf: Vec::with_capacity(16384),
            txn_state: TransactionState::new(),
            client_state: ClientState::new(),
            close_after_write: false,
        }
    }
}

enum ClientEvent {
    Keep,
    Progress,
    Close,
}

fn flush_client(client: &mut ClientConn) -> std::io::Result<bool> {
    while !client.write_buf.is_empty() {
        match client.stream.write(&client.write_buf) {
            Ok(0) => return Ok(false),
            Ok(n) => {
                client.write_buf.drain(..n);
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(true),
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

fn service_client(client: &mut ClientConn) -> std::io::Result<ClientEvent> {
    let mut made_progress = false;

    if !client.write_buf.is_empty() {
        if !flush_client(client)? {
            return Ok(ClientEvent::Close);
        }
        made_progress = true;
    }
    if client.close_after_write && client.write_buf.is_empty() {
        return Ok(ClientEvent::Close);
    }

    loop {
        match client.stream.read(&mut client.read_buf) {
            Ok(0) => {
                return if client.write_buf.is_empty() {
                    Ok(ClientEvent::Close)
                } else {
                    client.close_after_write = true;
                    Ok(ClientEvent::Progress)
                };
            }
            Ok(n) => {
                client.resp3.read_bytes(&client.read_buf[..n]);
                made_progress = true;

                loop {
                    match client.resp3.next_frame() {
                        Ok(Some(frame)) => match parse_resp3(frame) {
                            Ok(cmd) => {
                                handle_command(
                                    &cmd,
                                    &mut client.txn_state,
                                    &mut client.client_state,
                                    &mut client.write_buf,
                                )?;
                                if client.client_state.close_after_reply {
                                    client.close_after_write = true;
                                }
                            }
                            Err(err) => {
                                write_parse_error(&mut client.write_buf, err)?;
                            }
                        },
                        Ok(None) => break,
                        Err(_) => {
                            write_err(&mut client.write_buf, "protocol error")?;
                            break;
                        }
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
    }

    if !client.write_buf.is_empty() {
        if !flush_client(client)? {
            return Ok(ClientEvent::Close);
        }
        made_progress = true;
    }

    if client.close_after_write && client.write_buf.is_empty() {
        Ok(ClientEvent::Close)
    } else if made_progress {
        Ok(ClientEvent::Progress)
    } else {
        Ok(ClientEvent::Keep)
    }
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
    write_integer(writer, client_state.id as i64)?;
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
        write_integer(writer, client_state.id as i64)
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
        let line = format!("id={} name={} flags=N db=0\r\n", client_state.id, name);
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

fn config_value(name: &[u8]) -> Option<(&'static [u8], &'static [u8])> {
    if ascii_eq_ci(name, b"save") {
        Some((b"save", b""))
    } else if ascii_eq_ci(name, b"appendonly") {
        Some((b"appendonly", b"no"))
    } else if ascii_eq_ci(name, b"databases") {
        Some((b"databases", b"1"))
    } else if ascii_eq_ci(name, b"maxmemory") {
        Some((b"maxmemory", b"0"))
    } else {
        None
    }
}

fn config_pattern_matches(pattern: &[u8], name: &[u8]) -> bool {
    pattern == b"*" || ascii_eq_ci(pattern, name)
}

fn handle_config_command<W: Write>(cmd: &Command, writer: &mut W) -> std::io::Result<()> {
    let Some(subcommand) = cmd.args.first() else {
        write_err(writer, "wrong number of arguments for 'config' command")?;
        return Ok(());
    };

    if ascii_eq_ci(subcommand, b"GET") {
        if cmd.args.len() != 2 {
            write_err(writer, "wrong number of arguments for 'config|get' command")?;
            return Ok(());
        }
        let known = [
            b"save".as_slice(),
            b"appendonly",
            b"databases",
            b"maxmemory",
        ];
        let mut entries = Vec::new();
        for name in known {
            if config_pattern_matches(cmd.args[1].as_ref(), name) {
                if let Some(pair) = config_value(name) {
                    entries.push(pair);
                }
            }
        }
        write_array_header(writer, entries.len() * 2)?;
        for (name, value) in entries {
            write_bulk(writer, name)?;
            write_bulk(writer, value)?;
        }
        Ok(())
    } else if ascii_eq_ci(subcommand, b"SET") {
        if cmd.args.len() != 3 {
            write_err(writer, "wrong number of arguments for 'config|set' command")?;
            return Ok(());
        }
        write_simple_ok(writer)
    } else if ascii_eq_ci(subcommand, b"RESETSTAT") {
        if cmd.args.len() != 1 {
            write_err(
                writer,
                "wrong number of arguments for 'config|resetstat' command",
            )?;
            return Ok(());
        }
        write_simple_ok(writer)
    } else {
        write_err(writer, "unsupported CONFIG subcommand")
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
    out.push_str("total_connections_received:");
    out.push_str(
        &TOTAL_CONNECTIONS_RECEIVED
            .load(Ordering::Relaxed)
            .to_string(),
    );
    out.push_str("\r\n");
    out.push_str("uptime_in_seconds:");
    out.push_str(&metrics.uptime_seconds.to_string());
    out.push_str("\r\n\r\n");
}

fn append_clients_info(out: &mut String) {
    out.push_str("# Clients\r\n");
    out.push_str("connected_clients:");
    out.push_str(&CONNECTED_CLIENTS.load(Ordering::Relaxed).to_string());
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
        append_clients_info(&mut out);
        append_mako_info(&mut out, &metrics);
    } else if ascii_eq_ci(section, b"server") {
        append_server_info(&mut out, &metrics);
    } else if ascii_eq_ci(section, b"clients") {
        append_clients_info(&mut out);
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
        OpCode::Config => {
            handle_config_command(cmd, writer)?;
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
        OpCode::Wait => {
            if txn_state.in_multi {
                txn_state.queue_command(cmd.clone());
                write_queued(writer)?;
            } else {
                write_integer(writer, 0)?;
            }
        }
        OpCode::HScan => {
            write_err(
                writer,
                "HSCAN requires hash command storage, not implemented",
            )?;
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
        OpCode::Get
        | OpCode::Set
        | OpCode::Del
        | OpCode::Exists
        | OpCode::MGet
        | OpCode::MSet
        | OpCode::MSetNx
        | OpCode::GetSet
        | OpCode::SetNx
        | OpCode::Append
        | OpCode::StrLen
        | OpCode::Incr
        | OpCode::IncrBy
        | OpCode::Decr
        | OpCode::DecrBy
        | OpCode::IncrByFloat
        | OpCode::Expire
        | OpCode::PExpire
        | OpCode::ExpireAt
        | OpCode::PExpireAt
        | OpCode::Ttl
        | OpCode::PTtl
        | OpCode::Persist
        | OpCode::Keys
        | OpCode::Scan
        | OpCode::DbSize
        | OpCode::Type
        | OpCode::SAdd
        | OpCode::SMembers
        | OpCode::SIsMember
        | OpCode::SRem
        | OpCode::SCard
        | OpCode::SMove
        | OpCode::SPop
        | OpCode::SRandMember
        | OpCode::SInter
        | OpCode::SUnion
        | OpCode::SDiff
        | OpCode::SInterStore
        | OpCode::SUnionStore
        | OpCode::SDiffStore
        | OpCode::LPush
        | OpCode::RPush
        | OpCode::LPop
        | OpCode::RPop
        | OpCode::LLen
        | OpCode::LIndex
        | OpCode::LRange
        | OpCode::LSet
        | OpCode::LRem
        | OpCode::LTrim
        | OpCode::LInsert
        | OpCode::LPushX
        | OpCode::RPushX
        | OpCode::LMove
        | OpCode::RPopLPush
        | OpCode::LPos
        | OpCode::ZAdd
        | OpCode::ZScore
        | OpCode::ZIncrBy
        | OpCode::ZRem
        | OpCode::ZCard
        | OpCode::ZRange
        | OpCode::ZRevRange
        | OpCode::ZRangeByScore
        | OpCode::ZRank
        | OpCode::ZRevRank
        | OpCode::ZCount
        | OpCode::ZPopMin
        | OpCode::ZPopMax
        | OpCode::ZScan => {
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
        Command::new(
            op,
            Vec::new(),
            None,
            args.iter().map(|arg| Bytes::copy_from_slice(arg)).collect(),
        )
    }

    fn data_command(op: OpCode, keys: &[&[u8]], val: Option<&[u8]>) -> Command {
        Command::new(
            op,
            keys.iter().map(|key| Bytes::copy_from_slice(key)).collect(),
            val.map(Bytes::copy_from_slice),
            keys.iter().map(|key| Bytes::copy_from_slice(key)).collect(),
        )
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
        assert!(text.contains("+id\r\n:"));
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
    fn client_id_is_stable_for_connection() {
        let mut txn_state = TransactionState::new();
        let mut client_state = ClientState::new();
        let expected = format!(":{}\r\n", client_state.id).into_bytes();

        let first = run(
            command(OpCode::Client, &[b"ID"]),
            &mut txn_state,
            &mut client_state,
        );
        let reset = run(
            command(OpCode::Reset, &[]),
            &mut txn_state,
            &mut client_state,
        );
        let second = run(
            command(OpCode::Client, &[b"ID"]),
            &mut txn_state,
            &mut client_state,
        );

        assert_eq!(first, expected);
        assert_eq!(reset, b"+RESET\r\n");
        assert_eq!(second, first);
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
    fn config_get_and_resetstat_return_client_compatible_replies() {
        let mut txn_state = TransactionState::new();
        let mut client_state = ClientState::new();

        let get_save = run(
            command(OpCode::Config, &[b"GET", b"save"]),
            &mut txn_state,
            &mut client_state,
        );
        let get_all = run(
            command(OpCode::Config, &[b"GET", b"*"]),
            &mut txn_state,
            &mut client_state,
        );
        let resetstat = run(
            command(OpCode::Config, &[b"RESETSTAT"]),
            &mut txn_state,
            &mut client_state,
        );

        assert_eq!(get_save, b"*2\r\n$4\r\nsave\r\n$0\r\n\r\n");
        assert!(get_all.starts_with(b"*8\r\n"));
        assert_eq!(resetstat, b"+OK\r\n");
    }

    #[test]
    fn info_server_returns_parseable_server_section() {
        let mut txn_state = TransactionState::new();
        let mut client_state = ClientState::new();
        TOTAL_CONNECTIONS_RECEIVED.store(7, Ordering::Relaxed);

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
        assert!(text.contains("total_connections_received:7\r\n"));
        assert!(text.contains("uptime_in_seconds:42\r\n"));
    }

    #[test]
    fn info_clients_returns_connection_metrics() {
        let mut txn_state = TransactionState::new();
        let mut client_state = ClientState::new();
        CONNECTED_CLIENTS.store(3, Ordering::Relaxed);

        let out = run(
            command(OpCode::Info, &[b"clients"]),
            &mut txn_state,
            &mut client_state,
        );
        let text = String::from_utf8(out).unwrap();

        assert!(text.contains("# Clients\r\n"));
        assert!(text.contains("connected_clients:3\r\n"));
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
            int_value: 0,
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
            int_value: 0,
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
                int_value: 0,
            },
            TxnOpResult {
                success: true,
                value_present: true,
                data_ptr: std::ptr::null_mut(),
                data_len: 0,
                int_value: 0,
            },
            TxnOpResult {
                success: true,
                value_present: true,
                data_ptr: std::ptr::null_mut(),
                data_len: 0,
                int_value: 0,
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
