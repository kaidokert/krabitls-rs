//! krabitls_cli — host-side TLS 1.3 client built on the krabitls typestate.
//!
//! Mirrors `tls_fixture/cli.py`; interleavable on the same `packets/` +
//! `state/` directories:
//!
//!     krabitls_cli  --conn-init           # writes packets/001_c2s_ClientHello.bin
//!     python3 …/serv.py --conn-response  # consumes 001, writes 002 + 003
//!     krabitls_cli  --conn-negotiate      # consumes 002 + 003, writes 004
//!     krabitls_cli  --send "hello"        # writes 005
//!     python3 …/serv.py --reply "world"  # consumes 005, writes 006
//!     krabitls_cli  --send "another"      # writes 007
//!
//! Deterministic mode (`--seed N`, default 0) carries no per-handshake state
//! — every command re-derives the priv from `(seed, label)`. `--random` mode
//! persists the OS-RNG priv to `state/priv.bin` for follow-up commands.
//!
//! Each command starts fresh — the typestate is entered via `replay`
//! constructors at the right state (WaitServerFlight for negotiate, AppData
//! for send / receive) so we don't lose state across process boundaries.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use krabitls::reassembler::ServerFlightReassembler;
use krabitls::{
    Aes128GcmSha256, AppData, CLIENT_FINISHED_LEN, DerCert, Init, RustCrypto, TlsConnection,
    VerifyMode,
};
use log::error;
use sha2::{Digest, Sha256};

const PACKETS_DIR: &str = "packets";
const STATE_DIR: &str = "state";
const PRIV_STATE_FILE: &str = "state/priv.bin";
/// `c_ap_ts (32B) || s_ap_ts (32B)`. Written by `--conn-negotiate`; read by
/// `--send` / `--receive` so they can skip the full HKDF chain + flight verify.
const SESSION_STATE_FILE: &str = "state/session.bin";

type Bn = fixed_bigint::FixedUInt<u32, 16, fixed_bigint::Ct>;
type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// Reassembler capacity for the seed-0 single-record server flight.
const FLIGHT_CAP: usize = 8 * 1024;

#[derive(Parser, Debug)]
#[command(
    name = "krabitls_cli",
    about = "TLS 1.3 client built on the krabitls library"
)]
struct Cli {
    #[arg(long, group = "action")]
    conn_init: bool,
    #[arg(long, group = "action")]
    conn_negotiate: bool,
    #[arg(long, value_name = "TEXT", group = "action")]
    send: Option<String>,
    #[arg(long, group = "action")]
    receive: bool,
    #[arg(long, group = "action")]
    reset: bool,
    /// Seed for deterministic priv / random (default 0; matches Python fixture).
    /// Ignored if `state/priv.bin` exists from a prior `--random --conn-init`.
    #[arg(long, default_value_t = 0)]
    seed: u64,
    /// OS-RNG for `--conn-init`; priv persisted to `state/priv.bin`.
    #[arg(long)]
    random: bool,
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<()> {
    if cli.reset {
        for d in [PACKETS_DIR, STATE_DIR] {
            if Path::new(d).exists() {
                fs::remove_dir_all(d)?;
            }
        }
        println!("reset");
        return Ok(());
    }
    if cli.conn_init {
        return cmd_conn_init(cli.seed, cli.random);
    }
    if cli.conn_negotiate {
        return cmd_conn_negotiate(cli.seed);
    }
    if let Some(text) = &cli.send {
        return cmd_send(cli.seed, text);
    }
    if cli.receive {
        return cmd_receive(cli.seed);
    }
    Err(
        "must pass exactly one of --conn-init / --conn-negotiate / --send / --receive / --reset"
            .into(),
    )
}

// =====================================================================
// Private-key acquisition
// =====================================================================

fn priv_for_init(seed: u64, use_random: bool) -> Result<[u8; 32]> {
    if use_random {
        let mut buf = [0u8; 32];
        getrandom::fill(&mut buf).map_err(|e| format!("getrandom: {e}"))?;
        fs::create_dir_all(STATE_DIR)?;
        write_secret_file(PRIV_STATE_FILE, &buf)?;
        Ok(buf)
    } else {
        Ok(derive_bytes::<32>(seed, "client_x25519"))
    }
}

/// 0o600 perms on unix; default elsewhere.
fn write_secret_file(path: &str, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
    }
    #[cfg(not(unix))]
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        f.write_all(bytes)?;
    }
    Ok(())
}

fn priv_for_followup(seed: u64) -> Result<[u8; 32]> {
    match fs::read(PRIV_STATE_FILE) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        }
        Ok(bytes) => Err(format!(
            "{} has unexpected size {} (expected 32); run --reset and --conn-init again",
            PRIV_STATE_FILE,
            bytes.len()
        )
        .into()),
        Err(_) => Ok(derive_bytes::<32>(seed, "client_x25519")),
    }
}

fn client_random_for_init(seed: u64, use_random: bool) -> Result<[u8; 32]> {
    if use_random {
        let mut buf = [0u8; 32];
        getrandom::fill(&mut buf).map_err(|e| format!("getrandom: {e}"))?;
        Ok(buf)
    } else {
        Ok(derive_bytes::<32>(seed, "client_random"))
    }
}

// =====================================================================
// --conn-init
// =====================================================================

fn cmd_conn_init(seed: u64, use_random: bool) -> Result<()> {
    fs::create_dir_all(PACKETS_DIR)?;
    let priv_bytes = priv_for_init(seed, use_random)?;
    let random = client_random_for_init(seed, use_random)?;
    let pub_bytes = ed25519_heapless::x25519_base::<Bn>(&priv_bytes);

    let conn = TlsConnection::<Init, RustCrypto, RustCrypto>::new(
        random,
        krabitls::ZeroBuf::<32>::new(priv_bytes),
    );
    let mut record = [0u8; krabitls::CLIENT_HELLO_LEN];
    let (ch_wire, _) = conn
        .write_client_hello_to_slice(&mut record, &pub_bytes, None)
        .map_err(|e| format!("write_client_hello: {e:?}"))?;

    let seq = next_packet_seq()?;
    let path = packet_path(seq, "c2s", "ClientHello");
    fs::write(&path, ch_wire)?;
    println!("wrote {}", path.display());
    Ok(())
}

// =====================================================================
// --conn-negotiate
// =====================================================================

fn cmd_conn_negotiate(seed: u64) -> Result<()> {
    let priv_bytes = priv_for_followup(seed)?;
    let ch_bytes = read_packet(|d, n| d == "c2s" && n.contains("ClientHello"))?;
    let sh_bytes = read_packet(|d, n| d == "s2c" && n.contains("ServerHello"))?;
    let sf_bytes = read_packet(|d, n| d == "s2c" && n.contains("ServerFlight"))?;

    // Feed the captured CH record straight into the transcript instead of
    // reconstructing it via write_client_hello — bytes the server actually
    // saw are authoritative; a rebuilt CH risks transcript drift.
    let conn = TlsConnection::<krabitls::WaitServerHello, RustCrypto, RustCrypto>::from_client_hello_record(
        &ch_bytes,
        krabitls::ZeroBuf::<32>::new(priv_bytes),
    )
    .map_err(|e| format!("from_client_hello_record: {e:?}"))?;

    let conn = conn
        .read_server_hello(&sh_bytes)
        .map_err(|e| format!("read_server_hello: {e:?}"))?
        .assume_aes_128_gcm()
        .map_err(|e| format!("assume_aes_128_gcm: {e:?}"))?;

    let mut reassembler: ServerFlightReassembler<FLIGHT_CAP> = ServerFlightReassembler::new();
    let mut pt = vec![0u8; sf_bytes.len()];
    let mut conn = conn;
    conn.feed_server_record(&sf_bytes, &mut reassembler, &mut pt)
        .map_err(|e| format!("feed_server_record: {e:?}"))?;
    let conn = conn
        .finalize_server_flight::<FLIGHT_CAP, DerCert, RustCrypto>(
            &reassembler,
            VerifyMode::SelfSigned,
        )
        .map_err(|e| format!("finalize_server_flight: {e:?}"))?;

    // Derive now; persist after CF is on disk so a partial-failure handshake
    // doesn't leave session.bin pointing at a peer that never saw CF.
    let (c_ap_ts, s_ap_ts) = conn
        .derive_app_secrets()
        .map_err(|e| format!("derive_app_secrets: {e:?}"))?;

    let mut cf_buf = [0u8; CLIENT_FINISHED_LEN];
    let cf_record = conn
        .build_client_finished(&mut cf_buf)
        .map_err(|e| format!("build_client_finished: {e:?}"))?;

    let seq = next_packet_seq()?;
    let path = packet_path(seq, "c2s", "ClientFinished_encrypted");
    fs::write(&path, cf_record)?;
    write_session_state(&c_ap_ts, &s_ap_ts)?;
    println!("wrote {} (handshake complete)", path.display());
    Ok(())
}

// =====================================================================
// --send TEXT
// =====================================================================

fn cmd_send(seed: u64, text: &str) -> Result<()> {
    let (c_ap_ts, s_ap_ts) = match load_session_state()? {
        Some(pair) => pair,
        None => {
            let priv_bytes = priv_for_followup(seed)?;
            renegotiate_app_secrets(&priv_bytes)?
        }
    };

    let ap_seq = next_c2s_app_data_seq()?;
    let mut conn =
        TlsConnection::<AppData<Aes128GcmSha256>, RustCrypto, RustCrypto>::from_app_secrets(
            c_ap_ts, s_ap_ts, ap_seq, 0,
        )
        .map_err(|e| format!("AppData::from_app_secrets: {e:?}"))?;

    let mut out = vec![0u8; text.len() + 32];
    let record = conn
        .encrypt_record(
            text.as_bytes(),
            krabitls::consts::CT_APPLICATION_DATA,
            &mut out,
        )
        .map_err(|e| format!("encrypt_record: {e:?}"))?;

    let seq = next_packet_seq()?;
    let path = packet_path(seq, "c2s", &format!("AppData_send_{}", ap_seq));
    fs::write(&path, record)?;
    println!("wrote {} (app-data seq={})", path.display(), ap_seq);
    Ok(())
}

// =====================================================================
// --receive
// =====================================================================

fn cmd_receive(seed: u64) -> Result<()> {
    let (c_ap_ts, s_ap_ts) = match load_session_state()? {
        Some(pair) => pair,
        None => {
            let priv_bytes = priv_for_followup(seed)?;
            renegotiate_app_secrets(&priv_bytes)?
        }
    };

    let mut replies: Vec<(u32, PathBuf)> = Vec::new();
    for entry in fs::read_dir(PACKETS_DIR)? {
        let entry = entry?;
        let name = entry.file_name();
        let s = name.to_str().unwrap_or("");
        if !(s.contains("_s2c_AppData_reply_") && s.ends_with(".bin")) {
            continue;
        }
        let n_str = s.trim_end_matches(".bin").rsplit('_').next().unwrap_or("");
        let n: u32 = n_str
            .parse()
            .map_err(|_| format!("unexpected reply filename: {}", s))?;
        replies.push((n, entry.path()));
    }
    replies.sort_by_key(|(n, _)| *n);

    if replies.is_empty() {
        println!("(no server replies yet)");
        return Ok(());
    }
    for (seq, path) in &replies {
        // One-shot AppData per reply so each decrypts at its own seq_in,
        // tolerating missing intermediate replies.
        let mut conn =
            TlsConnection::<AppData<Aes128GcmSha256>, RustCrypto, RustCrypto>::from_app_secrets(
                c_ap_ts.clone(),
                s_ap_ts.clone(),
                0,
                *seq as u64,
            )
            .map_err(|e| format!("AppData::from_app_secrets: {e:?}"))?;
        let record = fs::read(path)?;
        let mut pt_buf = vec![0u8; record.len()];
        let (content, _ct) = conn
            .decrypt_record(&record, &mut pt_buf)
            .map_err(|e| format!("decrypt {}: {:?}", path.display(), e))?;
        let text = core::str::from_utf8(content).unwrap_or("<not utf-8>");
        println!("seq {}: {}", seq, text);
    }
    Ok(())
}

// =====================================================================
// Session-secret recomputation (fallback when session.bin is absent)
// =====================================================================

/// Re-run the full handshake (CH+SH+sf already on disk) to recover the app
/// traffic secrets. Called only when `state/session.bin` is missing.
fn renegotiate_app_secrets(
    priv_bytes: &[u8; 32],
) -> Result<(krabitls::newtype::Secret, krabitls::newtype::Secret)> {
    let ch_bytes = read_packet(|d, n| d == "c2s" && n.contains("ClientHello"))?;
    let sh_bytes = read_packet(|d, n| d == "s2c" && n.contains("ServerHello"))?;
    let sf_bytes = read_packet(|d, n| d == "s2c" && n.contains("ServerFlight"))?;

    let conn = TlsConnection::<krabitls::WaitServerHello, RustCrypto, RustCrypto>::from_client_hello_record(
        &ch_bytes,
        krabitls::ZeroBuf::<32>::new(*priv_bytes),
    )
    .map_err(|e| format!("from_client_hello_record: {e:?}"))?;
    let conn = conn
        .read_server_hello(&sh_bytes)
        .map_err(|e| format!("read_server_hello: {e:?}"))?
        .assume_aes_128_gcm()
        .map_err(|e| format!("assume_aes_128_gcm: {e:?}"))?;

    let mut reassembler: ServerFlightReassembler<FLIGHT_CAP> = ServerFlightReassembler::new();
    let mut pt = vec![0u8; sf_bytes.len()];
    let mut conn = conn;
    conn.feed_server_record(&sf_bytes, &mut reassembler, &mut pt)
        .map_err(|e| format!("feed_server_record: {e:?}"))?;
    let conn = conn
        .finalize_server_flight::<FLIGHT_CAP, DerCert, RustCrypto>(
            &reassembler,
            VerifyMode::SelfSigned,
        )
        .map_err(|e| format!("finalize_server_flight: {e:?}"))?;
    conn.derive_app_secrets()
        .map_err(|e| format!("derive_app_secrets: {e:?}").into())
}

// =====================================================================
// Session-state file (`state/session.bin`)
// =====================================================================

fn write_session_state(
    c_ap_ts: &krabitls::newtype::Secret,
    s_ap_ts: &krabitls::newtype::Secret,
) -> Result<()> {
    fs::create_dir_all(STATE_DIR)?;
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(c_ap_ts.as_bytes());
    buf[32..].copy_from_slice(s_ap_ts.as_bytes());
    write_secret_file(SESSION_STATE_FILE, &buf)?;
    Ok(())
}

/// Persisted `(c_ap_ts, s_ap_ts)`; `None` if no prior `--conn-negotiate`.
fn load_session_state() -> Result<Option<(krabitls::newtype::Secret, krabitls::newtype::Secret)>> {
    let path = Path::new(SESSION_STATE_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path)?;
    if bytes.len() != 64 {
        return Err(format!(
            "{} has unexpected size {} (expected 64); re-run --conn-negotiate",
            SESSION_STATE_FILE,
            bytes.len()
        )
        .into());
    }
    let mut c = [0u8; 32];
    let mut s = [0u8; 32];
    c.copy_from_slice(&bytes[..32]);
    s.copy_from_slice(&bytes[32..]);
    Ok(Some((
        krabitls::newtype::Secret::from(c),
        krabitls::newtype::Secret::from(s),
    )))
}

// =====================================================================
// Packet directory helpers
// =====================================================================

fn read_packet<F>(matches: F) -> Result<Vec<u8>>
where
    F: Fn(&str, &str) -> bool,
{
    // Pick the highest-sequence match. With multiple captured handshakes in
    // packets/, returning the first hit could splice CH/SH/SF across sessions
    // and break transcript / secret derivation.
    let mut best: Option<(u32, PathBuf)> = None;
    for entry in fs::read_dir(PACKETS_DIR)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_str().unwrap_or("");
        if !name_str.ends_with(".bin") {
            continue;
        }
        // filename = "NNN_<dir>_<name>.bin"
        let parts: Vec<&str> = name_str.splitn(3, '_').collect();
        if parts.len() < 3 {
            continue;
        }
        let seq: u32 = match parts[0].parse() {
            Ok(s) => s,
            Err(_) => continue,
        };
        let direction = parts[1];
        let rest = parts[2].trim_end_matches(".bin");
        if matches(direction, rest) && best.as_ref().is_none_or(|(s, _)| seq > *s) {
            best = Some((seq, entry.path()));
        }
    }
    match best {
        Some((_, path)) => Ok(fs::read(path)?),
        None => Err("no matching packet in packets/".into()),
    }
}

fn next_packet_seq() -> Result<u32> {
    let mut max_seq = 0u32;
    if Path::new(PACKETS_DIR).exists() {
        for entry in fs::read_dir(PACKETS_DIR)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = match name.to_str() {
                Some(s) => s,
                None => continue,
            };
            if !name.ends_with(".bin") {
                continue;
            }
            let n = name.split('_').next().unwrap_or("");
            if let Ok(seq) = n.parse::<u32>()
                && seq > max_seq
            {
                max_seq = seq;
            }
        }
    }
    Ok(max_seq + 1)
}

fn packet_path(seq: u32, direction: &str, name: &str) -> PathBuf {
    let mut p = PathBuf::from(PACKETS_DIR);
    p.push(format!("{seq:03}_{direction}_{name}.bin"));
    p
}

/// Per-AEAD-key seq for next c2s app-data record. **max+1** (not count) so
/// `(key, seq)` is monotonic even if the user deletes a prior file; reusing
/// `(key, seq)` under AES-GCM breaks the cipher catastrophically.
fn next_c2s_app_data_seq() -> Result<u64> {
    if !Path::new(PACKETS_DIR).exists() {
        return Ok(0);
    }
    let mut max_seq: Option<u64> = None;
    for entry in fs::read_dir(PACKETS_DIR)? {
        let entry = entry?;
        let name = entry.file_name();
        let s = name.to_str().unwrap_or("");
        if !s.ends_with(".bin") {
            continue;
        }
        let Some(after) = s.split("_c2s_AppData_send_").nth(1) else {
            continue;
        };
        let seq_str = after.trim_end_matches(".bin");
        let Ok(seq) = seq_str.parse::<u64>() else {
            continue;
        };
        max_seq = Some(max_seq.map_or(seq, |m| m.max(seq)));
    }
    Ok(max_seq.map_or(0, |m| m + 1))
}

// =====================================================================
// Seed-derived RNG — byte-identical to tls13.derive_bytes in the Python fixture
// =====================================================================

fn derive_bytes<const N: usize>(seed: u64, label: &str) -> [u8; N] {
    let mut out = [0u8; N];
    let mut counter: u32 = 0;
    let mut written = 0;
    while written < N {
        let mut h = Sha256::new();
        h.update(b"tls_fixture\x00");
        h.update(seed.to_be_bytes());
        h.update(b"\x00");
        h.update(label.as_bytes());
        h.update(b"\x00");
        h.update(counter.to_be_bytes());
        let digest = h.finalize();
        let take = (N - written).min(32);
        out[written..written + take].copy_from_slice(&digest[..take]);
        written += take;
        counter += 1;
    }
    out
}
