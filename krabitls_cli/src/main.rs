//! krabitls_cli — host-side TLS 1.3 client built on the `krabitls` library.
//!
//! Mirrors `tls_fixture/cli.py` so you can interleave Rust and Python on the
//! same `packets/` + `state/` directories:
//!
//!     krabitls_cli  --conn-init           # writes packets/001_c2s_ClientHello.bin
//!     python3 …/serv.py --conn-response  # consumes 001, writes 002 + 003
//!     krabitls_cli  --conn-negotiate      # consumes 002 + 003, writes 004
//!     krabitls_cli  --send "hello"        # writes 005
//!     python3 …/serv.py --reply "world"  # consumes 005, writes 006
//!     krabitls_cli  --send "another"      # writes 007
//!
//! Deterministic mode (`--seed N`, default 0) carries **no state at all** —
//! every command re-derives the client X25519 private from `(seed, label)`.
//! `--random` mode generates an OS-RNG priv on `--conn-init` and persists it
//! to `state/priv.bin`; subsequent commands pick it up automatically.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use log::error;
use sha2::{Digest, Sha256};

const PACKETS_DIR: &str = "packets";
const STATE_DIR: &str = "state";
const PRIV_STATE_FILE: &str = "state/priv.bin";
/// Persisted post-handshake secrets so `--send` / `--receive` don't have to
/// re-derive the whole HKDF chain + re-verify the server flight on every
/// call. Layout: `c_ap_ts (32 B) || s_ap_ts (32 B)` = 64 bytes raw, no
/// header. Written by `--conn-negotiate` after it computes them; read by
/// `--send` / `--receive` when present, falling back to full re-derivation
/// if absent (so the Python-fixture-style "no state, just packets/" flow
/// still works).
const SESSION_STATE_FILE: &str = "state/session.bin";

type Bn = fixed_bigint::FixedUInt<u32, 16, fixed_bigint::Ct>;
type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Parser, Debug)]
#[command(
    name = "krabitls_cli",
    about = "TLS 1.3 client built on the krabitls library"
)]
struct Cli {
    /// Emit a ClientHello at the next packet sequence number.
    #[arg(long, group = "action")]
    conn_init: bool,

    /// Consume the server's ServerHello + encrypted flight, emit client Finished.
    #[arg(long, group = "action")]
    conn_negotiate: bool,

    /// Encrypt and append one application_data record.
    #[arg(long, value_name = "TEXT", group = "action")]
    send: Option<String>,

    /// Decrypt all server-to-client app-data records on disk and print them.
    #[arg(long, group = "action")]
    receive: bool,

    /// Wipe ./packets and ./state.
    #[arg(long, group = "action")]
    reset: bool,

    /// Deterministic seed for `--conn-init`-generated ephemeral keys / random.
    /// Default 0 makes the output byte-identical to the Python fixture's seed 0.
    /// Ignored on subsequent commands if `state/priv.bin` exists (`--random` mode).
    #[arg(long, default_value_t = 0)]
    seed: u64,

    /// Use OS RNG instead of `--seed`. Only meaningful on `--conn-init`; the
    /// generated private key is persisted to `state/priv.bin` and picked up by
    /// `--conn-negotiate` and `--send` automatically.
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

/// `--conn-init` priv: either OS-RNG (and persist) or seed-derived.
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

/// Write `bytes` to `path` with owner-only perms (0o600) on Unix so the
/// secret material isn't world-readable. On non-Unix targets falls back to
/// the platform default, since `std::os::unix::fs::OpenOptionsExt` isn't
/// available there.
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

/// `--conn-negotiate` / `--send` priv: prefer persisted random priv, else seed.
///
/// If `state/priv.bin` exists but isn't exactly 32 bytes the file is corrupt
/// — fail loudly rather than silently regenerating a seed-derived key whose
/// public half won't match what the server already responded to.
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

/// `--conn-init`'s ClientHello.random: OS-RNG in `--random` mode, else seed-derived.
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

    let mut record = [0u8; krabitls::CLIENT_HELLO_LEN];
    let mut cursor: &mut [u8] = &mut record;
    krabitls::write_client_hello(&mut cursor, &random, &pub_bytes, None)
        .map_err(|_| "krabitls::write_client_hello: buffer too small")?;

    let seq = next_packet_seq()?;
    let path = packet_path(seq, "c2s", "ClientHello");
    fs::write(&path, record)?;
    println!("wrote {}", path.display());
    Ok(())
}

// =====================================================================
// --conn-negotiate
// =====================================================================

fn cmd_conn_negotiate(seed: u64) -> Result<()> {
    let priv_bytes = priv_for_followup(seed)?;
    let session = compute_session_secrets(&priv_bytes)?;

    let mut out = [0u8; krabitls::CLIENT_FINISHED_LEN];
    let record = krabitls::build_client_finished::<krabitls::RustCrypto, krabitls::RustCrypto>(
        &session.c_hs_ts,
        &session.transcript_hash_through_server_finished,
        0, // first record under c_hs_traffic_secret
        &mut out,
    )
    .map_err(|e| format!("build_client_finished: {:?}", e))?;

    let seq = next_packet_seq()?;
    let path = packet_path(seq, "c2s", "ClientFinished_encrypted");
    fs::write(&path, record)?;

    // Persist app-traffic secrets so subsequent --send / --receive can skip
    // re-derivation of the full HKDF chain + server-flight verify.
    write_session_state(&session.c_ap_ts, &session.s_ap_ts)?;

    println!("wrote {} (handshake complete)", path.display());
    Ok(())
}

// =====================================================================
// --send TEXT
// =====================================================================

fn cmd_send(seed: u64, text: &str) -> Result<()> {
    let c_ap_ts = match load_session_state()? {
        Some((c_ap, _s_ap)) => c_ap,
        None => {
            let priv_bytes = priv_for_followup(seed)?;
            compute_session_secrets(&priv_bytes)?.c_ap_ts
        }
    };
    let (c_ap_key, c_ap_iv) = krabitls::traffic_keys::<krabitls::RustCrypto>(&c_ap_ts)
        .map_err(|e| format!("traffic_keys (c_ap): {:?}", e))?;

    // Per-AEAD-key sequence number: # of c2s app-data records already on disk.
    let ap_seq = next_c2s_app_data_seq()?;

    let mut out = vec![0u8; text.len() + 32]; // header(5) + content + content_type(1) + tag(16) padding
    let record = krabitls::encrypt_record::<krabitls::RustCrypto>(
        text.as_bytes(),
        krabitls::consts::CT_APPLICATION_DATA,
        &c_ap_key,
        &c_ap_iv,
        ap_seq,
        &mut out,
    )
    .map_err(|e| format!("encrypt_record: {:?}", e))?;

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
    let s_ap_ts = match load_session_state()? {
        Some((_c_ap, s_ap)) => s_ap,
        None => {
            let priv_bytes = priv_for_followup(seed)?;
            compute_session_secrets(&priv_bytes)?.s_ap_ts
        }
    };
    let (s_ap_key, s_ap_iv) = krabitls::traffic_keys::<krabitls::RustCrypto>(&s_ap_ts)
        .map_err(|e| format!("traffic_keys (s_ap): {:?}", e))?;

    // Walk all s2c AppData_reply files in seq order. The trailing "_N" in
    // the filename is the per-AEAD-key sequence number for s_ap.
    let mut replies: Vec<(u32, PathBuf)> = Vec::new();
    for entry in fs::read_dir(PACKETS_DIR)? {
        let entry = entry?;
        let name = entry.file_name();
        let s = name.to_str().unwrap_or("");
        if !(s.contains("_s2c_AppData_reply_") && s.ends_with(".bin")) {
            continue;
        }
        // Pull the trailing "_N.bin" sequence number.
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
        let record = fs::read(path)?;
        let mut pt_buf = vec![0u8; record.len()];
        let inner = krabitls::decrypt_record::<krabitls::RustCrypto>(
            &record,
            &s_ap_key,
            &s_ap_iv,
            *seq as u64,
            &mut pt_buf,
        )
        .map_err(|e| format!("decrypt {}: {:?}", path.display(), e))?;
        let (content, _ct) = krabitls::split_inner_plaintext(inner)
            .map_err(|e| format!("inner plaintext: {:?}", e))?;
        let text = core::str::from_utf8(content).unwrap_or("<not utf-8>");
        println!("seq {}: {}", seq, text);
    }
    Ok(())
}

// =====================================================================
// Session-secret recomputation
//
// Everything needed for the current session can be derived from (priv_key,
// packets-on-disk). No state file required. Cheap enough to re-do on every
// CLI call.
// =====================================================================

struct SessionSecrets {
    c_hs_ts: krabitls::newtype::Secret,
    /// SHA-256(CH || SH || EE || Cert || CertVerify || ServerFinished).
    transcript_hash_through_server_finished: krabitls::newtype::TranscriptDigest,
    c_ap_ts: krabitls::newtype::Secret,
    #[allow(dead_code)]
    s_ap_ts: krabitls::newtype::Secret,
}

fn compute_session_secrets(priv_bytes: &[u8; 32]) -> Result<SessionSecrets> {
    use krabitls::{
        DerCert, RustCrypto, TranscriptHash, application_traffic_secrets, decrypt_record,
        handshake_secret, handshake_traffic_secrets, master_secret, parse_server_hello,
        split_inner_plaintext, traffic_keys, verify_server_flight,
    };

    let ch_bytes = read_packet(|d, _n| d == "c2s" && _n.contains("ClientHello"))?;
    let sh_bytes = read_packet(|d, n| d == "s2c" && n.contains("ServerHello"))?;
    let sf_bytes = read_packet(|d, n| d == "s2c" && n.contains("ServerFlight"))?;

    let sh = parse_server_hello(&sh_bytes).map_err(|e| format!("parse_server_hello: {:?}", e))?;

    let dhe = ed25519_heapless::x25519::<Bn>(priv_bytes, sh.x25519_share);
    let hs =
        handshake_secret::<RustCrypto>(&dhe).map_err(|e| format!("handshake_secret: {:?}", e))?;
    let mut transcript = TranscriptHash::<RustCrypto>::new();
    transcript
        .update_record(&ch_bytes)
        .map_err(|e| format!("transcript update_record(ch): {:?}", e))?;
    transcript
        .update_record(&sh_bytes)
        .map_err(|e| format!("transcript update_record(sh): {:?}", e))?;
    let (c_hs_ts, s_hs_ts) = handshake_traffic_secrets::<RustCrypto>(&hs, &transcript.snapshot())
        .map_err(|e| format!("handshake_traffic_secrets: {:?}", e))?;
    let (s_hs_key, s_hs_iv) =
        traffic_keys::<RustCrypto>(&s_hs_ts).map_err(|e| format!("traffic_keys: {:?}", e))?;

    let mut pt_buf = vec![0u8; sf_bytes.len()];
    let pt = decrypt_record::<RustCrypto>(&sf_bytes, &s_hs_key, &s_hs_iv, 0, &mut pt_buf)
        .map_err(|e| format!("decrypt server flight: {:?}", e))?;
    let (content, _ct) =
        split_inner_plaintext(pt).map_err(|e| format!("inner plaintext: {:?}", e))?;
    verify_server_flight::<RustCrypto, DerCert, RustCrypto>(&mut transcript, content, &s_hs_ts)
        .map_err(|e| format!("verify_server_flight: {:?}", e))?;
    let th_through_sf = transcript.snapshot();

    let ms = master_secret::<RustCrypto>(&hs).map_err(|e| format!("master_secret: {:?}", e))?;
    let (c_ap_ts, s_ap_ts) = application_traffic_secrets::<RustCrypto>(&ms, &th_through_sf)
        .map_err(|e| format!("application_traffic_secrets: {:?}", e))?;

    Ok(SessionSecrets {
        c_hs_ts,
        transcript_hash_through_server_finished: th_through_sf,
        c_ap_ts,
        s_ap_ts,
    })
}

// =====================================================================
// Session-state file (`state/session.bin`) — see SESSION_STATE_FILE doc.
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

/// Read the persisted post-handshake app-traffic secrets. Returns `None`
/// if the state file isn't present (e.g. `--conn-negotiate` hasn't run
/// yet, or the user `--reset`-ed). Returns an error if the file exists
/// but is the wrong size (schema mismatch — caller should re-negotiate).
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
        let direction = parts[1];
        let rest = parts[2].trim_end_matches(".bin");
        if matches(direction, rest) {
            return Ok(fs::read(entry.path())?);
        }
    }
    Err("no matching packet in packets/".into())
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

/// Next per-AEAD-key sequence number under `c_ap_traffic_secret`. Derived
/// from `max(seq in filename) + 1` across the existing `*_c2s_AppData_send_N.bin`
/// records, NOT from the file count.
///
/// **Why max+1, not count.** AES-GCM nonces are `iv XOR seq`, so reusing a
/// `(key, seq)` pair with two different plaintexts breaks the cipher (CTR
/// keystream re-use → XOR-leaks plaintext, plus a single forged tag enables
/// full GHASH key recovery). If we picked "count of files" and the user
/// deleted any earlier record, the next `--send` would re-emit an already-
/// used seq under the same `c_ap_key` from session.bin — silently
/// catastrophic. Parsing the trailing `_N.bin` and taking the max+1 means
/// `--send` keeps moving forward monotonically regardless of file deletes.
fn next_c2s_app_data_seq() -> Result<u64> {
    if !Path::new(PACKETS_DIR).exists() {
        return Ok(0);
    }
    let mut max_seq: Option<u64> = None;
    for entry in fs::read_dir(PACKETS_DIR)? {
        let entry = entry?;
        let name = entry.file_name();
        let s = name.to_str().unwrap_or("");
        // Filename shape: `NNN_c2s_AppData_send_{seq}.bin` where NNN is
        // the global packet sequence and {seq} is the per-AEAD-key index.
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
