//! Standalone Rust RDP DVC session agent (`lovelyhawk-win-agent`).
//!
//! Run inside a remote Windows RDP session to connect back to the LovelyHawk
//! Windows Incident Response workbench over the Dynamic Virtual Channel
//! `dvc::lovelyhawk::winir` (or `dvc::demo::chat` with `--compat`).

use std::path::PathBuf;
use std::process::Command;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use lovelyhawk_win_dvc::{
    COMPAT_CHANNEL_NAME, DvcWireMessage, FILE_CHUNK_SIZE, PRIMARY_CHANNEL_NAME, PduReassembler,
    StreamDecoder, encode_frame,
};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};

#[cfg(windows)]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let channel_name = if args.iter().any(|a| a == "--compat" || a == "-c") {
        COMPAT_CHANNEL_NAME
    } else {
        PRIMARY_CHANNEL_NAME
    };

    println!("[LovelyHawk-Win-Agent] 正在打开 DVC 通道 '{channel_name}' ...");
    // One stdin reader for the lifetime of the agent, including reconnects.
    let (input_tx, input_rx) = std::sync::mpsc::sync_channel(8);
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::stdin().lock().lines().map_while(Result::ok) {
            if input_tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut delay = 1u64;
    loop {
        let started = std::time::Instant::now();
        if let Err(err) = win_agent::run(channel_name, &input_rx) {
            eprintln!("[LovelyHawk-Win-Agent] {err}");
        }
        if args.iter().any(|arg| arg == "--once") {
            break;
        }
        if started.elapsed().as_secs() >= 30 {
            delay = 1;
        }
        eprintln!("[LovelyHawk-Win-Agent] {delay} 秒后重连；Ctrl+C 退出。旧指令不会重放。");
        std::thread::sleep(std::time::Duration::from_secs(delay));
        delay = (delay * 2).min(30);
    }
}

#[cfg(not(windows))]
fn main() {
    let _ = (
        PathBuf::new,
        Command::new,
        Arc::new::<()>,
        AtomicBool::new,
        AtomicU64::new,
        Ordering::SeqCst,
        BASE64,
        COMPAT_CHANNEL_NAME,
        PRIMARY_CHANNEL_NAME,
        FILE_CHUNK_SIZE,
        PduReassembler::new,
        StreamDecoder::new,
        encode_frame as fn(&DvcWireMessage) -> Result<Vec<u8>, String>,
        Mutex::new::<()>,
        Sha256::new,
    );
    eprintln!("lovelyhawk-win-agent 仅在 Windows RDP 会话内运行。");
    std::process::exit(1);
}

#[cfg(windows)]
mod win_agent {
    use super::*;
    use windows::Win32::Foundation::{GetLastError, HANDLE};
    use windows::Win32::System::RemoteDesktop::{
        WTS_CHANNEL_OPTION_DYNAMIC, WTS_CURRENT_SESSION, WTSVirtualChannelClose,
        WTSVirtualChannelOpenEx, WTSVirtualChannelRead, WTSVirtualChannelWrite,
    };
    use windows_core::PCSTR;

    const READ_BUFFER_SIZE: usize = 4096;
    const READ_TIMEOUT_MS: u32 = 2000;
    const MAX_CMD_OUTPUT_CHARS: usize = 512 * 1024;

    #[derive(Clone, Copy)]
    struct SendHandle(HANDLE);
    // SAFETY: synchronized via `write_lock` / dedicated reader thread.
    unsafe impl Send for SendHandle {}
    unsafe impl Sync for SendHandle {}

    impl SendHandle {
        fn raw(self) -> HANDLE {
            self.0
        }
    }

    pub fn run(
        channel_name: &str,
        input: &std::sync::mpsc::Receiver<String>,
    ) -> Result<(), String> {
        let mut cstr = channel_name.as_bytes().to_vec();
        cstr.push(0);
        // SAFETY: `cstr` is null-terminated ASCII.
        let handle = unsafe {
            WTSVirtualChannelOpenEx(
                WTS_CURRENT_SESSION,
                PCSTR(cstr.as_ptr()),
                WTS_CHANNEL_OPTION_DYNAMIC,
            )
            .map_err(|e| {
                let code = GetLastError().0;
                format!("WTSVirtualChannelOpenEx 失败 (err={code}, {e})。请确认已在 RDP 会话中运行且客户端已启动 LovelyHawk 监听。")
            })?
        };
        if handle.is_invalid() || handle.0.is_null() {
            return Err("WTSVirtualChannelOpenEx 返回了无效句柄。".to_owned());
        }
        println!("[LovelyHawk-Win-Agent] 通道已连接 ({channel_name})。等待 LovelyHawk 采集指令...");
        println!(
            "[LovelyHawk-Win-Agent] 输入文本回车可发送消息，输入 '/send <文件路径>' 可向客户端回传文件。"
        );

        let send_handle = SendHandle(handle);
        let write_lock = Arc::new(Mutex::new(()));
        let seq = Arc::new(AtomicU64::new(1));
        let stop = Arc::new(AtomicBool::new(false));
        let executing = Arc::new(AtomicBool::new(false));

        let send_msg = {
            let write_lock = Arc::clone(&write_lock);
            let seq = Arc::clone(&seq);
            let stop = Arc::clone(&stop);
            move |mut msg: DvcWireMessage| -> Result<(), String> {
                msg.seq = seq.fetch_add(1, Ordering::SeqCst);
                let frame = encode_frame(&msg)?;
                let mut written: u32 = 0;
                let _g = write_lock.lock();
                if stop.load(Ordering::Acquire) {
                    return Err("旧会话已经关闭".to_owned());
                }
                // SAFETY: `frame` slice is valid for `frame.len()` bytes.
                let result = unsafe {
                    WTSVirtualChannelWrite(send_handle.raw(), &frame, &mut written)
                        .map_err(|e| format!("WTSVirtualChannelWrite 失败: {e}"))
                };
                if result.is_err() || written as usize != frame.len() {
                    stop.store(true, Ordering::Release);
                    return Err("通道写入未完成，正在重新建立连接".to_owned());
                }
                Ok(())
            }
        };

        let stop_reader = Arc::clone(&stop);
        let send_for_reader = send_msg.clone();
        let reader_result = (|| -> Result<(), String> {
            let mut pdu = PduReassembler::new();
            let mut decoder = StreamDecoder::new();
            let mut recv_buf = vec![0u8; READ_BUFFER_SIZE];
            let mut incoming_file: Option<(PathBuf, Vec<u8>, u64, Sha256)> = None;

            while !stop_reader.load(Ordering::Relaxed) {
                if let Ok(line) = input.try_recv() {
                    let trimmed = line.trim();
                    if let Some(path) = trimmed.strip_prefix("/send ") {
                        if let Err(error) =
                            push_file_to_client(path.trim().trim_matches('"'), &send_for_reader)
                        {
                            eprintln!("[send] {error}");
                        }
                    } else if !trimmed.is_empty() {
                        send_for_reader(DvcWireMessage::chat("server", 0, trimmed))?;
                    }
                }
                let mut bytes_read: u32 = 0;
                // SAFETY: `recv_buf` has capacity `READ_BUFFER_SIZE`.
                let res = unsafe {
                    WTSVirtualChannelRead(
                        send_handle.raw(),
                        READ_TIMEOUT_MS,
                        &mut recv_buf,
                        &mut bytes_read,
                    )
                };
                let err_code = if res.is_err() {
                    unsafe { GetLastError().0 }
                } else {
                    0
                };
                if lovelyhawk_win_dvc::agent_runtime::read_is_idle(
                    res.is_ok(),
                    bytes_read,
                    err_code,
                ) {
                    continue;
                }
                if res.is_err() {
                    return Err(format!("通道读取失败 (code={err_code})"));
                }
                let Some(full_pdu) = pdu.push_read(&recv_buf[..bytes_read as usize]) else {
                    continue;
                };
                let messages = decoder.feed(&full_pdu)?;
                for msg in messages {
                    match msg.msg_type.as_str() {
                        "cmd" => {
                            if executing.swap(true, Ordering::AcqRel) {
                                return Err("收到重叠指令，已关闭通道以避免结果混淆".to_owned());
                            }
                            let cmd_text = msg.text.clone();
                            let sender = send_for_reader.clone();
                            let executing = Arc::clone(&executing);
                            println!(
                                "[LovelyHawk-Win-Agent] 收到采集/排查指令 ({} bytes)...",
                                cmd_text.len()
                            );
                            std::thread::spawn(move || {
                                if let Some(pull_path) = cmd_text.strip_prefix("__PULL_FILE__:") {
                                    let _ = push_file_to_client(pull_path.trim(), &sender);
                                    executing.store(false, Ordering::Release);
                                } else {
                                    let out = std::panic::catch_unwind(|| {
                                        execute_local_command(&cmd_text)
                                    })
                                    .unwrap_or_else(|_| {
                                        "[error] 采集器异常，本次查询未完成".to_owned()
                                    });
                                    println!(
                                        "[LovelyHawk-Win-Agent] 指令执行完成，回传 {} bytes",
                                        out.len()
                                    );
                                    // Allow the client's next serialized request before sending
                                    // this response. The old session's writer is invalidated on close.
                                    executing.store(false, Ordering::Release);
                                    if let Err(error) =
                                        sender(DvcWireMessage::result("server", 0, out))
                                    {
                                        eprintln!("[send] {error}");
                                    }
                                }
                            });
                        }
                        "file_start" => {
                            let name =
                                std::path::Path::new(msg.name.as_deref().unwrap_or("received.bin"))
                                    .file_name()
                                    .map(|s| s.to_string_lossy().into_owned())
                                    .unwrap_or_else(|| "received.bin".to_owned());
                            let recv_dir = PathBuf::from("recv");
                            let _ = std::fs::create_dir_all(&recv_dir);
                            let target = recv_dir.join(&name);
                            let expected = msg.size.unwrap_or(0);
                            if expected > 8 * 1024 * 1024 {
                                return Err("接收文件超过 8 MiB 上限".to_owned());
                            }
                            println!("[recv] <- {name} ({expected} bytes)");
                            incoming_file = Some((target, Vec::new(), expected, Sha256::new()));
                        }
                        "file_chunk" => {
                            if let (Some(b64), Some((_, buf, _, hasher))) =
                                (msg.b64.as_deref(), incoming_file.as_mut())
                                && let Ok(bytes) = BASE64.decode(b64)
                            {
                                if buf.len().saturating_add(bytes.len()) > 8 * 1024 * 1024 {
                                    return Err("接收文件超过 8 MiB 上限".to_owned());
                                }
                                hasher.update(&bytes);
                                buf.extend_from_slice(&bytes);
                            }
                        }
                        "file_end" => {
                            if let Some((path, buf, expected, hasher)) = incoming_file.take() {
                                let digest = format!("{:x}", hasher.finalize());
                                let ok = buf.len() as u64 == expected
                                    && msg
                                        .sha256
                                        .as_deref()
                                        .is_none_or(|s| s.eq_ignore_ascii_case(&digest));
                                if ok {
                                    use std::io::Write;
                                    let result = std::fs::OpenOptions::new()
                                        .write(true)
                                        .create_new(true)
                                        .open(&path)
                                        .and_then(|mut file| file.write_all(&buf));
                                    if let Err(error) = result {
                                        eprintln!("[recv] 保存失败: {error}");
                                    }
                                }
                                println!(
                                    "[recv] 完成: {} ({} bytes) [{}]",
                                    path.display(),
                                    buf.len(),
                                    if ok { "OK" } else { "MISMATCH" }
                                );
                            }
                        }
                        _ => {
                            println!("<- {}: {}", msg.from, msg.text);
                        }
                    }
                }
            }
            Ok(())
        })();

        let _guard = write_lock.lock();
        stop.store(true, Ordering::Release);
        // SAFETY: the reader is done; this lock excludes writers and all future
        // writes check `stop` under the same lock before touching the handle.
        unsafe {
            let _ = WTSVirtualChannelClose(send_handle.raw());
        }
        reader_result
    }

    fn execute_local_command(cmd: &str) -> String {
        if let Some(spec) = cmd.strip_prefix("__NATIVE_COLLECT__:") {
            return lovelyhawk_win_dvc::native_collect::handle_native_collect(spec.trim());
        }
        let run = |command: &mut Command| {
            lovelyhawk_win_dvc::agent_runtime::bounded_output(
                command,
                MAX_CMD_OUTPUT_CHARS,
                std::time::Duration::from_secs(35),
            )
        };
        let output = if let Some((_, b64)) = cmd.split_once("-EncodedCommand ") {
            run(Command::new("powershell.exe").args([
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                b64.trim(),
            ]))
        } else if let Some(ps_script) = cmd.strip_prefix("__PS__:") {
            let utf16: Vec<u8> = ps_script
                .encode_utf16()
                .flat_map(|w| w.to_le_bytes())
                .collect();
            let encoded = BASE64.encode(&utf16);
            run(Command::new("powershell.exe").args([
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                &encoded,
            ]))
        } else {
            run(Command::new("cmd.exe").args(["/d", "/C", cmd]))
        };

        match output {
            Ok(out) => {
                let code = out.status.code().unwrap_or(-1);
                let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
                let stderr = String::from_utf8_lossy(&out.stderr);
                if !stderr.trim().is_empty() {
                    if !combined.is_empty() && !combined.ends_with('\n') {
                        combined.push('\n');
                    }
                    combined.push_str(stderr.trim());
                }
                let trimmed = combined.trim();
                if trimmed.chars().count() > MAX_CMD_OUTPUT_CHARS {
                    return format!(
                        "[error] 命令输出超过 {MAX_CMD_OUTPUT_CHARS} 字符上限，请缩小查询范围"
                    );
                }
                format!("[exit={code}]\n{trimmed}")
            }
            Err(e) => format!("[error] {e}"),
        }
    }

    fn push_file_to_client<F>(path_str: &str, send_msg: &F) -> Result<(), String>
    where
        F: Fn(DvcWireMessage) -> Result<(), String>,
    {
        let path = PathBuf::from(path_str);
        use std::io::Read;
        let file = std::fs::File::open(&path).map_err(|e| format!("读取文件失败: {e}"))?;
        let mut data = Vec::new();
        file.take(8 * 1024 * 1024 + 1)
            .read_to_end(&mut data)
            .map_err(|e| e.to_string())?;
        if data.len() > 8 * 1024 * 1024 {
            return Err("文件超过 8 MiB 上限".to_owned());
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "artifact.bin".to_owned());
        send_msg(DvcWireMessage {
            from: "server".to_owned(),
            seq: 0,
            msg_type: "file_start".to_owned(),
            text: String::new(),
            name: Some(name.clone()),
            size: Some(data.len() as u64),
            b64: None,
            sha256: None,
        })?;
        let mut hasher = Sha256::new();
        for chunk in data.chunks(FILE_CHUNK_SIZE) {
            hasher.update(chunk);
            send_msg(DvcWireMessage {
                from: "server".to_owned(),
                seq: 0,
                msg_type: "file_chunk".to_owned(),
                text: String::new(),
                name: None,
                size: None,
                b64: Some(BASE64.encode(chunk)),
                sha256: None,
            })?;
        }
        let digest = format!("{:x}", hasher.finalize());
        send_msg(DvcWireMessage {
            from: "server".to_owned(),
            seq: 0,
            msg_type: "file_end".to_owned(),
            text: String::new(),
            name: Some(name.clone()),
            size: Some(data.len() as u64),
            b64: None,
            sha256: Some(digest),
        })?;
        println!("[send] 已回传文件 {name} ({} bytes)", data.len());
        Ok(())
    }
}
