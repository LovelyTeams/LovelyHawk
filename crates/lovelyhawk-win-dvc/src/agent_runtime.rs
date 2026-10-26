//! Bounded child-process IO and WTS idle handling shared by the session agent.
use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

/// A successful zero-byte WTS read is an idle poll, not EOF. Errors 1460 and
/// 996 also mean no complete data is available; other failures end the session.
pub fn read_is_idle(succeeded: bool, bytes: u32, error: u32) -> bool {
    (succeeded && bytes == 0) || (!succeeded && matches!(error, 1460 | 996))
}

/// Drain both pipes concurrently, cap allocation before it grows, and bound the
/// wait even when a child descendant keeps an inherited pipe open.
pub fn bounded_output(
    command: &mut Command,
    limit: usize,
    timeout: Duration,
) -> Result<Output, String> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command.spawn().map_err(|e| format!("无法启动查询: {e}"))?;
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let out_tx = tx.clone();
    let out_stop = Arc::clone(&stop);
    let out_reader = std::thread::spawn(move || {
        let _ = out_tx.send((0, read_pipe(stdout, limit, &out_stop)));
    });
    let err_stop = Arc::clone(&stop);
    let err_tx = tx.clone();
    let err_reader = std::thread::spawn(move || {
        let _ = err_tx.send((1, read_pipe(stderr, limit, &err_stop)));
    });
    drop(tx);
    let deadline = Instant::now() + timeout;
    let mut output: [Option<Vec<u8>>; 2] = [None, None];
    let result = (|| {
        loop {
            while let Ok((index, bytes)) = rx.try_recv() {
                let bytes = bytes.map_err(|e| format!("读取查询输出失败: {e}"))?;
                if bytes.len() > limit {
                    return Err(format!("查询输出超过 {} 字节上限", limit));
                }
                output[index] = Some(bytes);
            }
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())?
                && output.iter().all(Option::is_some)
            {
                return Ok(Output {
                    status,
                    stdout: output[0].take().unwrap(),
                    stderr: output[1].take().unwrap(),
                });
            }
            if Instant::now() >= deadline {
                return Err(
                    "查询超时，已停止等待并请求终止查询进程；其派生进程需另行核实".to_owned(),
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    stop.store(true, Ordering::Release);
    #[cfg(windows)]
    {
        let _ = out_reader.join();
        let _ = err_reader.join();
    }
    #[cfg(not(windows))]
    {
        let _ = (out_reader, err_reader);
    }
    result
}

#[cfg(windows)]
fn read_pipe(
    mut pipe: impl Read + std::os::windows::io::AsRawHandle,
    limit: usize,
    stop: &AtomicBool,
) -> std::io::Result<Vec<u8>> {
    use windows::Win32::{Foundation::HANDLE, System::Pipes::PeekNamedPipe};
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8192];
    while !stop.load(Ordering::Acquire) && bytes.len() <= limit {
        let mut available = 0;
        // SAFETY: the pipe is owned throughout this call; no other reader can
        // consume bytes between the nonblocking peek and the bounded read.
        if let Err(error) = unsafe {
            PeekNamedPipe(
                HANDLE(pipe.as_raw_handle()),
                None,
                0,
                None,
                Some(&mut available),
                None,
            )
        } {
            if error.code().0 as u32 & 0xffff == 109 {
                break;
            }
            return Err(std::io::Error::other(error));
        }
        if available == 0 {
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        let size = (available as usize)
            .min(buffer.len())
            .min(limit + 1 - bytes.len());
        let count = pipe.read(&mut buffer[..size])?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    Ok(bytes)
}

#[cfg(not(windows))]
fn read_pipe(mut pipe: impl Read, limit: usize, _: &AtomicBool) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    pipe.by_ref()
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn idle_reads_do_not_disconnect_the_agent() {
        assert!(read_is_idle(true, 0, 0));
        assert!(read_is_idle(false, 0, 1460));
        assert!(read_is_idle(false, 0, 996));
        assert!(!read_is_idle(false, 0, 6));
        assert!(!read_is_idle(true, 12, 0));
    }
    #[cfg(windows)]
    #[test]
    fn output_and_execution_time_are_bounded() {
        let mut command = Command::new("cmd.exe");
        command.args(["/d", "/c", "echo 123456789"]);
        assert!(
            bounded_output(&mut command, 4, Duration::from_secs(3))
                .unwrap_err()
                .contains("上限")
        );
        let mut command = Command::new("powershell.exe");
        command.args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Start-Sleep -Seconds 10",
        ]);
        let start = Instant::now();
        assert!(
            bounded_output(&mut command, 1024, Duration::from_millis(200))
                .unwrap_err()
                .contains("超时")
        );
        assert!(start.elapsed() < Duration::from_secs(5));
    }
}
