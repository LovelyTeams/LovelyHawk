use super::{BASE64, WindowsIncidentService, encode_powershell_command, strip_exit_prefix};
use crate::{CoreError, CoreResult};
use base64::Engine as _;
use flate2::{Compression, write::GzEncoder};
use std::{io::Write, time::Duration};

pub(super) fn compressed_command(script: &str) -> CoreResult<String> {
    let invalid =
        || CoreError::validation("windows script", "本次操作超过命令传输上限，请缩小范围。");
    if script.len() > 512 * 1024 {
        return Err(invalid());
    }
    let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
    gzip.write_all(script.as_bytes()).map_err(|_| invalid())?;
    let data = BASE64.encode(gzip.finish().map_err(|_| invalid())?);
    // Fixed application source only; caller data is separately encoded JSON.
    let loader = format!(
        "# LovelyHawk-IR-Query\n$m=[IO.MemoryStream]::new([Convert]::FromBase64String('{data}'));$z=[IO.Compression.GZipStream]::new($m,[IO.Compression.CompressionMode]::Decompress);$r=[IO.StreamReader]::new($z,[Text.Encoding]::UTF8);try{{& ([ScriptBlock]::Create($r.ReadToEnd()))}}finally{{$r.Dispose();$m.Dispose()}}"
    );
    let command = encode_powershell_command(&loader);
    if command.encode_utf16().count() > 30000 {
        return Err(invalid());
    }
    Ok(command)
}
impl WindowsIncidentService {
    pub(super) fn run_bounded_script(&self, script: &str, session: &str) -> CoreResult<String> {
        let command = compressed_command(script)?;
        let output = self
            .hub
            .execute_command_for_session(&command, Duration::from_secs(45), session)
            .map_err(|_| {
                CoreError::validation(
                    "windows script",
                    "没有取得目标返回结果，请核对连接并重新采集；不能确认操作是否完成。",
                )
            })?;
        if output.len() > lovelyhawk_win_dvc::command_result::MAX_COMMAND_RESULT_BYTES {
            return Err(CoreError::validation(
                "windows script",
                "目标返回内容超过上限。",
            ));
        }
        Ok(strip_exit_prefix(&output)?.to_owned())
    }
}
