//! Bounded command replies. Each multipart reply belongs to one request/session.
use crate::{BASE64, DvcWireMessage};
use base64::Engine as _;
use sha2::{Digest, Sha256};

pub const MAX_COMMAND_RESULT_BYTES: usize = 16 * 1024 * 1024;
pub const COMMAND_RESULT_CHUNK_BYTES: usize = 48 * 1024;

/// New clients put a request UUID in `cmd.name`. Older clients keep the single-frame format.
pub fn send_command_result(
    output: &str,
    request: Option<&str>,
    send: impl Fn(DvcWireMessage) -> Result<(), String>,
) -> Result<(), String> {
    let request = request.filter(|id| uuid::Uuid::parse_str(id).is_ok());
    let output = if output.len() > MAX_COMMAND_RESULT_BYTES {
        "[error] 查询输出超过 16 MiB 总量上限，请缩小查询范围。"
    } else if request.is_none() && output.len() > 512 * 1024 {
        "[error] 当前客户端不支持分段结果，请更新工作台后重新采集。"
    } else {
        output
    };
    let frame = |kind: &str| {
        let mut frame = DvcWireMessage::result("server", 0, "");
        frame.msg_type = kind.into();
        frame.name = request.map(str::to_owned);
        frame
    };
    if output.len() <= COMMAND_RESULT_CHUNK_BYTES || request.is_none() {
        let mut result = frame("result");
        result.text = output.into();
        return send(result);
    }
    let mut start = frame("result_start");
    start.size = Some(output.len() as u64);
    send(start)?;
    for (index, bytes) in output
        .as_bytes()
        .chunks(COMMAND_RESULT_CHUNK_BYTES)
        .enumerate()
    {
        let mut chunk = frame("result_chunk");
        chunk.size = Some((index * COMMAND_RESULT_CHUNK_BYTES) as u64);
        chunk.b64 = Some(BASE64.encode(bytes));
        send(chunk)?;
    }
    let mut end = frame("result_end");
    end.size = Some(output.len() as u64);
    end.sha256 = Some(format!("{:x}", Sha256::digest(output.as_bytes())));
    send(end)
}

pub(crate) struct PendingCommand {
    pub id: String,
    stream: Option<(usize, Vec<u8>)>,
    pub result: Option<Result<String, String>>,
}

impl PendingCommand {
    pub fn new(id: String) -> Self {
        Self {
            id,
            stream: None,
            result: None,
        }
    }

    /// Returns false for unrelated/late messages. Never exposes partial output.
    pub fn accept(&mut self, message: DvcWireMessage) -> bool {
        if self.result.is_some()
            || (message.name.as_deref() != Some(&self.id)
                && !(message.msg_type == "result" && message.name.is_none()))
        {
            return false;
        }
        match self.consume(message) {
            Ok(Some(output)) => self.result = Some(Ok(output)),
            Ok(None) => {}
            Err(()) => {
                self.stream = None;
                self.result = Some(Err(
                    "分段结果不完整或校验失败，本次结果未采用；请重新采集。".into(),
                ));
            }
        }
        true
    }

    fn consume(&mut self, m: DvcWireMessage) -> Result<Option<String>, ()> {
        match m.msg_type.as_str() {
            "result"
                if self.stream.is_none()
                    && m.text.len() <= MAX_COMMAND_RESULT_BYTES
                    && m.size.is_none()
                    && m.b64.is_none()
                    && m.sha256.is_none() =>
            {
                Ok(Some(m.text))
            }
            "result_start"
                if self.stream.is_none()
                    && m.text.is_empty()
                    && m.b64.is_none()
                    && m.sha256.is_none() =>
            {
                let size = m
                    .size
                    .filter(|size| *size > 0 && *size <= MAX_COMMAND_RESULT_BYTES as u64)
                    .ok_or(())? as usize;
                self.stream = Some((size, Vec::new()));
                Ok(None)
            }
            "result_chunk" if m.text.is_empty() && m.sha256.is_none() => {
                let (expected, bytes) = self.stream.as_mut().ok_or(())?;
                if m.size != Some(bytes.len() as u64) {
                    return Err(());
                }
                let encoded = m
                    .b64
                    .as_deref()
                    .filter(|s| !s.is_empty() && s.len() <= COMMAND_RESULT_CHUNK_BYTES / 3 * 4)
                    .ok_or(())?;
                let chunk = BASE64.decode(encoded).map_err(|_| ())?;
                if chunk.is_empty()
                    || chunk.len() > COMMAND_RESULT_CHUNK_BYTES
                    || bytes.len() + chunk.len() > *expected
                {
                    return Err(());
                }
                bytes.extend_from_slice(&chunk);
                Ok(None)
            }
            "result_end" if m.text.is_empty() && m.b64.is_none() => {
                let (expected, bytes) = self.stream.take().ok_or(())?;
                let digest = m.sha256.filter(|s| s.len() == 64).ok_or(())?;
                if bytes.len() != expected
                    || m.size != Some(expected as u64)
                    || !digest.eq_ignore_ascii_case(&format!("{:x}", Sha256::digest(&bytes)))
                {
                    return Err(());
                }
                String::from_utf8(bytes).map(Some).map_err(|_| ())
            }
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn frames(text: &str, id: &str) -> Vec<DvcWireMessage> {
        let frames = std::cell::RefCell::new(Vec::new());
        send_command_result(text, Some(id), |m| {
            frames.borrow_mut().push(m);
            Ok(())
        })
        .unwrap();
        frames.into_inner()
    }
    #[test]
    fn large_utf8_reply_round_trips_only_after_the_digest() {
        let id = uuid::Uuid::new_v4().to_string();
        let text = "[exit=0]\n中🙂文".repeat(100_000);
        let mut pending = PendingCommand::new(id.clone());
        let mut messages = frames(&text, &id);
        let end = messages.pop().unwrap();
        for message in messages {
            assert!(crate::encode_frame(&message).unwrap().len() < 66000);
            assert!(pending.accept(message));
            assert!(pending.result.is_none());
        }
        pending.accept(end);
        assert_eq!(pending.result.unwrap().unwrap(), text);
    }
    #[test]
    fn gaps_duplicates_reordering_wrong_digests_and_limits_are_rejected() {
        let id = uuid::Uuid::new_v4().to_string();
        let original = frames(&"x".repeat(100_000), &id);
        for scenario in 0..7 {
            let mut messages = original.clone();
            match scenario {
                0 => {
                    messages.remove(1);
                }
                1 => messages.insert(2, messages[1].clone()),
                2 => messages.swap(1, 2),
                3 => messages.last_mut().unwrap().sha256 = Some("0".repeat(64)),
                4 => messages[0].size = Some(MAX_COMMAND_RESULT_BYTES as u64 + 1),
                5 => messages[1].b64 = Some("!".into()),
                _ => messages[1].size = Some(u64::MAX),
            }
            let mut pending = PendingCommand::new(id.clone());
            for message in messages {
                pending.accept(message);
            }
            assert!(pending.result.unwrap().is_err(), "scenario {scenario}");
        }
    }
    #[test]
    fn unrelated_and_post_completion_messages_never_replace_a_reply() {
        let id = uuid::Uuid::new_v4().to_string();
        let mut pending = PendingCommand::new(id.clone());
        for message in frames(&"x".repeat(100_000), &uuid::Uuid::new_v4().to_string()) {
            assert!(!pending.accept(message));
        }
        assert!(pending.result.is_none());
        pending.accept(DvcWireMessage::result("server", 1, "legacy reply"));
        assert!(!pending.accept(frames("later", &id).remove(0)));
        assert_eq!(pending.result.unwrap().unwrap(), "legacy reply");
    }
}
