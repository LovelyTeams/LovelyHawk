"""Shared protocol for the bidirectional demo.

Wire format (little-endian):
    [bodyLen:u32][json body]
    body = {"from": "server"|"client", "seq": n,
            "type": <type>, "text": "...", ...extra fields}

Message types:
- chat:       plain message, just print it
- cmd:        text is a shell command; receiver runs it and replies
              with a "result" message whose text is the output
- result:     command output, just print it
- file_start: {"name","size"} - announces an incoming file
- file_chunk: {"b64"} - one base64 chunk, in stream order
- file_end:   {"name","size","sha256"} - receiver verifies and reports
"""

import base64
import hashlib
import json
import os
import struct
import subprocess

MAX_FRAME = 16 * 1024 * 1024
MAX_OUTPUT = 8000
CMD_PREFIX = "/cmd "
SEND_PREFIX = "/send "
CHUNK_SIZE = 48 * 1024  # raw bytes per file_chunk (64KB after base64)


def encode(sender: str, seq: int, text: str = "", type: str = "chat", **fields) -> bytes:
    body = {"from": sender, "seq": seq, "type": type, "text": text, **fields}
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    return struct.pack("<I", len(data)) + data


def run_command(cmd: str, timeout: int = 30) -> str:
    """Run a shell command, return '[exit=N] output' (capped)."""
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, errors="replace", timeout=timeout)
        out = ((p.stdout or "") + (p.stderr or "")).strip()
        if len(out) > MAX_OUTPUT:
            out = out[:MAX_OUTPUT] + f"\n... <truncated, {len(out)} chars total>"
        return f"[exit={p.returncode}]\n{out}"
    except subprocess.TimeoutExpired:
        return f"[error] command timed out after {timeout}s"
    except Exception as e:
        return f"[error] {e}"


# ------------------------------------------------------------------
# File transfer
# ------------------------------------------------------------------

def send_file(path: str, send_msg, log=print) -> bool:
    """Send a file over the channel.

    send_msg(type, text="", **fields) -> bool  is the caller's frame sender.
    Returns True if the whole file was handed to the channel.
    """
    if not os.path.isfile(path):
        log(f"[send] not a file: {path}")
        return False
    name = os.path.basename(path)
    size = os.path.getsize(path)
    sha = hashlib.sha256()

    if not send_msg("file_start", name=name, size=size):
        return False
    log(f"[send] -> {name} ({size} bytes)")

    sent = 0
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                sha.update(chunk)
                if not send_msg("file_chunk",
                                b64=base64.b64encode(chunk).decode("ascii")):
                    return False
                sent += len(chunk)
    except OSError as e:
        log(f"[send] read failed: {e}")
        return False

    if not send_msg("file_end", name=name, size=sent, sha256=sha.hexdigest()):
        return False
    log(f"[send] done: {name} ({sent} bytes, sha256={sha.hexdigest()[:16]}...)")
    return True


class FileReceiver:
    """Handles file_start/file_chunk/file_end messages, writes to dest_dir."""

    def __init__(self, dest_dir: str) -> None:
        self._dest = dest_dir
        self._cur = None  # {"fp","name","size","received","sha"}

    def handle(self, msg: dict, log=print) -> None:
        mtype = msg.get("type")
        if mtype == "file_start":
            name = os.path.basename(msg.get("name") or "unnamed")
            size = int(msg.get("size") or 0)
            os.makedirs(self._dest, exist_ok=True)
            target = os.path.join(self._dest, name)
            self._cur = {
                "fp": open(target, "wb"), "name": name, "path": target,
                "size": size, "received": 0, "sha": hashlib.sha256(),
            }
            log(f"[recv] <- {name} ({size} bytes)")

        elif mtype == "file_chunk" and self._cur:
            data = base64.b64decode(msg.get("b64") or "")
            self._cur["fp"].write(data)
            self._cur["sha"].update(data)
            self._cur["received"] += len(data)

        elif mtype == "file_end" and self._cur:
            cur = self._cur
            self._cur = None
            cur["fp"].close()
            digest = cur["sha"].hexdigest()
            ok_size = cur["received"] == cur["size"] == int(msg.get("size") or -1)
            ok_hash = digest == msg.get("sha256")
            status = "OK" if (ok_size and ok_hash) else \
                f"MISMATCH size={ok_size} sha256={ok_hash}"
            log(f"[recv] done: {cur['path']} ({cur['received']} bytes) [{status}]")


def decode_body(body: bytes) -> dict:
    return json.loads(body.decode("utf-8"))


class StreamDecoder:
    """Reassembles length-prefixed messages from an arbitrary byte stream.

    DVC delivers a byte stream; a single Write may arrive split across
    several reads (or several Writes coalesced). Keep feeding feed()
    and consume the complete messages it returns.
    """

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, data: bytes) -> list:
        self._buf += data
        out = []
        while len(self._buf) >= 4:
            (n,) = struct.unpack_from("<I", self._buf)
            if n > MAX_FRAME:
                raise ValueError(f"implausible frame length: {n}")
            if len(self._buf) < 4 + n:
                break
            body = bytes(self._buf[4:4 + n])
            del self._buf[:4 + n]
            out.append(decode_body(body))
        return out
