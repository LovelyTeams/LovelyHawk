# Bidirectional chat demo - server side.
# Run INSIDE the RDP session:  python demo_server.py
#
# - Prints every message received from the client plugin
# - Anything you type on stdin is sent to the client
import ctypes
import logging
import os
import signal
import sys
import threading
from ctypes import wintypes

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from win32more.Windows.Win32.Foundation import GetLastError
from win32more.Windows.Win32.System.RemoteDesktop import (
    WTSVirtualChannelOpenEx,
    WTSVirtualChannelClose,
    WTSVirtualChannelRead,
    WTSVirtualChannelWrite,
    WTS_CURRENT_SESSION,
    WTS_CHANNEL_OPTION_DYNAMIC,
)

from demo_protocol import (
    encode, run_command, send_file, FileReceiver, StreamDecoder,
    CMD_PREFIX, SEND_PREFIX,
)
from rdp_simple_plugin_server.dvc_reassembler import DvcReassembler

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s: %(message)s",
                    datefmt="%H:%M:%S")
_log = logging.getLogger("demo_server")

CHANNEL_NAME = "dvc::demo::chat"
READ_BUFFER_SIZE = 4096
READ_TIMEOUT_MS = 2000
# WTSVirtualChannelRead reports a timed-out read as failure + one of these codes
READ_TIMEOUT_CODES = {1460, 996}  # ERROR_TIMEOUT, ERROR_IO_INCOMPLETE

stop_event = threading.Event()
channel = None
write_lock = threading.Lock()
seq = 0


def send_msg(type: str, text: str = "", **fields) -> bool:
    """Send one framed message to the client. Returns False on write failure."""
    global seq
    data = encode("server", seq, text, type, **fields)
    seq += 1
    written = wintypes.DWORD(0)
    with write_lock:
        ok = WTSVirtualChannelWrite(channel, data, len(data), ctypes.byref(written))
    if not ok:
        _log.error("WTSVirtualChannelWrite failed: %d", GetLastError())
        return False
    if type in ("chat", "cmd", "result"):
        _log.info("-> client (%d bytes): %s", written.value, text)
    return True


def send_text(text: str, type: str = "chat") -> bool:
    return send_msg(type, text)


def _recv_log(msg: str) -> None:
    _log.info("%s", msg)


file_receiver = FileReceiver(os.path.join(os.path.dirname(os.path.abspath(__file__)), "recv"))


def read_loop() -> None:
    """Read PDU fragments, reassemble, decode chat messages."""
    reassembler = DvcReassembler()
    decoder = StreamDecoder()
    while not stop_event.is_set():
        buf = ctypes.create_string_buffer(READ_BUFFER_SIZE)
        n = wintypes.DWORD(0)
        ok = WTSVirtualChannelRead(channel, READ_TIMEOUT_MS, buf,
                                   READ_BUFFER_SIZE, ctypes.byref(n))
        if not ok:
            err = GetLastError()
            if err in READ_TIMEOUT_CODES:
                continue
            _log.error("WTSVirtualChannelRead failed: %d", err)
            break
        if n.value == 0:
            _log.info("channel closed by peer")
            break

        full = reassembler.push_read(buf.raw[:n.value])
        if full is None:
            continue
        try:
            for msg in decoder.feed(full):
                handle_message(msg)
        except Exception as e:
            _log.warning("decode error: %s", e)
    stop_event.set()


def handle_message(msg: dict) -> None:
    mtype = msg.get("type", "chat")
    text = msg.get("text", "")
    if mtype == "cmd":
        _log.info("<- %s cmd: %s", msg.get("from"), text)
        def _run():
            send_text(run_command(text), "result")
        threading.Thread(target=_run, daemon=True).start()
    elif mtype == "result":
        _log.info("<- %s result:\n%s", msg.get("from"), text)
    elif mtype in ("file_start", "file_chunk", "file_end"):
        file_receiver.handle(msg, _recv_log)
    else:
        _log.info("<- %s seq=%s: %s", msg.get("from"), msg.get("seq"), text)


def stdin_loop() -> None:
    _log.info("Type a message + Enter to chat; '/cmd <命令>' 对端执行命令; '/send <文件路径>' 传文件 (Ctrl+C to quit)")
    for line in sys.stdin:
        text = line.rstrip("\r\n")
        if not text or stop_event.is_set():
            continue
        if text.startswith(CMD_PREFIX):
            ok = send_text(text[len(CMD_PREFIX):], "cmd")
        elif text.startswith(SEND_PREFIX):
            path = text[len(SEND_PREFIX):].strip().strip('"')
            threading.Thread(
                target=lambda: send_file(path, send_msg, _recv_log),
                daemon=True).start()
            continue
        else:
            ok = send_text(text)
        if not ok:
            stop_event.set()
            break


def main() -> int:
    global channel
    _log.info("Opening DVC '%s' ...", CHANNEL_NAME)
    channel = WTSVirtualChannelOpenEx(
        WTS_CURRENT_SESSION,
        CHANNEL_NAME.encode("ascii"),
        WTS_CHANNEL_OPTION_DYNAMIC,
    )
    if not channel:
        _log.error("WTSVirtualChannelOpenEx failed: %d", GetLastError())
        return 1
    _log.info("Channel open (handle=%s)", channel)

    def on_sigint(sig, frame):
        _log.info("Ctrl+C, shutting down")
        stop_event.set()
        try:
            WTSVirtualChannelClose(channel)
        except Exception:
            pass

    signal.signal(signal.SIGINT, on_sigint)

    t_read = threading.Thread(target=read_loop, daemon=True)
    t_read.start()
    stdin_loop()          # main thread reads stdin
    stop_event.wait(2)
    try:
        WTSVirtualChannelClose(channel)
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
