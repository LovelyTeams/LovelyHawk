"""Read-only, bounded correlation of one live SQL connection with Linux procfs.

Input contains only PID, socket endpoints and an optional reported directory.
No process arguments, environment, credentials, configuration or program runs.
"""
import datetime
import hashlib
import ipaddress
import json
import os
import select
import signal
import stat
import sys


class Refusal(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise Refusal(reason)


def read(path, limit):
    with open(path, "rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "limit-exceeded")
    return data


def process_stat(pid):
    data = read("/proc/%d/stat" % pid, 4096)
    fields = data[data.rindex(b")") + 2:].split()
    require(len(fields) >= 20 and fields[0] not in (b"Z", b"X", b"x"), "process-changed")
    return int(fields[1]), int(fields[19])


def path_text(value):
    require(value.startswith("/") and len(value.encode()) <= 2048 and not any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value), "path-unavailable")
    return value


def address(raw):
    # procfs prints each native-endian 32-bit word, including for IPv6.
    require(len(raw) in (8, 32), "invalid-procfs")
    packed = b"".join(int(raw[i:i + 8], 16).to_bytes(4, sys.byteorder) for i in range(0, len(raw), 8))
    value = ipaddress.ip_address(packed)
    return value.ipv4_mapped if isinstance(value, ipaddress.IPv6Address) and value.ipv4_mapped else value


def endpoint(raw):
    host, port = raw.split(":")
    return address(host), int(port, 16)


def expected_address(raw):
    value = ipaddress.ip_address(raw)
    return value.ipv4_mapped if isinstance(value, ipaddress.IPv6Address) and value.ipv4_mapped else value


def socket_inode(pid, request):
    wanted = ((expected_address(request["serverAddress"]), request["serverPort"]), (expected_address(request["clientAddress"]), request["clientPort"]))
    found = []
    total = 0
    for protocol in ("tcp", "tcp6"):
        try:
            lines = read("/proc/%d/net/%s" % (pid, protocol), 2 * 1024 * 1024).splitlines()[1:]
        except FileNotFoundError:
            continue
        for line in lines:
            total += 1
            require(total <= 16384, "limit-exceeded")
            fields = line.split()
            require(len(fields) >= 10, "invalid-procfs")
            if fields[3] == b"01" and (endpoint(fields[1].decode()), endpoint(fields[2].decode())) == wanted:
                found.append(int(fields[9]))
    require(len(found) == 1 and found[0] > 0, "socket-unmatched")
    owned = False
    with os.scandir("/proc/%d/fd" % pid) as entries:
        for count, item in enumerate(entries):
            require(count < 4096, "limit-exceeded")
            try:
                owned |= os.readlink(item.path) == "socket:[%d]" % found[0]
            except FileNotFoundError:
                continue
    require(owned, "socket-unmatched")
    return str(found[0])


def live(fd):
    poll = select.poll()
    poll.register(fd, select.POLLIN)
    require(not poll.poll(0), "process-changed")


def namespaces(pid):
    return {name: str(os.stat("/proc/%s/ns/%s" % (pid, name)).st_ino) for name in ("pid", "net", "mnt")}


def capture(request):
    require(sys.platform == "linux" and hasattr(os, "pidfd_open"), "unsupported")
    pid = request["backendPid"]
    require(type(pid) is int and 1 <= pid <= 2147483647, "invalid-input")
    for prefix in ("server", "client"):
        require(type(request[prefix + "Port"]) is int and 1 <= request[prefix + "Port"] <= 65535, "invalid-input")
        expected_address(request[prefix + "Address"])
    reported = request["dataDirectory"]
    require(reported is None or isinstance(reported, str), "invalid-input")
    if reported is not None:
        path_text(reported)
    own = namespaces("self")
    backend_fd = os.pidfd_open(pid)
    try:
        live(backend_fd)
        backend = process_stat(pid)
        parent = backend[0]
        require(parent > 0 and parent != pid, "process-changed")
        parent_fd = os.pidfd_open(parent)
        try:
            live(parent_fd)
            master = process_stat(parent)
            require(namespaces(pid) == own == namespaces(parent), "namespace-unmatched")
            inode = socket_inode(pid, request)
            boot_id = read("/proc/sys/kernel/random/boot_id", 64).decode().strip()
            # Read through the pinned process's executable link; never execute it.
            executable_path = path_text(os.readlink("/proc/%d/exe" % parent))
            require(not executable_path.endswith(" (deleted)"), "executable-unavailable")
            cwd = path_text(os.readlink("/proc/%d/cwd" % parent))
            require(cwd == os.readlink("/proc/%d/cwd" % pid), "process-changed")
            with open("/proc/%d/exe" % parent, "rb") as executable:
                before = os.fstat(executable.fileno())
                child = os.stat("/proc/%d/exe" % pid)
                require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 64 * 1024 * 1024, "limit-exceeded")
                require((before.st_dev, before.st_ino) == (child.st_dev, child.st_ino), "executable-unmatched")
                digest = hashlib.sha256()
                total = 0
                while True:
                    block = executable.read(64 * 1024)
                    if not block:
                        break
                    total += len(block)
                    require(total <= 64 * 1024 * 1024, "limit-exceeded")
                    digest.update(block)
                after = os.fstat(executable.fileno())
                require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "process-changed")
            require(process_stat(pid) == backend and process_stat(parent) == master, "process-changed")
            require(namespaces(pid) == own == namespaces(parent) == namespaces("self"), "namespace-unmatched")
            require(os.readlink("/proc/%d/exe" % parent) == executable_path and os.readlink("/proc/%d/cwd" % parent) == cwd, "process-changed")
            current_exe = os.stat("/proc/%d/exe" % parent)
            require((current_exe.st_dev, current_exe.st_ino) == (before.st_dev, before.st_ino), "process-changed")
            child_exe = os.stat("/proc/%d/exe" % pid)
            require((child_exe.st_dev, child_exe.st_ino) == (before.st_dev, before.st_ino) and os.readlink("/proc/%d/cwd" % pid) == cwd, "process-changed")
            require(socket_inode(pid, request) == inode, "socket-unmatched")
            live(backend_fd)
            live(parent_fd)
            return {"observedAt": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"), "bootId": boot_id,
                    "backendPid": pid, "backendStartTicks": str(backend[1]), "postmasterPid": parent, "postmasterStartTicks": str(master[1]),
                    "socketInode": inode, "pidNamespace": own["pid"], "networkNamespace": own["net"], "mountNamespace": own["mnt"],
                    "executablePath": executable_path, "executableDevice": str(before.st_dev), "executableInode": str(before.st_ino), "executableSha256": digest.hexdigest(),
                    "dataDirectory": cwd, "reportedDirectoryMatches": None if reported is None else reported.rstrip("/") == cwd.rstrip("/")}
        finally:
            os.close(parent_fd)
    finally:
        os.close(backend_fd)


def main():
    if sys.platform != "linux" or not hasattr(os, "pidfd_open"):
        print(json.dumps({"state": "unavailable", "reason": "unsupported", "process": None}))
        return
    def timeout(_signal, _frame):
        raise Refusal("timeout")
    try:
        signal.signal(signal.SIGALRM, timeout)
        signal.alarm(6)
        raw = sys.stdin.buffer.read(8193)
        require(len(raw) <= 8192, "invalid-input")
        request = json.loads(raw)
        require(isinstance(request, dict) and set(request) == {"backendPid", "serverAddress", "serverPort", "clientAddress", "clientPort", "dataDirectory"}, "invalid-input")
        result = {"state": "matched", "reason": None, "process": capture(request)}
    except Refusal as error:
        result = {"state": "unavailable", "reason": str(error), "process": None}
    except PermissionError:
        result = {"state": "unavailable", "reason": "permission-denied", "process": None}
    except (FileNotFoundError, ProcessLookupError):
        result = {"state": "unavailable", "reason": "process-unavailable", "process": None}
    except (OSError, ValueError, KeyError, TypeError):
        result = {"state": "unavailable", "reason": "invalid-procfs", "process": None}
    finally:
        signal.alarm(0)
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
