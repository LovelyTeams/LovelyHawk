"""Finite remote helper, embedded by the Rust middleware service (Python 3.9+).

No target installation, shell evaluation, user supplied program, or PID-file
signalling. Raw environment and process text never leave this helper.
"""
import hashlib
import json
import os
import re
import select
import shlex
import signal
import subprocess
import sys
import time


class Refusal(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise Refusal(reason)


def read(path, limit):
    with open(path, "rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "bounded-read-exceeded")
    return data


def digest(data):
    return hashlib.sha256(data).hexdigest()


def process_ids():
    ids = []
    with os.scandir("/proc") as entries:
        for entry in entries:
            if entry.name.isdecimal():
                ids.append(int(entry.name))
                require(len(ids) <= 8192, "process-inventory-too-large")
    return sorted(ids)


def stat(pid):
    value = read("/proc/%d/stat" % pid, 4096)
    fields = value[value.rindex(b")") + 2:].split()
    # Inventory may cross unrelated zombies, especially under container PID 1.
    # Master liveness is verified by its pinned pidfd; empty zombie cmdlines do
    # not match a serving worker. Do not fail every instance because one exited.
    require(len(fields) >= 20, "invalid-process-stat")
    return int(fields[1]), int(fields[19])


def canonical(path):
    require(isinstance(path, str) and len(path) <= 4096 and path.startswith("/"), "non-absolute-path")
    require(re.fullmatch(r"/[A-Za-z0-9_./+-]+", path) is not None, "unsupported-path-characters")
    path = path.rstrip("/") or "/"
    require(path != "/" and os.path.realpath(path) == path, "non-canonical-path")
    return path


def launch_arguments(command, executable):
    # nginx flattens argv into a title; never shlex arbitrary titles back into
    # supposedly original argv. Only these complete conventional titles match.
    prefix = "nginx: master process "
    require(command.startswith(prefix), "not-nginx-master")
    title = command[len(prefix):]
    for name in ("nginx", executable):
        if title == name:
            return []
        if title == name + " -g daemon off;":
            return ["-g", "daemon off;"]
    raise Refusal("unsupported-master-arguments")


def live(fd):
    poll = select.poll()
    poll.register(fd, select.POLLIN)
    require(not poll.poll(0), "process-exited")


def capture(pid):
    fd = os.pidfd_open(pid)
    try:
        live(fd)
        base = "/proc/%d/" % pid
        _, ticks = stat(pid)
        require(os.stat(base + "root") == os.stat("/"), "different-process-root")
        namespace = os.stat(base + "ns/mnt").st_ino
        require(namespace == os.stat("/proc/self/ns/mnt").st_ino, "different-mount-namespace")
        executable = canonical(os.readlink(base + "exe"))
        require(os.path.basename(executable) == "nginx", "unexpected-executable")
        command = read(base + "cmdline", 16384)
        first, _, padding = command.partition(b"\0")
        require(not padding.strip(b"\0"), "ambiguous-process-title")
        arguments = launch_arguments(first.decode("utf-8", "strict"), executable)
        environment = read(base + "environ", 262144)
        cwd = os.readlink(base + "cwd")
        require(cwd.startswith("/") and os.path.realpath(cwd) == cwd, "unsupported-working-directory")
        binary = read(base + "exe", 64 * 1024 * 1024)
        result = {
            "pid": pid, "start_time_ticks": ticks,
            "boot_id": read("/proc/sys/kernel/random/boot_id", 64).decode("ascii").strip(),
            "executable": executable, "executable_sha256": digest(binary),
            "cmdline_sha256": digest(command), "environment_sha256": digest(environment),
            "mount_namespace": namespace, "cwd": cwd, "arguments": arguments,
        }
        require(stat(pid)[1] == ticks, "process-changed-during-read")
        live(fd)
        return result
    finally:
        os.close(fd)


def run_nginx(evidence, flag):
    # Pin the executable before probing; replacing its path cannot substitute a
    # different program between the identity check and exec. Environment stays
    # on the target and matches the captured master, including env directives.
    pid = evidence["pid"]
    fd = os.open("/proc/%d/exe" % pid, os.O_RDONLY)
    try:
        verify(evidence)
        environment = dict(item.split(b"=", 1) for item in
                           read("/proc/%d/environ" % pid, 262144).split(b"\0") if b"=" in item)
        require(digest(os.pread(fd, 64 * 1024 * 1024 + 1, 0)) == evidence["executable_sha256"],
                "executable-changed")
        command = ["/proc/self/fd/%d" % fd, flag] + evidence["arguments"]
        # Drain bounded diagnostics instead of persisting arbitrary secret text.
        with subprocess.Popen(command, cwd=evidence["cwd"], env=environment,
                              pass_fds=(fd,), stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as child:
            output = bytearray()
            deadline = time.monotonic() + 20
            try:
                os.set_blocking(child.stdout.fileno(), False)
                while True:
                    require(time.monotonic() < deadline, "native-check-timeout")
                    chunk = child.stdout.read(65536)
                    if chunk:
                        output.extend(chunk)
                        require(len(output) <= 262144, "native-output-too-large")
                    elif chunk == b"" and child.poll() is not None:
                        break
                    else:
                        time.sleep(0.02)
                require(child.wait(timeout=1) == 0, "native-configuration-rejected")
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=2)
        verify(evidence)
        return output.decode("utf-8", "strict")
    finally:
        os.close(fd)


IDENTITY_FIELDS = ("pid", "start_time_ticks", "boot_id", "executable", "executable_sha256",
                   "cmdline_sha256", "environment_sha256", "mount_namespace", "cwd", "arguments")


def verify(evidence):
    observed = capture(evidence["pid"])
    require(all(observed[key] == evidence[key] for key in IDENTITY_FIELDS), "runtime-identity-changed")


def build_scope(evidence):
    output = run_nginx(evidence, "-V")
    version = output.splitlines()[0]
    require(re.fullmatch(r"nginx version: nginx/[0-9]+\.[0-9]+\.[0-9]+", version) is not None,
            "unsupported-nginx-version-banner")
    lines = [line[len("configure arguments: "):] for line in output.splitlines()
             if line.startswith("configure arguments: ")]
    require(len(lines) == 1, "missing-build-configuration")
    fields = shlex.split(lines[0])
    values = {}
    for key in ("prefix", "conf-path"):
        found = [value[len(key) + 3:] for value in fields if value.startswith("--" + key + "=")]
        require(len(found) == 1, "missing-build-path")
        values[key] = found[0]
    prefix = canonical(values["prefix"])
    config = canonical(os.path.join(prefix, values["conf-path"]))
    require(os.path.isfile(config) and os.path.isdir(prefix), "missing-instance-path")
    return {"prefix": prefix, "config": config, "version": version}


def verify_scope(evidence):
    # Durable history is data, not authority to choose another configuration.
    # Re-derive even its path/version fields from the pinned current executable.
    current = build_scope(evidence)
    require(all(evidence[key] == value for key, value in current.items()), "runtime-identity-changed")
    for pid in master_ids():
        if pid != evidence["pid"]:
            other = build_scope(capture(pid))
            require(other["config"] != evidence["config"], "shared-master-configuration")


def master_ids():
    masters = []
    for pid in process_ids():
        try:
            if read("/proc/%d/comm" % pid, 128).strip() != b"nginx":
                continue
            if read("/proc/%d/cmdline" % pid, 16384).startswith(b"nginx: master process "):
                require(len(masters) < 32, "too-many-nginx-masters")
                masters.append(pid)
        except (FileNotFoundError, ProcessLookupError):
            continue
    return masters


def discover():
    result = []
    for pid in master_ids():
        try:
            evidence = capture(pid)
        except (FileNotFoundError, ProcessLookupError):
            continue  # exited while listing, never a guessed instance
        require(len(result) < 32, "too-many-nginx-masters")
        evidence.update(build_scope(evidence))
        verify(evidence)
        result.append(evidence)
    require(len({entry["config"] for entry in result}) == len(result), "shared-master-configuration")
    return result


def workers(pid):
    result = set()
    for child in process_ids():
        try:
            parent, ticks = stat(child)
            if parent == pid and read("/proc/%d/cmdline" % child, 16384).split(b"\0")[0] == b"nginx: worker process":
                result.add((child, ticks))
                require(len(result) <= 1024, "too-many-workers")
        except (FileNotFoundError, ProcessLookupError):
            continue
    return result


def reload_and_verify(evidence):
    fd = os.pidfd_open(evidence["pid"])
    try:
        before = workers(evidence["pid"])
        require(before, "no-serving-workers")
        verify(evidence)
        live(fd)
        # pidfd never targets a new process if the numeric PID is recycled.
        signal.pidfd_send_signal(fd, signal.SIGHUP)
        deadline = time.monotonic() + 15
        stable = None
        since = 0
        while time.monotonic() < deadline:
            live(fd)
            current = workers(evidence["pid"])
            if current and current.isdisjoint(before):
                if current != stable:
                    stable, since = current, time.monotonic()
                elif time.monotonic() - since >= 0.6:
                    verify(evidence)
                    return
            else:
                stable = None
            time.sleep(0.15)
        raise Refusal("reload-worker-transition-unverified")
    finally:
        os.close(fd)


def tcp_listeners(data, ipv6):
    import ipaddress
    lines = data.splitlines()
    require(len(lines) <= 8193, "socket-inventory-too-large")
    result = []
    for line in lines[1:]:
        fields = line.split()
        require(len(fields) >= 10, "invalid-socket-inventory")
        if fields[3] != b"0A":
            continue
        address, port = fields[1].split(b":")
        require(len(address) == (32 if ipv6 else 8), "invalid-socket-inventory")
        # procfs prints native u32 words; tcp6 contains four such words.
        raw = b"".join(int(address[i:i + 8], 16).to_bytes(4, sys.byteorder)
                       for i in range(0, len(address), 8))
        result.append({"address": str(ipaddress.ip_address(raw)),
                       "port": int(port, 16), "inode": int(fields[9])})
    return result


def owned_listeners(pid):
    namespace = os.stat("/proc/%d/ns/net" % pid).st_ino
    require(namespace == os.stat("/proc/self/ns/net").st_ino, "different-network-namespace")
    inodes = set()
    with os.scandir("/proc/%d/fd" % pid) as entries:
        for count, entry in enumerate(entries):
            require(count < 4096, "socket-inventory-too-large")
            try:
                link = os.readlink(entry.path)
            except FileNotFoundError:
                continue
            match = re.fullmatch(r"socket:\[(\d+)\]", link)
            if match:
                inodes.add(int(match[1]))
    all_listeners = []
    for name in ("tcp", "tcp6"):
        try:
            data = read("/proc/%d/net/%s" % (pid, name), 2 * 1024 * 1024)
        except FileNotFoundError:
            require(name == "tcp6", "socket-inventory-unavailable")
            continue  # kernels built without IPv6 have no tcp6 table
        all_listeners.extend(tcp_listeners(data, name == "tcp6"))
    selected = [dict(item, network_namespace=namespace) for item in all_listeners if item["inode"] in inodes]
    require(len(selected) <= 64, "too-many-listeners")
    return selected, all_listeners


def overlaps(left, right):
    import ipaddress
    if left["port"] != right["port"]:
        return False
    a, b = (ipaddress.ip_address(item["address"]) for item in (left, right))
    a = getattr(a, "ipv4_mapped", None) or a
    b = getattr(b, "ipv4_mapped", None) or b
    if a.version != b.version:
        # Without the socket's IPV6_V6ONLY option, a wildcard may accept IPv4.
        return a == ipaddress.ip_address("::") or b == ipaddress.ip_address("::")
    return a == b or a.is_unspecified or b.is_unspecified


def verify_listener(evidence, endpoint):
    import ipaddress
    endpoint = dict(endpoint, address=str(ipaddress.ip_address(endpoint["address"])))
    selected, all_listeners = owned_listeners(evidence["pid"])
    require(endpoint in selected, "listener-changed")
    owned = {item["inode"] for item in selected}
    require(not any(overlaps(endpoint, item) and item["inode"] not in owned for item in all_listeners),
            "ambiguous-listener")


def probe_name(value):
    import ipaddress
    require(isinstance(value, str) and 0 < len(value) <= 253 and value.isascii(), "invalid-probe-name")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        require(":" not in value and not re.fullmatch(r"[0-9.]+", value), "invalid-probe-name")
    require(all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                for label in value.split(".")), "invalid-probe-name")
    return value


def probe_path(value):
    require(isinstance(value, str) and 0 < len(value) <= 1024 and value.startswith("/")
            and not value.startswith("//") and all(0x21 <= ord(char) <= 0x7e and char not in "?#\\" for char in value),
            "invalid-probe-path")
    return value


def tls_context(ssl, version, legacy):
    import warnings
    # create_default_context enables SSLKEYLOGFILE. Never write session keys,
    # including when the SSH account has that environment variable configured.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.keylog_filename = None
    if legacy:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_ciphers("ALL:@SECLEVEL=0")
    else:
        context.load_default_certs()
        context.set_alpn_protocols(["http/1.1"])
    protocol = getattr(ssl.TLSVersion, version)
    # The helper runs as __main__; default DeprecationWarnings for the old
    # versions otherwise corrupt its JSON channel (SSH combines both streams).
    # The UI already reports legacy acceptance as a risk, not a recommendation.
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=DeprecationWarning, message=r"ssl\.TLSVersion\..* is deprecated")
        context.minimum_version = protocol
        context.maximum_version = protocol
    return context


def tls_row(version, outcome, detail, certificate=None, http_outcome="not-sent", http_status=None):
    return {"version": version, "outcome": outcome, "detail": detail,
            "certificateSha256": certificate, "httpOutcome": http_outcome, "httpStatus": http_status}


def head_status(connection, hostname, port, path, deadline):
    host = "[" + hostname + "]" if ":" in hostname else hostname
    request = "HEAD %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n" % (path, host, port)
    connection.settimeout(max(0.01, deadline - time.monotonic()))
    connection.sendall(request.encode("ascii"))
    status = bytearray()
    while b"\r\n" not in status:
        require(time.monotonic() < deadline and len(status) < 4096, "http-status-unavailable")
        connection.settimeout(max(0.01, deadline - time.monotonic()))
        chunk = connection.recv(min(256, 4096 - len(status)))
        require(chunk, "http-status-unavailable")
        status.extend(chunk)
    # Do not retain arbitrary headers, cookies, bodies or reason phrases.
    match = re.fullmatch(rb"HTTP/1\.[01] ([1-5][0-9]{2})(?: [\x20-\x7e]*)?", status.split(b"\r\n", 1)[0])
    require(match is not None, "http-status-unavailable")
    return int(match[1])


def probe_version(ssl, socket, endpoint, hostname, path, version):
    import ipaddress
    legacy = version in ("TLSv1", "TLSv1_1")
    try:
        context = tls_context(ssl, version, legacy)
    except (AttributeError, ValueError, OSError, NotImplementedError):
        return tls_row(version, "local-unavailable", "local-protocol-unavailable")
    address = ipaddress.ip_address(endpoint["address"])
    require(not address.is_link_local, "unsupported-listener-address")
    if address.is_unspecified:
        address = ipaddress.ip_address("::1" if address.version == 6 else "127.0.0.1")
    deadline = time.monotonic() + 4
    try:
        with socket.socket(socket.AF_INET6 if address.version == 6 else socket.AF_INET, socket.SOCK_STREAM) as raw:
            raw.settimeout(2)
            raw.connect((str(address), endpoint["port"]))
            raw.settimeout(max(0.01, deadline - time.monotonic()))
            with context.wrap_socket(raw, server_hostname=hostname) as connection:
                expected = {"TLSv1": "TLSv1", "TLSv1_1": "TLSv1.1", "TLSv1_2": "TLSv1.2", "TLSv1_3": "TLSv1.3"}
                require(connection.version() == expected[version], "negotiated-protocol-mismatch")
                if legacy:
                    # No HTTP, authentication or other application data is sent.
                    return tls_row(version, "accepted", "legacy-accepted")
                certificate = digest(connection.getpeercert(binary_form=True))
                try:
                    status = head_status(connection, hostname, endpoint["port"], path, deadline)
                    return tls_row(version, "accepted", "identity-verified", certificate, "status", status)
                except (OSError, Refusal):
                    return tls_row(version, "accepted", "identity-verified", certificate, "unavailable")
    except ssl.SSLCertVerificationError:
        return tls_row(version, "certificate-rejected", "certificate-verification-failed")
    except (TimeoutError, socket.timeout):
        return tls_row(version, "inconclusive", "timeout")
    except ssl.SSLError as error:
        reason = getattr(error, "reason", "")
        if reason == "TLSV1_ALERT_PROTOCOL_VERSION":
            return tls_row(version, "protocol-rejected", "server-protocol-alert")
        if reason in ("NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE", "UNSUPPORTED_PROTOCOL"):
            return tls_row(version, "local-unavailable", "local-protocol-unavailable")
        return tls_row(version, "inconclusive", "handshake-failed")
    except OSError:
        return tls_row(version, "inconclusive", "connection-failed")


def connectivity(evidence, request):
    endpoint = request["endpoint"]
    hostname, path = probe_name(request["server_name"]), probe_path(request["path"])
    verify_listener(evidence, endpoint)
    versions = ("TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3")
    try:
        import ssl
        import socket
    except ImportError:
        return {"clientVersion": "unavailable", "rows": [tls_row(v, "local-unavailable", "local-tls-unavailable") for v in versions]}
    rows = []
    for version in versions:
        verify_listener(evidence, endpoint)
        rows.append(probe_version(ssl, socket, endpoint, hostname, path, version))
    verify_listener(evidence, endpoint)
    return {"clientVersion": ssl.OPENSSL_VERSION, "rows": rows}


def main():
    require(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"), "pidfd-python39-required")
    request = json.loads(sys.argv[1])
    mode = request["mode"]
    if mode == "discover":
        result = {"instances": discover()}
    else:
        evidence = request["evidence"]
        verify(evidence)
        verify_scope(evidence)
        result = {"verified": True}
        if mode == "listeners":
            result = {"listeners": owned_listeners(evidence["pid"])[0]}
        elif mode == "connectivity":
            result = connectivity(evidence, request)
        elif mode == "config-test":
            run_nginx(evidence, "-t")
        elif mode == "reload":
            reload_and_verify(evidence)
        elif mode == "health":
            require(workers(evidence["pid"]), "no-serving-workers")
        else:
            require(mode == "verify", "unknown-operation")
        verify(evidence)
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except Refusal as error:
        print(json.dumps({"refused": str(error)}))
        sys.exit(1)
    except Exception:
        # Includes missing tools/permissions, malformed procfs, and OS errors.
        # Do not leak a command, environment, config byte, or exception repr.
        print('{"refused":"runtime-probe-unavailable"}')
        sys.exit(1)
