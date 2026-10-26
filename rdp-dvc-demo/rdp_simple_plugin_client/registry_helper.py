# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Registry helper for RDP AddIn registration.

Supports per-user (HKCU) and machine-wide (HKLM) registration.
"""

import os
import sys
import winreg
from dataclasses import dataclass
from typing import Optional, Tuple


# CLSID must match cpp/dotnet implementations
PLUGIN_CLSID = "D9B80669-C06A-4BD1-9CB1-3B7168C9E3A3"
ADDIN_NAME = "SimpleRdpPlugin"


@dataclass(frozen=True)
class RegPaths:
    clsid_key: str
    localserver32_key: str
    addin_key: str


def _format_clsid_braced(clsid: str) -> str:
    clsid = clsid.strip()
    if clsid.startswith("{") and clsid.endswith("}"):
        return clsid
    return "{" + clsid + "}"


def _get_root(per_user: bool) -> Tuple[int, str]:
    return (winreg.HKEY_CURRENT_USER, "HKCU") if per_user else (winreg.HKEY_LOCAL_MACHINE, "HKLM")


def _build_paths(clsid: str) -> RegPaths:
    clsid_braced = _format_clsid_braced(clsid)

    clsid_key = rf"Software\Classes\CLSID\{clsid_braced}"
    localserver32_key = rf"{clsid_key}\LocalServer32"
    addin_key = rf"Software\Microsoft\Terminal Server Client\Default\AddIns\{ADDIN_NAME}"

    return RegPaths(
        clsid_key=clsid_key,
        localserver32_key=localserver32_key,
        addin_key=addin_key,
    )


def _set_default_value(key_handle, value: str) -> None:
    winreg.SetValueEx(key_handle, "", 0, winreg.REG_SZ, value)


def _delete_tree(root: int, subkey: str) -> None:
    """Recursively delete a key and all subkeys."""
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ | winreg.KEY_WRITE) as h:
            while True:
                try:
                    child = winreg.EnumKey(h, 0)
                except OSError:
                    break
                _delete_tree(root, subkey + "\\" + child)
    except FileNotFoundError:
        return

    winreg.DeleteKey(root, subkey)


def register_addin(
    per_user: bool = True,
    *,
    exe_path: Optional[str] = None,
    addin_display_name: Optional[str] = None,
    verbose: bool = True,
) -> bool:
    """Register COM LocalServer and RDP client AddIn.

    Args:
        per_user: HKCU if True, HKLM if False (admin required for HKLM)
        exe_path: Path to COM LocalServer EXE. Defaults to sys.executable.
        addin_display_name: Optional friendly name for CLSID key.
        verbose: Print progress.

    Returns:
        True if successful.
    """
    root, root_name = _get_root(per_user)
    paths = _build_paths(PLUGIN_CLSID)
    clsid_braced = _format_clsid_braced(PLUGIN_CLSID)

    if exe_path is None:
        exe_path = sys.executable
    exe_path = os.path.abspath(exe_path)

    localserver_cmd = f'"{exe_path}" -Embedding'

    try:
        # CLSID key
        with winreg.CreateKeyEx(root, paths.clsid_key, 0, winreg.KEY_SET_VALUE) as k:
            if addin_display_name:
                _set_default_value(k, addin_display_name)
        if verbose:
            print(f"[{root_name}] Created CLSID key: {paths.clsid_key}")

        # LocalServer32 key
        with winreg.CreateKeyEx(root, paths.localserver32_key, 0, winreg.KEY_SET_VALUE) as k:
            _set_default_value(k, localserver_cmd)
        if verbose:
            print(f"[{root_name}] Created LocalServer32: {localserver_cmd}")

        # AddIn key
        with winreg.CreateKeyEx(root, paths.addin_key, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "Name", 0, winreg.REG_SZ, clsid_braced)
        if verbose:
            print(f"[{root_name}] Created AddIn key: {paths.addin_key} (Name={clsid_braced})")

        return True

    except PermissionError as e:
        print(f"Registration failed: {e}", file=sys.stderr)
        if not per_user:
            print("Tip: run as Administrator for /machine registration.", file=sys.stderr)
        return False

    except Exception as e:
        print(f"Registration failed: {e}", file=sys.stderr)
        return False


def unregister_addin(per_user: bool = True, *, verbose: bool = True) -> bool:
    """Remove AddIn + CLSID registration.

    Returns:
        True if all removals succeeded (or keys didn't exist).
    """
    root, root_name = _get_root(per_user)
    paths = _build_paths(PLUGIN_CLSID)

    ok = True

    try:
        _delete_tree(root, paths.addin_key)
        if verbose:
            print(f"[{root_name}] Removed AddIn key: {paths.addin_key}")
    except Exception as e:
        print(f"Failed to remove AddIn key: {e}", file=sys.stderr)
        ok = False

    try:
        _delete_tree(root, paths.clsid_key)
        if verbose:
            print(f"[{root_name}] Removed CLSID key: {paths.clsid_key}")
    except Exception as e:
        print(f"Failed to remove CLSID key: {e}", file=sys.stderr)
        ok = False

    return ok
