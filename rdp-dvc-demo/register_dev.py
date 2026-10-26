# Development-mode registration for the Python DVC client plugin.
#
# The stock `python -m rdp_simple_plugin_client /register` writes
#   LocalServer32 = "python.exe" -Embedding
# which does not load the plugin. This script writes the full command line:
#   LocalServer32 = "python.exe" "<demo dir>\client_host.py" -Embedding
#
# Usage:
#   python register_dev.py            # register (per-user, no admin)
#   python register_dev.py --unregister
import os
import sys
import winreg

CLSID = "{D9B80669-C06A-4BD1-9CB1-3B7168C9E3A3}"
ADDIN_KEY = r"Software\Microsoft\Terminal Server Client\Default\AddIns\SimpleRdpPlugin"
CLSID_KEY = rf"Software\Classes\CLSID\{CLSID}"

HERE = os.path.dirname(os.path.abspath(__file__))
HOST_SCRIPT = os.path.join(HERE, "client_host.py")
LOCALSERVER_CMD = f'"{sys.executable}" "{HOST_SCRIPT}" -Embedding'


def delete_tree(root, subkey):
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ | winreg.KEY_WRITE) as h:
            while True:
                try:
                    child = winreg.EnumKey(h, 0)
                except OSError:
                    break
                delete_tree(root, subkey + "\\" + child)
    except FileNotFoundError:
        return
    winreg.DeleteKey(root, subkey)


def register():
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, CLSID_KEY, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, "", 0, winreg.REG_SZ, "Simple RDP DVC Plugin (Python dev)")
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, CLSID_KEY + r"\LocalServer32", 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, "", 0, winreg.REG_SZ, LOCALSERVER_CMD)
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, ADDIN_KEY, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, "Name", 0, winreg.REG_SZ, CLSID)
    print("Registered (HKCU):")
    print(f"  {CLSID_KEY}\\LocalServer32 = {LOCALSERVER_CMD}")
    print(f"  {ADDIN_KEY} Name = {CLSID}")


def unregister():
    delete_tree(winreg.HKEY_CURRENT_USER, ADDIN_KEY)
    delete_tree(winreg.HKEY_CURRENT_USER, CLSID_KEY)
    print("Unregistered.")


if __name__ == "__main__":
    if "--unregister" in sys.argv or "/unregister" in sys.argv:
        unregister()
    else:
        register()
