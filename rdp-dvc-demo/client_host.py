# Development-mode COM LocalServer host.
# Lets COM launch the plugin directly with a plain Python install:
#   LocalServer32 = "python.exe" "<this file>" -Embedding
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rdp_simple_plugin_client.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())
