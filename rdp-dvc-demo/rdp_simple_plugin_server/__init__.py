# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""RDP Simple Plugin Server.

Server-side application that runs inside RDP sessions.
"""

from .simple_server import SimpleServer
from .dvc_reassembler import DvcReassembler

__all__ = ["SimpleServer", "DvcReassembler"]
