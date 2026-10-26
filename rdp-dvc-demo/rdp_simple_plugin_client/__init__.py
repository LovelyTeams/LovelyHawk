# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""RDP Simple Plugin Client.

Client-side COM LocalServer plugin that runs alongside the RDP client.
"""

from .simple_plugin import SimplePlugin

__all__ = ["SimplePlugin"]
