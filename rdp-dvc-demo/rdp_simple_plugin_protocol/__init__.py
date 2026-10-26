# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""RDP Simple Plugin Protocol Library.

Provides message structures and codec for the simple ping/echo DVC protocol.
"""

from .ping_message import PingMessage
from .ping_message_codec import (
    PingMessageCodec,
    FrameParseStatus,
    DEFAULT_PAYLOAD_SIZE,
    MESSAGE_HEADER_SIZE,
    FRAME_HEADER_SIZE,
    MAX_PAYLOAD_SIZE,
)

__all__ = [
    "PingMessage",
    "PingMessageCodec",
    "FrameParseStatus",
    "DEFAULT_PAYLOAD_SIZE",
    "MESSAGE_HEADER_SIZE",
    "FRAME_HEADER_SIZE",
    "MAX_PAYLOAD_SIZE",
]
