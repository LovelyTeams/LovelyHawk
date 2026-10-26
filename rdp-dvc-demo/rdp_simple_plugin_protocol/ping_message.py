# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Simple ping message structure.

Wire format (little-endian):
- sequenceNumber: uint32 (4 bytes)
- utcTicks: int64 (8 bytes)
- payload: variable length byte array
"""

from __future__ import annotations

from dataclasses import dataclass

# Wire type ranges
UINT32_MAX = 0xFFFFFFFF
INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1


@dataclass(frozen=True, slots=True)
class PingMessage:
    """Simple ping message for DVC communication.
    
    Immutable dataclass with slot optimization for cheaper instances.
    
    Attributes:
        sequence_number: Sequence number for tracking ping/pong pairs (uint32).
        utc_ticks: UTC timestamp in 100-nanosecond ticks (int64, Windows FILETIME).
        payload: Payload data (deterministic pattern for testing).
    """
    sequence_number: int = 0
    utc_ticks: int = 0
    payload: bytes = b""
    
    def __post_init__(self) -> None:
        """Validates wire type ranges after initialization."""
        if not (0 <= self.sequence_number <= UINT32_MAX):
            raise ValueError(f"sequence_number {self.sequence_number} out of uint32 range [0, {UINT32_MAX}]")
        if not (INT64_MIN <= self.utc_ticks <= INT64_MAX):
            raise ValueError(f"utc_ticks {self.utc_ticks} out of int64 range [{INT64_MIN}, {INT64_MAX}]")
    
    def __str__(self) -> str:
        """Human-readable string for logging."""
        return f"PingMessage[Seq={self.sequence_number}, Ticks={self.utc_ticks}, PayloadSize={len(self.payload)}]"
