import hashlib
import hmac
import struct
import time
from dataclasses import dataclass

# 8B uint64 seq, 8B uint64 wall_ts_ns, 8B uint64 mono_ts_ns, 4B uint32 payload_len
FRAME_HEADER_FMT = "!QQQI"
FRAME_HEADER_SIZE = struct.calcsize(FRAME_HEADER_FMT)  # 28 bytes
HMAC_SIZE = 32


class SecurityViolation(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(slots=True)
class VerifiedFrame:
    seq_num: int
    wall_ts_ns: int
    mono_ts_ns: int
    payload: bytes


def seal_frame(secret_key: bytes, seq_num: int, payload: bytes) -> bytes:
    """Wraps a raw F1 UDP packet with sequence, timestamps, and HMAC-SHA256."""
    wall_ts_ns = time.time_ns()
    mono_ts_ns = time.perf_counter_ns()
    header = struct.pack(FRAME_HEADER_FMT, seq_num, wall_ts_ns, mono_ts_ns, len(payload))
    body = header + payload
    mac = hmac.new(secret_key, body, hashlib.sha256).digest()
    return body + mac


class AntiReplayVerifier:
    """Verifies HMAC-SHA256, timestamp freshness, and monotonic sequence numbers."""

    def __init__(self, secret_key: bytes, max_skew_ms: float = 2000.0):
        self.secret_key = secret_key
        self.max_skew_ns = int(max_skew_ms * 1_000_000)
        self.highest_seq = 0

    def verify(self, header_bytes: bytes, payload: bytes, received_mac: bytes) -> VerifiedFrame:
        # 1. Constant-time HMAC integrity verification
        expected_mac = hmac.new(self.secret_key, header_bytes + payload, hashlib.sha256).digest()
        if not hmac.compare_digest(expected_mac, received_mac):
            raise SecurityViolation("INVALID_HMAC", "Cryptographic integrity check failed (tampered packet).")

        seq_num, wall_ts_ns, mono_ts_ns, _ = struct.unpack(FRAME_HEADER_FMT, header_bytes)

        # 2. Timestamp freshness check (blocks delayed replays)
        now_ns = time.time_ns()
        if abs(now_ns - wall_ts_ns) > self.max_skew_ns:
            raise SecurityViolation(
                "STALE_TIMESTAMP",
                f"Packet timestamp drift exceeded {self.max_skew_ns / 1e6:.0f}ms window.",
            )

        # 3. Monotonic sequence check (blocks immediate replays & out-of-order injection)
        if seq_num <= self.highest_seq:
            raise SecurityViolation(
                "REPLAY_DETECTED",
                f"Replay/duplicate sequence detected: got {seq_num}, highest seen {self.highest_seq}.",
            )

        self.highest_seq = seq_num
        return VerifiedFrame(seq_num=seq_num, wall_ts_ns=wall_ts_ns, mono_ts_ns=mono_ts_ns, payload=payload)