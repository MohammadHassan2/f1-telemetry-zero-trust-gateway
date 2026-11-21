import argparse
import asyncio
import hashlib
import hmac
import os
from pathlib import Path
import socket
import ssl
import struct
import time

from common.f1_packets import build_synthetic_telemetry_packet
from common.security import FRAME_HEADER_FMT, seal_frame

UDP_HOST = os.getenv("UDP_TARGET_HOST", "127.0.0.1")
UDP_PORT = int(os.getenv("UDP_LISTEN_PORT", "20777"))
FACTORY_HOST = os.getenv("FACTORY_HOST", "127.0.0.1")
FACTORY_PORT = int(os.getenv("FACTORY_PORT", "8443"))
FACTORY_SERVER_NAME = os.getenv("FACTORY_SERVER_NAME", "factory-server")
CERTS_DIR = Path(os.getenv("CERTS_DIR", "certs"))
HMAC_SECRET = os.getenv("F1_HMAC_SECRET", "dev-pitwall-secret-change-me").encode()


def send_udp_packets(packets: list[bytes], host: str, port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for pkt in packets:
            sock.sendto(pkt, (host, port))
    finally:
        sock.close()


def attack_spoof_speed() -> str:
    """Injects an impossible 120->465 kph spike to trigger CEILING + DELTA alerts."""
    p1 = build_synthetic_telemetry_packet(1, 120, 0.8, 0.0, 3, 10500, 1.000, session_uid=880001)
    p2 = build_synthetic_telemetry_packet(2, 465, 1.0, 0.0, 8, 12200, 1.016, session_uid=880001)
    send_udp_packets([p1, p2], UDP_HOST, UDP_PORT)
    return "Sent 120->465 kph spike via UDP -> Expect SPOOFED_SPEED_CEILING + SPOOFED_SPEED_DELTA"


def attack_spoof_rpm() -> str:
    """Injects an over-revved 18,500 RPM telemetry frame."""
    pkt = build_synthetic_telemetry_packet(1, 295, 1.0, 0.0, 7, 18500, 2.000, session_uid=880002)
    send_udp_packets([pkt], UDP_HOST, UDP_PORT)
    return "Sent 18,500 RPM packet via UDP -> Expect SPOOFED_RPM"


def attack_udp_replay() -> str:
    """Replays an identical F1 frame_id back-to-back on the trackside LAN."""
    p1 = build_synthetic_telemetry_packet(50, 240, 0.9, 0.0, 6, 11200, 3.000, session_uid=880003)
    send_udp_packets([p1, p1], UDP_HOST, UDP_PORT)
    return "Sent duplicate frame_id=50 via UDP -> Expect UPSTREAM_FRAME_REPLAY"


def attack_drop_frames() -> str:
    """Simulates a 15-frame UDP loss gap on the trackside link."""
    p1 = build_synthetic_telemetry_packet(10, 210, 0.8, 0.0, 5, 10900, 4.000, session_uid=880004)
    p2 = build_synthetic_telemetry_packet(26, 220, 0.8, 0.0, 5, 11100, 4.250, session_uid=880004)
    send_udp_packets([p1, p2], UDP_HOST, UDP_PORT)
    return "Sent frame gap 10->26 via UDP -> Expect DROPPED_FRAMES (15 lost)"


def attack_malformed_udp() -> str:
    """Sends truncated/corrupted UDP payloads to test Edge perimeter filtering."""
    send_udp_packets([b"NOT_F1_DATA", b"\x00\xff\x13\x37", b"A" * 12], UDP_HOST, UDP_PORT)
    return "Sent 3 malformed UDP packets -> Expect Edge Gateway malformed counter +3"


def _build_valid_client_ssl() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=CERTS_DIR / "edge.crt", keyfile=CERTS_DIR / "edge.key")
    ctx.load_verify_locations(cafile=CERTS_DIR / "ca.crt")
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


async def attack_tamper_hmac() -> str:
    """Flips 1 bit inside a sealed payload over mTLS to trigger INVALID_HMAC."""
    ssl_ctx = _build_valid_client_ssl()
    _, writer = await asyncio.open_connection(
        FACTORY_HOST, FACTORY_PORT, ssl=ssl_ctx, server_hostname=FACTORY_SERVER_NAME
    )
    try:
        raw = build_synthetic_telemetry_packet(1, 280, 1.0, 0.0, 7, 11800, 5.0, session_uid=880005)
        sealed = bytearray(seal_frame(HMAC_SECRET, seq_num=1, payload=raw))
        # Flip 1 bit inside the payload bytes (after the 28-byte header)
        sealed[35] ^= 0x01
        writer.write(bytes(sealed))
        await writer.drain()
        await asyncio.sleep(0.15)
        return "Sent 1-bit tampered payload over mTLS -> Expect CRITICAL INVALID_HMAC"
    finally:
        writer.close()
        await writer.wait_closed()


async def attack_seq_replay() -> str:
    """Sends a valid seq=1 frame, then immediately replays the exact wire bytes."""
    ssl_ctx = _build_valid_client_ssl()
    _, writer = await asyncio.open_connection(
        FACTORY_HOST, FACTORY_PORT, ssl=ssl_ctx, server_hostname=FACTORY_SERVER_NAME
    )
    try:
        raw = build_synthetic_telemetry_packet(1, 250, 0.9, 0.0, 6, 11400, 6.0, session_uid=880006)
        sealed = seal_frame(HMAC_SECRET, seq_num=1, payload=raw)
        writer.write(sealed)
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.write(sealed)  # Replay exact frame
        await writer.drain()
        await asyncio.sleep(0.15)
        return "Replayed identical sealed frame (seq=1) -> Expect CRITICAL REPLAY_DETECTED"
    finally:
        writer.close()
        await writer.wait_closed()


async def attack_stale_timestamp() -> str:
    """Crafts a validly signed frame with a timestamp 15 seconds in the past."""
    ssl_ctx = _build_valid_client_ssl()
    _, writer = await asyncio.open_connection(
        FACTORY_HOST, FACTORY_PORT, ssl=ssl_ctx, server_hostname=FACTORY_SERVER_NAME
    )
    try:
        raw = build_synthetic_telemetry_packet(1, 260, 0.9, 0.0, 6, 11500, 7.0, session_uid=880007)
        stale_wall_ns = time.time_ns() - 15_000_000_000
        mono_ns = time.perf_counter_ns()
        header = struct.pack(FRAME_HEADER_FMT, 1, stale_wall_ns, mono_ns, len(raw))
        body = header + raw
        mac = hmac.new(HMAC_SECRET, body, hashlib.sha256).digest()
        writer.write(body + mac)
        await writer.drain()
        await asyncio.sleep(0.15)
        return "Sent validly signed frame with -15s timestamp -> Expect CRITICAL STALE_TIMESTAMP"
    finally:
        writer.close()
        await writer.wait_closed()


async def attack_rogue_mtls() -> str:
    """Attempts to connect to Factory server WITHOUT a CA-signed edge client certificate."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=CERTS_DIR / "ca.crt")
    ctx.verify_mode = ssl.CERT_REQUIRED
    # Intentionally omit load_cert_chain()

    try:
        reader, writer = await asyncio.open_connection(
            FACTORY_HOST, FACTORY_PORT, ssl=ctx, server_hostname=FACTORY_SERVER_NAME
        )
        try:
            # In TLS 1.3, server certificate_required alert arrives post-handshake on first read/write
            writer.write(b"\x00")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(16), timeout=1.0)
            if data == b"":
                return "BLOCKED: Rogue client without cert was disconnected by mTLS server."
            return "WARNING: Rogue client unexpectedly received data!"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except (ssl.SSLError, ConnectionError, OSError) as exc:
        return f"BLOCKED: Rogue client rejected by mTLS ({type(exc).__name__})."


ATTACKS = {
    "spoof-speed": ("UDP", attack_spoof_speed),
    "spoof-rpm": ("UDP", attack_spoof_rpm),
    "udp-replay": ("UDP", attack_udp_replay),
    "drop-frames": ("UDP", attack_drop_frames),
    "malformed": ("UDP", attack_malformed_udp),
    "tamper-hmac": ("mTLS", attack_tamper_hmac),
    "seq-replay": ("mTLS", attack_seq_replay),
    "stale-ts": ("mTLS", attack_stale_timestamp),
    "rogue-mtls": ("mTLS", attack_rogue_mtls),
}


async def run_selected(selection: list[str]) -> None:
    print(f"[ATTACK] Running {len(selection)} adversarial test(s)...\n")
    for name in selection:
        plane, fn = ATTACKS[name]
        if asyncio.iscoroutinefunction(fn):
            result = await fn()
        else:
            result = fn()
        print(f"  [{plane:4}] {name:<13} | {result}")
        await asyncio.sleep(0.2)
    print("\n[ATTACK] Suite complete. Inspect Factory Server console & logs\\siem_events.ndjson.")


def main() -> None:
    parser = argparse.ArgumentParser(description="F1 Zero-Trust Telemetry Adversarial Attack Injector")
    parser.add_argument(
        "--attack",
        choices=["all", *ATTACKS.keys()],
        default="all",
        help="Attack vector to execute (default: all)",
    )
    args = parser.parse_args()
    selection = list(ATTACKS.keys()) if args.attack == "all" else [args.attack]
    asyncio.run(run_selected(selection))


if __name__ == "__main__":
    main()