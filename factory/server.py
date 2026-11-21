import asyncio
from collections import deque
import json
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import struct
import time

from common.f1_packets import parse_player_telemetry
from common.security import (
    AntiReplayVerifier,
    FRAME_HEADER_FMT,
    FRAME_HEADER_SIZE,
    HMAC_SIZE,
    SecurityViolation,
)
from factory.anomaly import TelemetryAnomalyDetector

LISTEN_HOST = os.getenv("FACTORY_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("FACTORY_PORT", "8443"))
CERTS_DIR = Path(os.getenv("CERTS_DIR", "certs"))
DATA_DIR = Path(os.getenv("DATA_DIR", "data"))
LOGS_DIR = Path(os.getenv("LOGS_DIR", "logs"))
HMAC_SECRET = os.getenv("F1_HMAC_SECRET", "dev-pitwall-secret-change-me").encode()
MAX_PAYLOAD_SIZE = 4096  # F1 UDP packets are < 1.5KB; blocks length-prefix DoS


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(round((pct / 100.0) * (len(ordered) - 1))))
    return ordered[idx]


def init_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_ns INTEGER NOT NULL,
            seq_num INTEGER NOT NULL,
            frame_id INTEGER NOT NULL,
            speed_kph INTEGER NOT NULL,
            throttle REAL NOT NULL,
            brake REAL NOT NULL,
            gear INTEGER NOT NULL,
            rpm INTEGER NOT NULL,
            drs INTEGER NOT NULL,
            tyre_temps TEXT NOT NULL,
            latency_ms REAL NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS siem_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_ns INTEGER NOT NULL,
            severity TEXT NOT NULL,
            code TEXT NOT NULL,
            source TEXT NOT NULL,
            detail TEXT NOT NULL
        )
        """
    )
    conn.commit()
    return conn


class FactoryServer:
    def __init__(self) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        self.db_conn = init_db(DATA_DIR / "telemetry.db")
        self.siem_path = LOGS_DIR / "siem_events.ndjson"

        self.db_queue: asyncio.Queue = asyncio.Queue(maxsize=4096)
        self.latencies_ms: deque[float] = deque(maxlen=600)
        self.rx_window = 0
        self.total_rx = 0
        self.total_alerts = 0
        self.last_speed = 0
        self.last_gear = 0
        self.last_rpm = 0

    def _build_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(certfile=CERTS_DIR / "factory.crt", keyfile=CERTS_DIR / "factory.key")
        ctx.load_verify_locations(cafile=CERTS_DIR / "ca.crt")
        ctx.verify_mode = ssl.CERT_REQUIRED  # Mutual TLS enforcement
        return ctx

    def record_siem(self, severity: str, code: str, source: str, detail: str) -> None:
        ts_ns = time.time_ns()
        self.total_alerts += 1
        entry = {
            "ts_ns": ts_ns,
            "severity": severity,
            "code": code,
            "source": source,
            "detail": detail,
        }
        with self.siem_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        try:
            self.db_queue.put_nowait(("siem", (ts_ns, severity, code, source, detail)))
        except asyncio.QueueFull:
            pass
        print(f"[SIEM][{severity}] {code} ({source}): {detail}")

    async def db_flusher(self) -> None:
        """Flushes batched telemetry & SIEM records every 250ms off the hot network path."""
        while True:
            await asyncio.sleep(0.25)
            telem_batch = []
            siem_batch = []
            while not self.db_queue.empty():
                kind, row = self.db_queue.get_nowait()
                if kind == "telemetry":
                    telem_batch.append(row)
                else:
                    siem_batch.append(row)

            if telem_batch:
                self.db_conn.executemany(
                    """
                    INSERT INTO telemetry
                    (ts_ns, seq_num, frame_id, speed_kph, throttle, brake, gear, rpm, drs, tyre_temps, latency_ms)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    telem_batch,
                )
            if siem_batch:
                self.db_conn.executemany(
                    "INSERT INTO siem_events (ts_ns, severity, code, source, detail) VALUES (?, ?, ?, ?, ?)",
                    siem_batch,
                )
            if telem_batch or siem_batch:
                self.db_conn.commit()

    async def stats_reporter(self) -> None:
        while True:
            await asyncio.sleep(1.0)
            vals = list(self.latencies_ms)
            p50 = percentile(vals, 50)
            p95 = percentile(vals, 95)
            p99 = percentile(vals, 99)
            sla_tag = "PASS" if p99 < 5.0 else "SLA_BREACH"
            print(
                f"[FACTORY] rx={self.rx_window:>3}/s | total={self.total_rx:<6} | "
                f"overhead p50={p50:.2f}ms p95={p95:.2f}ms p99={p99:.2f}ms [{sla_tag}] | "
                f"car={self.last_speed:>3}kph G{self.last_gear} {self.last_rpm:>5}rpm | "
                f"alerts={self.total_alerts}"
            )
            self.rx_window = 0

    async def handle_edge_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        sock = writer.get_extra_info("socket")
        if sock is not None:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass

        peer = writer.get_extra_info("peername")
        cert = writer.get_extra_info("peercert") or {}
        cn = dict(x[0] for x in cert.get("subject", ())).get("commonName", "unknown-edge")
        source_id = f"{cn}@{peer[0]}" if peer else cn
        print(f"[FACTORY] Authenticated mTLS edge connected: {source_id}")

        verifier = AntiReplayVerifier(HMAC_SECRET)
        detector = TelemetryAnomalyDetector()

        try:
            while True:
                header_bytes = await reader.readexactly(FRAME_HEADER_SIZE)
                _, _, _, payload_len = struct.unpack(FRAME_HEADER_FMT, header_bytes)

                if payload_len == 0 or payload_len > MAX_PAYLOAD_SIZE:
                    self.record_siem(
                        "CRITICAL",
                        "MALFORMED_FRAME_LEN",
                        source_id,
                        f"Rejected frame with invalid payload length {payload_len}.",
                    )
                    break

                payload = await reader.readexactly(payload_len)
                received_mac = await reader.readexactly(HMAC_SIZE)

                try:
                    verified = verifier.verify(header_bytes, payload, received_mac)
                except SecurityViolation as exc:
                    self.record_siem("CRITICAL", exc.code, source_id, exc.detail)
                    continue

                # Measure end-to-end gateway->factory overhead (same-host monotonic, cross-host wall fallback)
                mono_diff_ns = time.perf_counter_ns() - verified.mono_ts_ns
                if 0 <= mono_diff_ns < 5_000_000_000:
                    latency_ms = mono_diff_ns / 1_000_000.0
                else:
                    latency_ms = max(0.0, (time.time_ns() - verified.wall_ts_ns) / 1_000_000.0)

                self.latencies_ms.append(latency_ms)
                self.rx_window += 1
                self.total_rx += 1

                if latency_ms > 5.0:
                    self.record_siem(
                        "WARNING",
                        "LATENCY_SLA_BREACH",
                        source_id,
                        f"Seq {verified.seq_num} exceeded 5ms target ({latency_ms:.2f}ms).",
                    )

                telemetry = parse_player_telemetry(verified.payload)
                if telemetry is None:
                    continue

                self.last_speed = telemetry.speed_kph
                self.last_gear = telemetry.gear
                self.last_rpm = telemetry.engine_rpm

                for anomaly in detector.inspect(telemetry):
                    self.record_siem(anomaly.severity, anomaly.code, source_id, anomaly.detail)

                try:
                    self.db_queue.put_nowait(
                        (
                            "telemetry",
                            (
                                time.time_ns(),
                                verified.seq_num,
                                telemetry.frame_id,
                                telemetry.speed_kph,
                                telemetry.throttle,
                                telemetry.brake,
                                telemetry.gear,
                                telemetry.engine_rpm,
                                telemetry.drs,
                                json.dumps(telemetry.tyre_surface_temps),
                                latency_ms,
                            ),
                        )
                    )
                except asyncio.QueueFull:
                    pass

        except asyncio.IncompleteReadError:
            print(f"[FACTORY] Edge disconnected cleanly: {source_id}")
        except Exception as exc:
            print(f"[FACTORY] Connection error ({source_id}): {exc}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def run(self) -> None:
        ssl_ctx = self._build_ssl_context()
        server = await asyncio.start_server(
            self.handle_edge_client, LISTEN_HOST, LISTEN_PORT, ssl=ssl_ctx
        )
        print(f"[FACTORY] Listening on mTLS {LISTEN_HOST}:{LISTEN_PORT} (TLS 1.3 required)")
        flusher_task = asyncio.create_task(self.db_flusher())
        stats_task = asyncio.create_task(self.stats_reporter())
        try:
            async with server:
                await server.serve_forever()
        finally:
            flusher_task.cancel()
            stats_task.cancel()
            self.db_conn.close()


if __name__ == "__main__":
    try:
        asyncio.run(FactoryServer().run())
    except KeyboardInterrupt:
        print("\n[FACTORY] Shutdown complete.")