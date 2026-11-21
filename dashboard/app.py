import asyncio
import json
import os
from pathlib import Path
import sqlite3
import time

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

DATA_DIR = Path(os.getenv("DATA_DIR", "data"))
DB_PATH = DATA_DIR / "telemetry.db"
STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(title="F1 Zero-Trust Telemetry Dashboard")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(round((pct / 100.0) * (len(ordered) - 1))))
    return ordered[idx]


def query_snapshot() -> dict:
    if not DB_PATH.exists():
        return {"status": "waiting"}

    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=2.0)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.cursor()

        latest = cur.execute(
            """
            SELECT ts_ns, seq_num, frame_id, speed_kph, throttle, brake,
                   gear, rpm, drs, tyre_temps, latency_ms
            FROM telemetry
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()

        alerts_rows = cur.execute(
            """
            SELECT id, ts_ns, severity, code, source, detail
            FROM siem_events
            ORDER BY id DESC
            LIMIT 30
            """
        ).fetchall()

        total_packets = cur.execute("SELECT COUNT(*) FROM telemetry").fetchone()[0]
        total_alerts = cur.execute("SELECT COUNT(*) FROM siem_events").fetchone()[0]

        if latest is None:
            return {
                "status": "waiting",
                "total_packets": 0,
                "total_alerts": total_alerts,
                "alerts": [dict(r) for r in alerts_rows],
            }

        recent_rows = cur.execute(
            """
            SELECT ts_ns, speed_kph, latency_ms
            FROM telemetry
            ORDER BY id DESC
            LIMIT 300
            """
        ).fetchall()

        latencies = [float(r["latency_ms"]) for r in recent_rows]
        now_ns = time.time_ns()
        cutoff_ns = now_ns - 2_000_000_000
        recent_2s = sum(1 for r in recent_rows if r["ts_ns"] >= cutoff_ns)
        rx_rate = round(recent_2s / 2.0, 1)

        # Last 90 points ordered oldest -> newest for charts
        trace = list(reversed(recent_rows[:90]))
        p99 = round(_percentile(latencies, 99), 3)

        try:
            tyre_temps = json.loads(latest["tyre_temps"])
        except Exception:
            tyre_temps = [0, 0, 0, 0]

        stale = (now_ns - int(latest["ts_ns"])) > 2_500_000_000

        return {
            "status": "idle" if stale else "live",
            "rx_rate": rx_rate,
            "total_packets": total_packets,
            "total_alerts": total_alerts,
            "telemetry": {
                "seq_num": latest["seq_num"],
                "frame_id": latest["frame_id"],
                "speed_kph": latest["speed_kph"],
                "throttle": round(float(latest["throttle"]), 3),
                "brake": round(float(latest["brake"]), 3),
                "gear": latest["gear"],
                "rpm": latest["rpm"],
                "drs": bool(latest["drs"]),
                "tyre_temps": tyre_temps,  # [RL, RR, FL, FR]
                "latency_ms": round(float(latest["latency_ms"]), 3),
            },
            "latency": {
                "p50": round(_percentile(latencies, 50), 3),
                "p95": round(_percentile(latencies, 95), 3),
                "p99": p99,
                "max": round(max(latencies), 3) if latencies else 0.0,
                "sla_pass": p99 < 5.0,
            },
            "trace": {
                "speed": [int(r["speed_kph"]) for r in trace],
                "latency": [round(float(r["latency_ms"]), 3) for r in trace],
            },
            "alerts": [dict(r) for r in alerts_rows],
        }
    except sqlite3.OperationalError:
        return {"status": "waiting"}
    finally:
        conn.close()


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/snapshot")
async def api_snapshot() -> JSONResponse:
    data = await asyncio.to_thread(query_snapshot)
    return JSONResponse(data)


@app.websocket("/ws/live")
async def ws_live(websocket: WebSocket) -> None:
    await websocket.accept()
    try:
        while True:
            snapshot = await asyncio.to_thread(query_snapshot)
            await websocket.send_json(snapshot)
            await asyncio.sleep(0.1)  # 10Hz UI refresh
    except WebSocketDisconnect:
        return
    except Exception:
        return