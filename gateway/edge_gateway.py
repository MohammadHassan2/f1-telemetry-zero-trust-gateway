import asyncio
import os
from pathlib import Path
import socket
import ssl
import time

from common.f1_packets import parse_header
from common.security import seal_frame

UDP_HOST = os.getenv("UDP_LISTEN_HOST", "0.0.0.0")
UDP_PORT = int(os.getenv("UDP_LISTEN_PORT", "20777"))
FACTORY_HOST = os.getenv("FACTORY_HOST", "127.0.0.1")
FACTORY_PORT = int(os.getenv("FACTORY_PORT", "8443"))
FACTORY_SERVER_NAME = os.getenv("FACTORY_SERVER_NAME", "factory-server")
CERTS_DIR = Path(os.getenv("CERTS_DIR", "certs"))
HMAC_SECRET = os.getenv("F1_HMAC_SECRET", "dev-pitwall-secret-change-me").encode()


class EdgeGatewayState:
    def __init__(self) -> None:
        self.queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=256)
        self.seq_num = 0
        self.rx_window = 0
        self.fwd_window = 0
        self.dropped_malformed = 0
        self.dropped_backpressure = 0
        self.sign_ns_total = 0
        self.sign_count = 0
        self.connected = False


class F1UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, state: EdgeGatewayState) -> None:
        self.state = state

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        # Edge perimeter filter: drop non-F1 garbage before signing
        if parse_header(data) is None:
            self.state.dropped_malformed += 1
            return

        self.state.rx_window += 1
        self.state.seq_num += 1

        t0 = time.perf_counter_ns()
        sealed = seal_frame(HMAC_SECRET, self.state.seq_num, data)
        self.state.sign_ns_total += time.perf_counter_ns() - t0
        self.state.sign_count += 1

        # Real-time telemetry rule: drop oldest on backpressure, never delay live frames
        if self.state.queue.full():
            try:
                self.state.queue.get_nowait()
                self.state.dropped_backpressure += 1
            except asyncio.QueueEmpty:
                pass
        self.state.queue.put_nowait(sealed)


def build_client_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=CERTS_DIR / "edge.crt", keyfile=CERTS_DIR / "edge.key")
    ctx.load_verify_locations(cafile=CERTS_DIR / "ca.crt")
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


async def mtls_forwarder(state: EdgeGatewayState) -> None:
    ssl_ctx = build_client_ssl_context()
    while True:
        writer = None
        try:
            _, writer = await asyncio.open_connection(
                FACTORY_HOST,
                FACTORY_PORT,
                ssl=ssl_ctx,
                server_hostname=FACTORY_SERVER_NAME,
            )
            sock = writer.get_extra_info("socket")
            if sock is not None:
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass

            state.connected = True
            print(f"[EDGE] Persistent mTLS tunnel established -> {FACTORY_HOST}:{FACTORY_PORT}")

            while True:
                frame = await state.queue.get()
                writer.write(frame)
                await writer.drain()
                state.fwd_window += 1

        except (ConnectionError, OSError, ssl.SSLError) as exc:
            state.connected = False
            print(f"[EDGE] Tunnel down ({exc}). Retrying in 1.5s...")
            await asyncio.sleep(1.5)
        finally:
            state.connected = False
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass


async def stats_reporter(state: EdgeGatewayState) -> None:
    while True:
        await asyncio.sleep(1.0)
        avg_sign_ms = (
            (state.sign_ns_total / state.sign_count) / 1_000_000.0 if state.sign_count else 0.0
        )
        status = "CONNECTED" if state.connected else "RECONNECTING"
        print(
            f"[EDGE] udp_rx={state.rx_window:>3}/s | fwd={state.fwd_window:>3}/s | "
            f"hmac_sign={avg_sign_ms:.3f}ms | malformed={state.dropped_malformed} | "
            f"tunnel={status}"
        )
        state.rx_window = 0
        state.fwd_window = 0
        state.sign_ns_total = 0
        state.sign_count = 0


async def main() -> None:
    loop = asyncio.get_running_loop()
    state = EdgeGatewayState()

    transport, _ = await loop.create_datagram_endpoint(
        lambda: F1UDPProtocol(state),
        local_addr=(UDP_HOST, UDP_PORT),
    )
    print(f"[EDGE] Listening for F1 25 UDP telemetry on {UDP_HOST}:{UDP_PORT}")

    forwarder_task = asyncio.create_task(mtls_forwarder(state))
    stats_task = asyncio.create_task(stats_reporter(state))
    try:
        await asyncio.gather(forwarder_task, stats_task)
    finally:
        transport.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[EDGE] Shutdown complete.")