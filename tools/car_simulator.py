import argparse
import math
import socket
import time

from common.f1_packets import build_synthetic_telemetry_packet


def lap_physics_profile(lap_t: float) -> tuple[int, float, float, int, int, tuple[int, int, int, int]]:
    """Generates smooth, realistic F1 telemetry over a 20-second synthetic sector loop."""
    phase = lap_t % 20.0

    if phase < 7.0:
        # Main straight acceleration: 110 -> 335 kph
        progress = phase / 7.0
        speed = 110.0 + 225.0 * (1.0 - (1.0 - progress) ** 1.8)
        throttle, brake = 1.0, 0.0
    elif phase < 9.2:
        # Heavy braking zone into Turn 1: 335 -> 85 kph (~5.5G peak)
        progress = (phase - 7.0) / 2.2
        speed = 335.0 - 250.0 * progress
        throttle, brake = 0.0, 1.0 - 0.35 * progress
    elif phase < 13.5:
        # Technical sweepers: 85 -> 215 kph with mid-corner modulation
        progress = (phase - 9.2) / 4.3
        speed = 85.0 + 130.0 * progress + 12.0 * math.sin(progress * math.pi * 2.0)
        throttle, brake = 0.78, 0.0
    elif phase < 15.2:
        # Chicane braking: 215 -> 115 kph
        progress = (phase - 13.5) / 1.7
        speed = 215.0 - 100.0 * progress
        throttle, brake = 0.0, 0.85
    else:
        # Exit onto start/finish straight: 115 -> 110..260..110 loop transition
        progress = (phase - 15.2) / 4.8
        speed = 115.0 + 145.0 * math.sin(progress * math.pi)
        throttle = 0.95 if progress < 0.55 else 0.15
        brake = 0.0 if progress < 0.65 else 0.70

    speed_kph = max(60, min(350, int(round(speed))))

    # Realistic F1 8-speed gear mapping
    gear_thresholds = [85, 125, 165, 205, 245, 285, 315, 400]
    gear = 1
    for idx, limit in enumerate(gear_thresholds, start=1):
        if speed_kph <= limit:
            gear = idx
            break

    low = 0 if gear == 1 else gear_thresholds[gear - 2]
    high = gear_thresholds[gear - 1]
    gear_ratio = max(0.0, min(1.0, (speed_kph - low) / max(1, high - low)))
    rpm = int(9600 + gear_ratio * 2600)

    # Gradual tyre thermal oscillation (90-108 C)
    base_temp = int(95 + 6 * math.sin(lap_t * 0.4))
    tyre_temps = (base_temp - 1, base_temp, base_temp + 3, base_temp + 2)

    return speed_kph, throttle, brake, gear, rpm, tyre_temps


def main() -> None:
    parser = argparse.ArgumentParser(description="60Hz Synthetic EA F1 25 UDP Telemetry Emitter")
    parser.add_argument("--host", default="127.0.0.1", help="Edge gateway IP (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=20777, help="Edge gateway UDP port (default: 20777)")
    parser.add_argument("--hz", type=float, default=60.0, help="Packet send frequency (default: 60Hz)")
    parser.add_argument("--duration", type=float, default=0.0, help="Stop after N seconds (0 = infinite)")
    parser.add_argument("--session-uid", type=int, default=999999, help="F1 session UID")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    interval = 1.0 / args.hz
    start_mono = time.perf_counter()
    next_tick = start_mono
    frame_id = 1
    sent_window = 0
    last_report = start_mono

    print(f"[SIM] Streaming synthetic F1 25 telemetry @ {args.hz:.0f}Hz -> {args.host}:{args.port}")

    try:
        while True:
            now = time.perf_counter()
            elapsed = now - start_mono
            if args.duration > 0 and elapsed >= args.duration:
                break

            speed, throttle, brake, gear, rpm, tyres = lap_physics_profile(elapsed)
            pkt = build_synthetic_telemetry_packet(
                frame_id=frame_id,
                speed_kph=speed,
                throttle=throttle,
                brake=brake,
                gear=gear,
                rpm=rpm,
                session_time=elapsed,
                session_uid=args.session_uid,
                tyre_temps=tyres,
            )
            sock.sendto(pkt, (args.host, args.port))
            frame_id += 1
            sent_window += 1

            if now - last_report >= 1.0:
                print(
                    f"[SIM] tx={sent_window:>3}/s | frame={frame_id:<6} | "
                    f"{speed:>3} kph | G{gear} | {rpm:>5} rpm | thr={throttle:.2f} brk={brake:.2f}"
                )
                sent_window = 0
                last_report = now

            next_tick += interval
            sleep_for = next_tick - time.perf_counter()
            if sleep_for > 0:
                time.sleep(sleep_for)
            else:
                # Re-sync after OS scheduler hiccup instead of bursting
                next_tick = time.perf_counter()
    except KeyboardInterrupt:
        print("\n[SIM] Stopped.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()