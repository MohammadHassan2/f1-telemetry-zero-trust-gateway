from dataclasses import dataclass, asdict
import time
from typing import Optional

from common.f1_packets import PlayerTelemetry


@dataclass(slots=True)
class AnomalyEvent:
    timestamp_ns: int
    severity: str       # WARNING | HIGH | CRITICAL
    code: str
    frame_id: int
    detail: str
    speed_kph: int

    def to_dict(self) -> dict:
        return asdict(self)


class TelemetryAnomalyDetector:
    """Validates decoded F1 telemetry against motorsport physics and frame continuity."""

    MAX_VALID_SPEED_KPH = 380      # Above realistic F1 slipstream ceiling
    MAX_VALID_ACCEL_MPS2 = 85.0    # ~8.6G physical ceiling (braking peaks ~6G)
    MAX_VALID_RPM = 15500          # Modern F1 PU ceiling
    MAX_VALID_TYRE_TEMP_C = 165

    def __init__(self) -> None:
        self.last_session_uid: Optional[int] = None
        self.last_frame_id: Optional[int] = None
        self.last_speed_kph: Optional[int] = None
        self.last_session_time: Optional[float] = None
        self.total_dropped_frames: int = 0

    def _reset_session(self, session_uid: int) -> None:
        self.last_session_uid = session_uid
        self.last_frame_id = None
        self.last_speed_kph = None
        self.last_session_time = None

    def inspect(self, pkt: PlayerTelemetry) -> list[AnomalyEvent]:
        now_ns = time.time_ns()
        events: list[AnomalyEvent] = []

        if self.last_session_uid is not None and pkt.session_uid != self.last_session_uid:
            self._reset_session(pkt.session_uid)
        self.last_session_uid = pkt.session_uid

        # 1. Frame continuity & upstream UDP replay check
        if self.last_frame_id is not None:
            gap = pkt.frame_id - self.last_frame_id
            if gap > 1:
                dropped = gap - 1
                self.total_dropped_frames += dropped
                events.append(
                    AnomalyEvent(
                        timestamp_ns=now_ns,
                        severity="WARNING",
                        code="DROPPED_FRAMES",
                        frame_id=pkt.frame_id,
                        detail=f"Detected {dropped} dropped F1 frame(s) ({self.last_frame_id} -> {pkt.frame_id}).",
                        speed_kph=pkt.speed_kph,
                    )
                )
            elif gap <= 0:
                events.append(
                    AnomalyEvent(
                        timestamp_ns=now_ns,
                        severity="HIGH",
                        code="UPSTREAM_FRAME_REPLAY",
                        frame_id=pkt.frame_id,
                        detail=f"Duplicate/out-of-order F1 frame_id {pkt.frame_id} (last {self.last_frame_id}).",
                        speed_kph=pkt.speed_kph,
                    )
                )

        # 2. Absolute speed ceiling check (speed spoofing)
        if pkt.speed_kph > self.MAX_VALID_SPEED_KPH:
            events.append(
                AnomalyEvent(
                    timestamp_ns=now_ns,
                    severity="CRITICAL",
                    code="SPOOFED_SPEED_CEILING",
                    frame_id=pkt.frame_id,
                    detail=f"Impossible speed {pkt.speed_kph} kph (ceiling {self.MAX_VALID_SPEED_KPH} kph).",
                    speed_kph=pkt.speed_kph,
                )
            )

        # 3. Physics delta check (sudden spoofed speed jump)
        if self.last_speed_kph is not None and self.last_session_time is not None:
            dt = pkt.session_time - self.last_session_time
            delta_kph = abs(pkt.speed_kph - self.last_speed_kph)
            if 0.0 < dt <= 0.5 and delta_kph > 25:
                accel_mps2 = (delta_kph / 3.6) / dt
                if accel_mps2 > self.MAX_VALID_ACCEL_MPS2:
                    events.append(
                        AnomalyEvent(
                            timestamp_ns=now_ns,
                            severity="CRITICAL",
                            code="SPOOFED_SPEED_DELTA",
                            frame_id=pkt.frame_id,
                            detail=(
                                f"Impossible speed jump {self.last_speed_kph}->{pkt.speed_kph} kph "
                                f"in {dt*1000:.1f}ms ({accel_mps2/9.81:.1f}G)."
                            ),
                            speed_kph=pkt.speed_kph,
                        )
                    )

        # 4. Power unit & tyre bounds check
        if pkt.engine_rpm > self.MAX_VALID_RPM:
            events.append(
                AnomalyEvent(
                    timestamp_ns=now_ns,
                    severity="HIGH",
                    code="SPOOFED_RPM",
                    frame_id=pkt.frame_id,
                    detail=f"Engine RPM {pkt.engine_rpm} exceeded {self.MAX_VALID_RPM} limit.",
                    speed_kph=pkt.speed_kph,
                )
            )

        if any(t > self.MAX_VALID_TYRE_TEMP_C for t in pkt.tyre_surface_temps):
            events.append(
                AnomalyEvent(
                    timestamp_ns=now_ns,
                    severity="WARNING",
                    code="TYRE_TEMP_SPIKE",
                    frame_id=pkt.frame_id,
                    detail=f"Abnormal tyre surface temps: {pkt.tyre_surface_temps} C.",
                    speed_kph=pkt.speed_kph,
                )
            )

        # Only update baseline state if the frame wasn't a spoofed speed ceiling outlier
        if pkt.speed_kph <= self.MAX_VALID_SPEED_KPH and (
            self.last_frame_id is None or pkt.frame_id > self.last_frame_id
        ):
            self.last_frame_id = pkt.frame_id
            self.last_speed_kph = pkt.speed_kph
            self.last_session_time = pkt.session_time

        return events