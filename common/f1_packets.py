import struct
from dataclasses import dataclass
from typing import Optional

# F1 23/24/25 Packet Header: 29 bytes (little-endian)
HEADER_FMT = "<HBBBBBQfIIBB"
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # 29 bytes

# CarTelemetryData per car: 60 bytes (little-endian)
CAR_TELEMETRY_FMT = "<HfffBbHBBH4H4B4BH4f4B"
CAR_TELEMETRY_SIZE = struct.calcsize(CAR_TELEMETRY_FMT)  # 60 bytes

PACKET_ID_CAR_TELEMETRY = 6
PACKET_ID_CAR_DAMAGE = 10


@dataclass(slots=True)
class PacketHeader:
    packet_format: int
    game_year: int
    game_major_version: int
    game_minor_version: int
    packet_version: int
    packet_id: int
    session_uid: int
    session_time: float
    frame_identifier: int
    overall_frame_identifier: int
    player_car_index: int
    secondary_player_car_index: int


@dataclass(slots=True)
class PlayerTelemetry:
    session_uid: int
    session_time: float
    frame_id: int
    speed_kph: int
    throttle: float
    steer: float
    brake: float
    gear: int
    engine_rpm: int
    drs: int
    tyre_surface_temps: tuple[int, int, int, int]  # RL, RR, FL, FR
    engine_temp: int


def parse_header(data: bytes) -> Optional[PacketHeader]:
    if len(data) < HEADER_SIZE:
        return None
    fields = struct.unpack_from(HEADER_FMT, data, 0)
    return PacketHeader(*fields)


def parse_player_telemetry(data: bytes) -> Optional[PlayerTelemetry]:
    header = parse_header(data)
    if not header or header.packet_id != PACKET_ID_CAR_TELEMETRY:
        return None

    offset = HEADER_SIZE + (header.player_car_index * CAR_TELEMETRY_SIZE)
    if len(data) < offset + CAR_TELEMETRY_SIZE:
        return None

    unpacked = struct.unpack_from(CAR_TELEMETRY_FMT, data, offset)
    return PlayerTelemetry(
        session_uid=header.session_uid,
        session_time=header.session_time,
        frame_id=header.frame_identifier,
        speed_kph=unpacked[0],
        throttle=unpacked[1],
        steer=unpacked[2],
        brake=unpacked[3],
        gear=unpacked[5],
        engine_rpm=unpacked[6],
        drs=unpacked[7],
        tyre_surface_temps=(unpacked[14], unpacked[15], unpacked[16], unpacked[17]),
        engine_temp=unpacked[22],
    )


def build_synthetic_telemetry_packet(
    frame_id: int,
    speed_kph: int,
    throttle: float,
    brake: float,
    gear: int,
    rpm: int,
    session_time: float,
    session_uid: int = 999999,
    tyre_temps: tuple[int, int, int, int] = (92, 94, 96, 95),
) -> bytes:
    """Builds a valid F1 25 Packet ID 6 binary UDP payload for offline testing."""
    header = struct.pack(
        HEADER_FMT,
        2025, 25, 1, 0, 1,
        PACKET_ID_CAR_TELEMETRY,
        session_uid,
        session_time,
        frame_id,
        frame_id,
        0,   # player_car_index = 0
        255, # no secondary player
    )
    player_car = struct.pack(
        CAR_TELEMETRY_FMT,
        speed_kph, throttle, 0.0, brake, 0, gear, rpm, 1 if speed_kph > 290 else 0,
        min(100, int((rpm / 12500) * 100)), 0,
        450, 455, 510, 515,         # brakes temp
        *tyre_temps,                # surface temps
        *(t + 5 for t in tyre_temps), # inner temps
        104,                        # engine temp
        21.5, 21.5, 23.0, 23.0,     # tyre pressures
        0, 0, 0, 0,                 # asphalt surface
    )
    # Pad remaining 21 cars + 3 trailing bytes (mfdPanelIndex, etc.)
    other_cars = b"\x00" * (CAR_TELEMETRY_SIZE * 21 + 3)
    return header + player_car + other_cars