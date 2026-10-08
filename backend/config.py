"""Environment-backed configuration for the capture backend service."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).with_name(".env"))


def _path_value(value: str) -> Path:
    """Make Windows dotenv values safe when double quotes converted ``\n``."""
    value = value.replace("\r", r"\r").replace("\n", r"\n").replace("\t", r"\t")
    path = Path(value)
    if not path.is_absolute():
        path = Path(__file__).resolve().parent.parent / path
    return path


@dataclass(frozen=True)
class Settings:
    source_mode: str = "none"
    source_path: Path | None = None
    zeek_path: Path | None = None
    suricata_live_path: Path = Path("data/suricata/eve.json")
    zeek_live_path: Path = Path("data/zeek/conn.log")
    interface: str | None = None
    packet_filter: str | None = None
    history_path: Path = Path("data/normalized/events.jsonl")
    redis_url: str | None = None
    redis_stream: str = "nids:raw-events"
    auto_start: bool = False

    @classmethod
    def from_environment(cls) -> "Settings":
        source_path = os.getenv("NIDS_SOURCE_PATH")
        return cls(
            source_mode=os.getenv("NIDS_SOURCE_MODE", "none").lower(),
            source_path=_path_value(source_path) if source_path else None,
            zeek_path=(
                _path_value(os.getenv("NIDS_ZEEK_PATH"))
                if os.getenv("NIDS_ZEEK_PATH")
                else None
            ),
            suricata_live_path=_path_value(
                os.getenv("NIDS_SURICATA_EVE_PATH", "data/suricata/eve.json")
            ),
            zeek_live_path=_path_value(
                os.getenv("NIDS_ZEEK_CONN_PATH", "data/zeek/conn.log")
            ),
            interface=os.getenv("NIDS_INTERFACE"),
            packet_filter=os.getenv("NIDS_PACKET_FILTER"),
            history_path=_path_value(
                os.getenv("NIDS_HISTORY_PATH", "data/normalized/events.jsonl")
            ),
            redis_url=os.getenv("REDIS_URL"),
            redis_stream=os.getenv("NIDS_REDIS_STREAM", "nids:raw-events"),
            auto_start=os.getenv("NIDS_AUTO_START", "false").lower()
            in {"1", "true", "yes"},
        )
