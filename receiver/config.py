import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    TCP_HOST: str = os.getenv("TCP_HOST", "0.0.0.0")
    TCP_PORT: int = int(os.getenv("TCP_PORT", "9100"))
    # "ASCII" or "HEX"
    DATA_FORMAT: str = os.getenv("DATA_FORMAT", "ASCII")
    DEVICE_ID: str = os.getenv("DEVICE_ID", "keyence-01")
    API_URL: str = os.getenv("API_URL", "http://localhost:3000/api/scans")
    API_KEY: str = os.getenv("API_KEY", "")
    BUFFER_DB_PATH: str = os.getenv("BUFFER_DB_PATH", "buffer.db")
    # Seconds to wait for data on an open socket before checking _stop
    CONNECTION_TIMEOUT: float = float(os.getenv("CONNECTION_TIMEOUT", "2.0"))
    # Seconds between offline-buffer flush attempts
    FLUSH_INTERVAL: int = int(os.getenv("FLUSH_INTERVAL", "10"))
    # Optional metadata attached to every event
    LOCATION: str = os.getenv("LOCATION", "")
    PRODUCTION_LINE: str = os.getenv("PRODUCTION_LINE", "")
