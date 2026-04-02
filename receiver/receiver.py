"""
Keyence TCP/IP data receiver.

Listens on a TCP port, decodes ASCII or HEX packets from Keyence devices,
buffers events in a local SQLite database when the API is unreachable, and
flushes the buffer once connectivity is restored.
"""

import json
import logging
import signal
import socket
import sqlite3
import threading
import time
from datetime import datetime, timezone

import requests

from config import Config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Local buffer
# ---------------------------------------------------------------------------


class LocalBuffer:
    """SQLite-backed FIFO queue for events that could not be sent immediately."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS pending_scans (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    payload     TEXT    NOT NULL,
                    created_at  TEXT    NOT NULL,
                    retry_count INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.commit()

    def enqueue(self, payload: dict) -> int:
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.execute(
                    "INSERT INTO pending_scans (payload, created_at) VALUES (?, ?)",
                    (json.dumps(payload), datetime.now(timezone.utc).isoformat()),
                )
                conn.commit()
                return cur.lastrowid  # type: ignore[return-value]

    def delete(self, record_id: int) -> None:
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM pending_scans WHERE id = ?", (record_id,))
                conn.commit()

    def increment_retry(self, record_id: int) -> None:
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "UPDATE pending_scans SET retry_count = retry_count + 1 WHERE id = ?",
                    (record_id,),
                )
                conn.commit()

    def get_pending(self, limit: int = 50) -> list[dict]:
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute(
                    "SELECT id, payload, retry_count FROM pending_scans ORDER BY id ASC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [
            {"id": r[0], "payload": json.loads(r[1]), "retry_count": r[2]}
            for r in rows
        ]

    def count(self) -> int:
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                return conn.execute(
                    "SELECT COUNT(*) FROM pending_scans"
                ).fetchone()[0]


# ---------------------------------------------------------------------------
# Packet decoder
# ---------------------------------------------------------------------------


class DataDecoder:
    @staticmethod
    def decode(raw: bytes, fmt: str) -> str | None:
        """Return the decoded string value or None if the packet is empty."""
        if fmt == "ASCII":
            value = raw.decode("ascii", errors="replace").strip("\r\n\x00 ")
        elif fmt == "HEX":
            # Keyence HEX mode: each byte is sent as two ASCII hex digits.
            hex_str = raw.decode("ascii", errors="replace").strip()
            try:
                value = bytes.fromhex(hex_str).decode("ascii", errors="replace").strip(
                    "\r\n\x00 "
                )
            except ValueError:
                # Fall back to raw hex representation
                value = hex_str
        else:
            logger.warning("Unknown format %r, treating as ASCII", fmt)
            value = raw.decode("ascii", errors="replace").strip("\r\n\x00 ")

        return value if value else None


# ---------------------------------------------------------------------------
# API sender
# ---------------------------------------------------------------------------


class APISender:
    def __init__(self, api_url: str, api_key: str) -> None:
        self.api_url = api_url
        self.session = requests.Session()
        if api_key:
            self.session.headers["X-API-Key"] = api_key
        self.session.headers["Content-Type"] = "application/json"

    def send(self, payload: dict, timeout: int = 5) -> bool:
        try:
            resp = self.session.post(self.api_url, json=payload, timeout=timeout)
            if resp.status_code in (200, 201):
                return True
            logger.warning("API returned %d: %s", resp.status_code, resp.text[:120])
            return False
        except requests.RequestException as exc:
            logger.debug("Send failed: %s", exc)
            return False


# ---------------------------------------------------------------------------
# TCP receiver
# ---------------------------------------------------------------------------


class TCPReceiver:
    def __init__(
        self, config: Config, buffer: LocalBuffer, sender: APISender
    ) -> None:
        self.config = config
        self.buffer = buffer
        self.sender = sender
        self._stop = threading.Event()

    def _build_payload(self, value: str, source_ip: str) -> dict:
        return {
            "value": value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "deviceId": self.config.DEVICE_ID,
            "format": self.config.DATA_FORMAT,
            "metadata": {
                "location": self.config.LOCATION,
                "productionLine": self.config.PRODUCTION_LINE,
                "sourceIp": source_ip,
            },
        }

    def _process_line(self, raw_line: bytes, addr: tuple) -> None:
        value = DataDecoder.decode(raw_line, self.config.DATA_FORMAT)
        if not value:
            return

        payload = self._build_payload(value, addr[0])
        logger.info("Scan from %s: %s", addr[0], value)

        record_id = self.buffer.enqueue(payload)
        if self.sender.send(payload):
            self.buffer.delete(record_id)
        else:
            logger.warning(
                "API unreachable — buffered (queue size: %d)", self.buffer.count()
            )

    def _handle_connection(self, conn: socket.socket, addr: tuple) -> None:
        logger.info("Connected: %s:%d", *addr)
        accumulator = b""
        try:
            conn.settimeout(self.config.CONNECTION_TIMEOUT)
            while not self._stop.is_set():
                try:
                    chunk = conn.recv(4096)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                accumulator += chunk
                # Keyence terminates lines with CR+LF or LF
                while True:
                    for delimiter in (b"\r\n", b"\n"):
                        if delimiter in accumulator:
                            line, accumulator = accumulator.split(delimiter, 1)
                            if line:
                                self._process_line(line, addr)
                            break
                    else:
                        break
        except OSError as exc:
            logger.debug("Socket error from %s: %s", addr, exc)
        finally:
            conn.close()
            logger.info("Disconnected: %s:%d", *addr)

    def start(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.config.TCP_HOST, self.config.TCP_PORT))
        server.listen(10)
        server.settimeout(1.0)
        logger.info(
            "Listening on %s:%d (format=%s)",
            self.config.TCP_HOST,
            self.config.TCP_PORT,
            self.config.DATA_FORMAT,
        )
        while not self._stop.is_set():
            try:
                conn, addr = server.accept()
            except socket.timeout:
                continue
            thread = threading.Thread(
                target=self._handle_connection, args=(conn, addr), daemon=True
            )
            thread.start()
        server.close()

    def stop(self) -> None:
        self._stop.set()


# ---------------------------------------------------------------------------
# Background flush loop
# ---------------------------------------------------------------------------


def flush_loop(buffer: LocalBuffer, sender: APISender, interval: int) -> None:
    """Continuously attempt to drain the offline buffer."""
    while True:
        pending = buffer.get_pending(limit=50)
        if pending:
            logger.info("Flushing %d buffered record(s)…", len(pending))
        for record in pending:
            if sender.send(record["payload"]):
                buffer.delete(record["id"])
                logger.info("Flushed: %s", record["payload"]["value"])
            else:
                buffer.increment_retry(record["id"])
        time.sleep(interval)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    config = Config()
    buffer = LocalBuffer(config.BUFFER_DB_PATH)
    sender = APISender(config.API_URL, config.API_KEY)
    receiver = TCPReceiver(config, buffer, sender)

    flush_thread = threading.Thread(
        target=flush_loop,
        args=(buffer, sender, config.FLUSH_INTERVAL),
        daemon=True,
    )
    flush_thread.start()

    def _shutdown(sig, frame):  # noqa: ANN001
        logger.info("Shutting down (signal %d)…", sig)
        receiver.stop()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    receiver.start()
    logger.info("Receiver stopped.")


if __name__ == "__main__":
    main()
