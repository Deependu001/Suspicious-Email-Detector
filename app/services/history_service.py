import json
import os
import re
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from app.models.pipeline_models import PipelineResult


DEFAULT_DATABASE_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "history.sqlite3"
)

DATABASE_PATH = os.environ.get(
    "EMAIL_DETECTOR_DATABASE_PATH",
    str(DEFAULT_DATABASE_PATH),
)

URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


class HistoryService:
    """Persist and retrieve sanitized email analysis history using SQLite."""

    def __init__(
        self,
        database_path: str | Path | None = None,
    ) -> None:
        self.database_path = Path(
            database_path
            if database_path is not None
            else DATABASE_PATH
        )

        self.initialize_database()

    def _connect(self) -> sqlite3.Connection:
        """Open a SQLite connection with named-column access."""

        connection = sqlite3.connect(
            str(self.database_path),
            timeout=5.0,
        )
        connection.row_factory = sqlite3.Row
        return connection

    def initialize_database(self) -> None:
        """Create the database directory and history table if necessary."""

        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with closing(self._connect()) as connection:
            with connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS analysis_history (
                        id TEXT PRIMARY KEY,
                        analyzed_at TEXT NOT NULL,
                        sender TEXT,
                        subject TEXT,
                        risk_score REAL NOT NULL,
                        ml_phishing_probability REAL NOT NULL,
                        result_json TEXT NOT NULL
                    )
                    """
                )

                connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS
                    idx_analysis_history_analyzed_at
                    ON analysis_history (analyzed_at DESC)
                    """
                )

    @staticmethod
    def _safe_url(url: str) -> str:
        """
        Keep a URL's scheme, hostname, and valid port.

        Redact the path, query, fragment, and any user information.
        """

        try:
            parsed = urlsplit(url)
            hostname = parsed.hostname

            if not parsed.scheme or not hostname:
                return "[REDACTED]"

            # IPv6 addresses require brackets when reconstructed.
            if ":" in hostname:
                hostname = f"[{hostname}]"

            safe_url = f"{parsed.scheme}://{hostname}"

            try:
                port = parsed.port
            except ValueError:
                port = None

            if port is not None:
                safe_url += f":{port}"

            return f"{safe_url}/[REDACTED]"

        except (TypeError, ValueError):
            return "[REDACTED]"

    @classmethod
    def _sanitize_embedded_urls(cls, value: Any) -> Any:
        """
        Recursively redact URLs embedded in saved text and data structures.

        This is applied to the history copy only. Live analysis results
        and detection behavior are not modified.
        """

        if isinstance(value, dict):
            return {
                key: cls._sanitize_embedded_urls(item)
                for key, item in value.items()
            }

        if isinstance(value, list):
            return [
                cls._sanitize_embedded_urls(item)
                for item in value
            ]

        if isinstance(value, tuple):
            return [
                cls._sanitize_embedded_urls(item)
                for item in value
            ]

        if isinstance(value, str):
            return URL_PATTERN.sub(
                lambda match: cls._safe_url(match.group(0)),
                value,
            )

        return value

    @classmethod
    def _sanitize_result(
        cls,
        result: PipelineResult | dict[str, Any],
    ) -> dict[str, Any]:
        """
        Convert findings into JSON-compatible, privacy-conscious data.

        Exclude the parsed email and sensitive header fields. Redact URL
        paths, queries, fragments, and embedded URLs throughout the
        saved result, including rule observations and explanations.
        """

        if isinstance(result, PipelineResult):
            payload = result.model_dump(mode="json")
        elif isinstance(result, dict):
            payload = dict(result)
        else:
            raise TypeError(
                "result must be a PipelineResult or dictionary."
            )

        # The parsed email may contain bodies, recipients, raw headers,
        # normalized headers, and authentication-header values.
        payload.pop("email", None)

        # Remove identifying email addresses from header-analysis findings.
        header_analysis = payload.get("header_analysis")

        if isinstance(header_analysis, dict):
            header_analysis = dict(header_analysis)

            for field in (
                "from_address",
                "reply_to",
                "return_path",
            ):
                header_analysis.pop(field, None)

            payload["header_analysis"] = header_analysis

        # Sanitize every URL-bearing text field, including URL analyses,
        # rule observations, and explainability observations.
        payload = cls._sanitize_embedded_urls(payload)

        # Explicitly clear URL components that may contain secrets.
        # Keep the fields present in the response contract when provided.
        url_analyses = payload.get("url_analyses")

        if isinstance(url_analyses, list):
            sanitized_urls = []

            for url_analysis in url_analyses:
                if not isinstance(url_analysis, dict):
                    sanitized_urls.append(url_analysis)
                    continue

                url_analysis = dict(url_analysis)

                scheme = url_analysis.get("scheme")
                hostname = url_analysis.get("hostname")
                port = url_analysis.get("port")

                if isinstance(hostname, str) and hostname:
                    safe_url = ""

                    if isinstance(scheme, str) and scheme:
                        safe_url = f"{scheme}://"

                    # Avoid retaining credentials or path components.
                    if ":" in hostname and not hostname.startswith("["):
                        safe_url += f"[{hostname}]"
                    else:
                        safe_url += hostname

                    if (
                        isinstance(port, int)
                        and not isinstance(port, bool)
                    ):
                        safe_url += f":{port}"

                    safe_url += "/[REDACTED]"
                else:
                    safe_url = "[REDACTED]"

                for field in (
                    "original_url",
                    "normalized_url",
                    "url",
                ):
                    if field in url_analysis:
                        url_analysis[field] = safe_url

                for field in (
                    "path",
                    "query",
                    "fragment",
                ):
                    if field in url_analysis:
                        url_analysis[field] = None

                sanitized_urls.append(url_analysis)

            payload["url_analyses"] = sanitized_urls

        try:
            return json.loads(
                json.dumps(
                    payload,
                    ensure_ascii=False,
                    allow_nan=False,
                )
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "Analysis findings must be valid JSON data."
            ) from exc

    @staticmethod
    def _summary_from_row(
        row: sqlite3.Row,
    ) -> dict[str, Any]:
        """Convert a database row into a history summary."""

        return {
            "id": row["id"],
            "analyzed_at": row["analyzed_at"],
            "sender": row["sender"],
            "subject": row["subject"],
            "risk_score": row["risk_score"],
            "ml_phishing_probability": (
                row["ml_phishing_probability"]
            ),
        }

    def save_analysis(
        self,
        result: PipelineResult | dict[str, Any],
    ) -> dict[str, Any]:
        """Save a completed analysis and return its history record."""

        if isinstance(result, PipelineResult):
            payload = result.model_dump(mode="json")
        elif isinstance(result, dict):
            payload = dict(result)
        else:
            raise TypeError(
                "result must be a PipelineResult or dictionary."
            )

        email_data = payload.get("email")

        if isinstance(email_data, dict):
            sender = email_data.get("sender")
            subject = email_data.get("subject")
        else:
            sender = getattr(email_data, "sender", None)
            subject = getattr(email_data, "subject", None)

        sanitized_result = self._sanitize_result(payload)

        risk_score = payload.get("risk_score")
        probability = payload.get("ml_phishing_probability")

        if risk_score is None or probability is None:
            raise ValueError(
                "Analysis result must contain risk_score and "
                "ml_phishing_probability."
            )

        try:
            risk_score = float(risk_score)
            probability = float(probability)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "Risk score and ML probability must be numeric."
            ) from exc

        if (
            not (0.0 <= risk_score <= 100.0)
            or not (0.0 <= probability <= 1.0)
        ):
            raise ValueError(
                "Risk score must be between 0 and 100, and "
                "ML probability must be between 0 and 1."
            )

        record_id = str(uuid4())

        analyzed_at = (
            datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )

        result_json = json.dumps(
            sanitized_result,
            ensure_ascii=False,
            allow_nan=False,
        )

        with closing(self._connect()) as connection:
            with connection:
                connection.execute(
                    """
                    INSERT INTO analysis_history (
                        id,
                        analyzed_at,
                        sender,
                        subject,
                        risk_score,
                        ml_phishing_probability,
                        result_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record_id,
                        analyzed_at,
                        sender,
                        subject,
                        risk_score,
                        probability,
                        result_json,
                    ),
                )

        return {
            "id": record_id,
            "analyzed_at": analyzed_at,
            "sender": sender,
            "subject": subject,
            "risk_score": risk_score,
            "ml_phishing_probability": probability,
            "result": sanitized_result,
        }

    def list_history(
        self,
        limit: int = 20,
    ) -> dict[str, Any]:
        """Return recent history summaries, newest first."""

        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ValueError("limit must be an integer.")

        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100.")

        with closing(self._connect()) as connection:
            total_row = connection.execute(
                "SELECT COUNT(*) AS total FROM analysis_history"
            ).fetchone()

            rows = connection.execute(
                """
                SELECT
                    id,
                    analyzed_at,
                    sender,
                    subject,
                    risk_score,
                    ml_phishing_probability
                FROM analysis_history
                ORDER BY analyzed_at DESC, rowid DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return {
            "items": [
                self._summary_from_row(row)
                for row in rows
            ],
            "total": total_row["total"],
        }

    def get_history_record(
        self,
        record_id: str,
    ) -> dict[str, Any] | None:
        """Retrieve one saved record, or None if it does not exist."""

        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT
                    id,
                    analyzed_at,
                    sender,
                    subject,
                    risk_score,
                    ml_phishing_probability,
                    result_json
                FROM analysis_history
                WHERE id = ?
                """,
                (record_id,),
            ).fetchone()

        if row is None:
            return None

        try:
            result = json.loads(row["result_json"])
        except (json.JSONDecodeError, TypeError) as exc:
            raise ValueError(
                "Stored analysis findings contain invalid JSON."
            ) from exc

        return {
            "id": row["id"],
            "analyzed_at": row["analyzed_at"],
            "sender": row["sender"],
            "subject": row["subject"],
            "risk_score": row["risk_score"],
            "ml_phishing_probability": (
                row["ml_phishing_probability"]
            ),
            "result": result,
        }
