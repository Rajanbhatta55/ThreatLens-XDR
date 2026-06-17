"""Email reporting helpers for ThreatLens."""

from __future__ import annotations

import mimetypes
import smtplib
import time
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path


@dataclass(slots=True)
class EmailAlerter:
    """SMTP email delivery for weekly reports and incident notifications."""

    smtp_host: str
    smtp_port: int = 587
    username: str | None = None
    password: str | None = None
    use_tls: bool = True
    use_ssl: bool = False
    retries: int = 3
    retry_delay: float = 1.0

    def _connect(self):
        if self.use_ssl:
            client = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=30)
        else:
            client = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=30)
        client.ehlo()
        if self.use_tls and not self.use_ssl:
            client.starttls()
            client.ehlo()
        if self.username and self.password:
            client.login(self.username, self.password)
        return client

    def send_report(
        self,
        from_address: str,
        to_address: str,
        subject: str,
        body: str,
        attachment_path: Path | None = None,
    ) -> None:
        message = EmailMessage()
        message["From"] = from_address
        message["To"] = to_address
        message["Subject"] = subject
        message.set_content(body)

        if attachment_path is not None:
            mime_type, _ = mimetypes.guess_type(str(attachment_path))
            maintype, subtype = (mime_type or "application/octet-stream").split("/", 1)
            message.add_attachment(
                attachment_path.read_bytes(),
                maintype=maintype,
                subtype=subtype,
                filename=attachment_path.name,
            )

        last_error: Exception | None = None
        for attempt in range(1, self.retries + 1):
            try:
                with self._connect() as client:
                    client.send_message(message)
                return
            except Exception as exc:
                last_error = exc
                if attempt >= self.retries:
                    break
                time.sleep(self.retry_delay * attempt)
        raise RuntimeError(f"Failed to send email after {self.retries} attempt(s): {last_error}") from last_error
