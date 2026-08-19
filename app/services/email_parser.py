import re

from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from pathlib import Path

from app.models.email_models import (
    EmailAttachment,
    EmailAuthenticationHeaders,
    EmailData,
)


class EmailParser:
    """
    Parses .eml files and converts them into our structured EmailData model.
    """

    def parse_file(self, file_path: str | Path) -> EmailData:
        """
        Parse an .eml file from disk.

        Args:
            file_path: Path to the .eml file.

        Returns:
            EmailData containing extracted email metadata.
        """

        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"Email file not found: {path}")

        if not path.is_file():
            raise ValueError(f"Provided path is not a file: {path}")

        with path.open("rb") as email_file:
            message = BytesParser(policy=policy.default).parse(email_file)

        return self._build_email_data(message)

    def _build_email_data(self, message) -> EmailData:
        """
        Convert a Python EmailMessage object into our structured EmailData model.
        """

        headers = {}
        normalized_headers = {}

        for header_name, header_value in message.items():
            value = str(header_value)

            headers.setdefault(header_name, []).append(value)

            normalized_name = header_name.lower()
            normalized_headers.setdefault(
                normalized_name,
                [],
            ).append(value)

        plain_text_body = self._extract_plain_text_body(message)
        html_body = self._extract_html_body(message)
        attachments = self._extract_attachments(message)
        authentication = self._extract_authentication_headers(message)

        return EmailData(
            sender=self._get_single_address(message.get("From")),
            recipients=self._get_addresses(message.get("To")),
            cc=self._get_addresses(message.get("Cc")),
            bcc=self._get_addresses(message.get("Bcc")),
            subject=self._get_header(message, "Subject"),
            date=self._get_header(message, "Date"),
            reply_to=self._get_single_address(message.get("Reply-To")),
            message_id=self._get_header(message, "Message-ID"),
            return_path=self._get_single_address(message.get("Return-Path")),
            content_type=self._get_header(message, "Content-Type"),
            mime_version=self._get_header(message, "MIME-Version"),
            is_multipart=message.is_multipart(),
            plain_text_body=plain_text_body,
            html_body=html_body,
            urls=self._extract_urls(
                plain_text_body=plain_text_body,
                html_body=html_body,
            ),
            attachments=attachments,
            authentication=authentication,
            headers=headers,
            normalized_headers=normalized_headers,
        )

    @staticmethod
    def _extract_authentication_headers(
        message,
    ) -> EmailAuthenticationHeaders:
        """
        Extract authentication-related headers from an email message.

        This method only extracts authentication-related headers that
        are actually present in the email.

        It does NOT independently verify:
        - SPF
        - DKIM
        - DMARC
        - ARC

        Multiple occurrences of the same header are preserved
        in their original order.
        """

        authentication = EmailAuthenticationHeaders()

        header_mapping = {
            "authentication-results": "authentication_results",
            "received-spf": "received_spf",
            "dkim-signature": "dkim_signature",
            "arc-authentication-results": "arc_authentication_results",
            "arc-message-signature": "arc_message_signature",
            "arc-seal": "arc_seal",
        }

        for header_name, header_value in message.raw_items():
            field_name = header_mapping.get(header_name.lower())

            if field_name is None:
                continue

            value = str(header_value)

            getattr(authentication, field_name).append(value)

        return authentication

    @staticmethod
    def _iter_body_parts(message):
        """
        Recursively traverse MIME parts while skipping attachments.

        Only non-attachment MIME parts are yielded.
        """

        if message.get_content_disposition() == "attachment":
            return

        if message.is_multipart():
            for child in message.iter_parts():
                yield from EmailParser._iter_body_parts(child)
        else:
            yield message

    @staticmethod
    def _extract_attachments(message) -> list[EmailAttachment]:
        """
        Extract metadata for attachment MIME parts.

        The actual attachment content is never stored.

        Returns:
            A list of EmailAttachment objects containing:
            - filename
            - content type
            - decoded size in bytes
            - content disposition
        """

        attachments = []

        for part in message.walk():
            content_disposition = part.get_content_disposition()

            if content_disposition != "attachment":
                continue

            payload = part.get_payload(decode=True)

            if payload is None:
                size_bytes = 0
            else:
                size_bytes = len(payload)

            attachment = EmailAttachment(
                filename=part.get_filename(),
                content_type=part.get_content_type(),
                size_bytes=size_bytes,
                content_disposition=content_disposition,
            )

            attachments.append(attachment)

        return attachments

    @staticmethod
    def _extract_plain_text_body(message) -> str | None:
        """
        Extract the first non-attachment text/plain body part.

        MIME transfer decoding and character-set decoding are handled
        by the email package through get_content().
        """

        for part in EmailParser._iter_body_parts(message):
            if part.get_content_type().lower() != "text/plain":
                continue

            try:
                content = part.get_content()

            except (LookupError, UnicodeDecodeError):
                payload = part.get_payload(decode=True)

                if payload is None:
                    continue

                charset = part.get_content_charset() or "utf-8"

                try:
                    content = payload.decode(charset)

                except (LookupError, UnicodeDecodeError):
                    content = payload.decode(
                        "utf-8",
                        errors="replace",
                    )

            if isinstance(content, str) and content.strip():
                return content.strip()

        return None

    @staticmethod
    def _extract_html_body(message) -> str | None:
        """
        Extract the first non-attachment text/html body part.

        MIME transfer decoding and character-set decoding are handled
        by the email package through get_content().
        """

        for part in EmailParser._iter_body_parts(message):
            if part.get_content_type().lower() != "text/html":
                continue

            try:
                content = part.get_content()

            except (LookupError, UnicodeDecodeError):
                payload = part.get_payload(decode=True)

                if payload is None:
                    continue

                charset = part.get_content_charset() or "utf-8"

                try:
                    content = payload.decode(charset)

                except (LookupError, UnicodeDecodeError):
                    content = payload.decode(
                        "utf-8",
                        errors="replace",
                    )

            if isinstance(content, str) and content.strip():
                return content.strip()

        return None

    @staticmethod
    def _extract_urls(
        plain_text_body: str | None,
        html_body: str | None,
    ) -> list[str]:
        """
        Extract URLs from plain-text and HTML email bodies.

        URLs are collected from:

        1. Plain-text content
        2. HTML href attributes

        Duplicate URLs are removed while preserving their
        original discovery order.
        """

        urls = []

        if plain_text_body:
            urls.extend(
                re.findall(
                    r"https?://[^\s<>\"]+",
                    plain_text_body,
                    flags=re.IGNORECASE,
                )
            )

        if html_body:
            urls.extend(
                re.findall(
                    r"""href\s*=\s*["'](https?://[^"']+)["']""",
                    html_body,
                    flags=re.IGNORECASE,
                )
            )

        unique_urls = []
        seen = set()

        for url in urls:
            cleaned_url = url.rstrip(".,!?;:)]}")

            if cleaned_url and cleaned_url not in seen:
                seen.add(cleaned_url)
                unique_urls.append(cleaned_url)

        return unique_urls

    @staticmethod
    def _get_header(message, header_name: str) -> str | None:
        """
        Safely retrieve a single email header.
        """

        value = message.get(header_name)

        if value is None:
            return None

        return str(value)

    @staticmethod
    def _get_single_address(header_value: str | None) -> str | None:
        """
        Extract a single email address from a header.

        Example:

            Alice Security <alice@example.com>

        becomes:

            alice@example.com
        """

        if not header_value:
            return None

        addresses = getaddresses([header_value])

        if not addresses:
            return None

        _, email_address = addresses[0]

        return email_address or None

    @staticmethod
    def _get_addresses(header_value: str | None) -> list[str]:
        """
        Extract email addresses from a recipient header.

        Example:

            Bob <bob@example.com>, Alice <alice@example.com>

        becomes:

            [
                "bob@example.com",
                "alice@example.com"
            ]
        """

        if not header_value:
            return []

        addresses = getaddresses([header_value])

        return [
            email_address
            for _, email_address in addresses
            if email_address
        ]