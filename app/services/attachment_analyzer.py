from pathlib import PurePath

from app.models.attachment_models import (
    AttachmentAnalysis,
    AttachmentAnalysisItem,
)
from app.models.email_models import EmailAttachment, EmailData


class AttachmentAnalyzer:
    """
    Analyze structural and security-related characteristics of
    email attachments.

    This component analyzes attachment metadata extracted by the
    Phase 2 email parser.

    It does not inspect attachment contents, execute files, assign
    a risk score, determine a verdict, or generate explanations.
    """

    POTENTIALLY_DANGEROUS_EXTENSIONS = {
        ".exe",
        ".bat",
        ".cmd",
        ".com",
        ".scr",
        ".js",
        ".jse",
        ".vbs",
        ".vbe",
        ".ps1",
        ".psm1",
        ".msi",
        ".msp",
        ".reg",
        ".dll",
        ".hta",
    }

    EXPECTED_MIME_TYPES = {
        ".pdf": {"application/pdf"},
        ".csv": {"text/csv"},
        ".txt": {"text/plain"},
        ".html": {"text/html"},
        ".htm": {"text/html"},
        ".jpg": {"image/jpeg"},
        ".jpeg": {"image/jpeg"},
        ".png": {"image/png"},
        ".zip": {"application/zip"},
        ".exe": {"application/vnd.microsoft.portable-executable"},
    }

    @staticmethod
    def analyze(email: EmailData) -> AttachmentAnalysis:
        """
        Analyze all attachments associated with an EmailData object.
        """

        if not isinstance(email, EmailData):
            raise TypeError("email must be an EmailData instance.")

        attachments = email.attachments

        analysis_items = []

        dangerous_extensions = []
        double_extensions = []
        mime_mismatches = []
        unusual_filenames = []

        for attachment in attachments:
            item = AttachmentAnalyzer._analyze_attachment(attachment)

            analysis_items.append(item)

            if item.is_potentially_dangerous_extension:
                if item.extension not in dangerous_extensions:
                    dangerous_extensions.append(item.extension)

            if item.is_double_extension and item.filename:
                double_extensions.append(item.filename)

            if item.is_filename_mime_mismatch and item.filename:
                mime_mismatches.append(item.filename)

            if item.filename is None or not item.filename.strip():
                unusual_filenames.append(
                    item.filename if item.filename is not None else ""
                )

        return AttachmentAnalysis(
            attachment_present=bool(attachments),
            attachment_count=len(attachments),
            attachments=analysis_items,
            dangerous_extensions=dangerous_extensions,
            double_extensions=double_extensions,
            mime_mismatches=mime_mismatches,
            unusual_filenames=unusual_filenames,
        )

    @staticmethod
    def _analyze_attachment(
        attachment: EmailAttachment,
    ) -> AttachmentAnalysisItem:
        """
        Analyze metadata for one attachment.
        """

        filename = attachment.filename
        content_type = (
            attachment.content_type.lower().strip()
            if attachment.content_type
            else None
        )

        has_filename = bool(filename and filename.strip())

        extension = AttachmentAnalyzer._extract_extension(filename)
        has_extension = extension is not None

        is_double_extension = AttachmentAnalyzer._is_double_extension(
            filename
        )

        is_potentially_dangerous_extension = (
            extension in AttachmentAnalyzer.POTENTIALLY_DANGEROUS_EXTENSIONS
        )

        is_filename_mime_mismatch = (
            AttachmentAnalyzer._is_filename_mime_mismatch(
                extension=extension,
                content_type=content_type,
            )
        )

        return AttachmentAnalysisItem(
            filename=filename,
            extension=extension,
            content_type=content_type,
            has_filename=has_filename,
            has_extension=has_extension,
            is_double_extension=is_double_extension,
            is_potentially_dangerous_extension=(
                is_potentially_dangerous_extension
            ),
            is_filename_mime_mismatch=is_filename_mime_mismatch,
            size_bytes=attachment.size_bytes,
        )

    @staticmethod
    def _extract_extension(filename: str | None) -> str | None:
        """
        Extract the final lowercase file extension.

        Returns None when the filename is missing, empty, or has no
        usable extension.
        """

        if not filename or not filename.strip():
            return None

        cleaned_filename = filename.strip()

        suffix = PurePath(cleaned_filename).suffix.lower()

        if not suffix or suffix == ".":
            return None

        return suffix

    @staticmethod
    def _is_double_extension(filename: str | None) -> bool:
        """
        Detect filenames containing multiple extensions.

        A filename is considered a double-extension filename when it
        contains at least two suffixes and the final suffix differs
        from the preceding suffix.

        Examples:

            invoice.pdf.exe -> True
            report.doc.pdf  -> True
            report.pdf      -> False
        """

        if not filename or not filename.strip():
            return False

        cleaned_filename = filename.strip()

        suffixes = [
            suffix.lower()
            for suffix in PurePath(cleaned_filename).suffixes
            if suffix and suffix != "."
        ]

        return len(suffixes) >= 2 and suffixes[-1] != suffixes[-2]

    @staticmethod
    def _is_filename_mime_mismatch(
        extension: str | None,
        content_type: str | None,
    ) -> bool:
        """
        Detect mismatches between known filename extensions and MIME types.

        Only MIME mappings explicitly defined in EXPECTED_MIME_TYPES are
        evaluated. Unknown extensions or unknown MIME mappings are not
        considered mismatches.
        """

        if extension is None or content_type is None:
            return False

        expected_types = AttachmentAnalyzer.EXPECTED_MIME_TYPES.get(
            extension
        )

        if expected_types is None:
            return False

        return content_type not in expected_types