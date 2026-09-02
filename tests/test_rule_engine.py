from app.models.attachment_models import AttachmentAnalysis, AttachmentAnalysisItem
from app.models.email_models import EmailAttachment, EmailAuthenticationHeaders, EmailData
from app.models.header_models import HeaderAnalysis
from app.models.url_models import URLAnalysis
from app.services.rule_engine import RuleEngine


def create_email() -> EmailData:
    return EmailData(
        sender="sender@example.com",
        recipients=["recipient@example.com"],
        subject="Test email",
        urls=[],
        attachments=[],
        authentication=EmailAuthenticationHeaders(),
        headers={},
        normalized_headers={},
        is_multipart=False,
    )


def create_header_analysis() -> HeaderAnalysis:
    return HeaderAnalysis(
        from_present=True,
        reply_to_present=True,
        return_path_present=True,
        from_domain="example.com",
        reply_to_domain="reply.example.net",
        return_path_domain="mail.example.net",
        from_reply_to_domain_mismatch=True,
        from_return_path_domain_mismatch=True,
        received_header_count=2,
        authentication_results_present=True,
        received_spf_present=True,
        dkim_signature_present=True,
        arc_authentication_results_present=False,
        arc_message_signature_present=False,
        arc_seal_present=False,
        spf_statuses=["fail"],
        dkim_statuses=["fail"],
        dmarc_statuses=["fail"],
    )


def create_url_analysis() -> list[URLAnalysis]:
    return [
        URLAnalysis(
            original_url="http://192.168.1.10:8080/login",
            normalized_url="http://192.168.1.10:8080/login",
            scheme="http",
            hostname="192.168.1.10",
            port=8080,
            domain="192.168.1.10",
            registered_domain=None,
            subdomain=None,
            tld=None,
            path="/login",
            query=None,
            fragment=None,
            url_length=32,
            has_ip_address=True,
            has_unusual_port=True,
            has_suspicious_characters=False,
            has_encoding=False,
            has_subdomain=False,
            suspicious_indicators=[
                "ip_address_url",
                "unusual_port",
            ],
        ),
        URLAnalysis(
            original_url="https://example.com/login%20now",
            normalized_url="https://example.com/login%20now",
            scheme="https",
            hostname="example.com",
            port=None,
            domain="example.com",
            registered_domain="example.com",
            subdomain=None,
            tld="com",
            path="/login%20now",
            query=None,
            fragment=None,
            url_length=31,
            has_ip_address=False,
            has_unusual_port=False,
            has_suspicious_characters=False,
            has_encoding=True,
            has_subdomain=False,
            suspicious_indicators=["encoded_url"],
        ),
        URLAnalysis(
            original_url="https://example.com/@login",
            normalized_url="https://example.com/@login",
            scheme="https",
            hostname="example.com",
            port=None,
            domain="example.com",
            registered_domain="example.com",
            subdomain=None,
            tld="com",
            path="/@login",
            query=None,
            fragment=None,
            url_length=26,
            has_ip_address=False,
            has_unusual_port=False,
            has_suspicious_characters=True,
            has_encoding=False,
            has_subdomain=False,
            suspicious_indicators=["suspicious_characters"],
        ),
    ]


def create_attachment_analysis() -> AttachmentAnalysis:
    attachment = AttachmentAnalysisItem(
        filename="invoice.pdf.exe",
        extension=".exe",
        content_type="application/pdf",
        has_filename=True,
        has_extension=True,
        is_double_extension=True,
        is_potentially_dangerous_extension=True,
        is_filename_mime_mismatch=True,
        size_bytes=1024,
    )

    return AttachmentAnalysis(
        attachment_present=True,
        attachment_count=1,
        attachments=[attachment],
        dangerous_extensions=["invoice.pdf.exe"],
        double_extensions=["invoice.pdf.exe"],
        mime_mismatches=["invoice.pdf.exe"],
        unusual_filenames=["invoice.pdf.exe"],
    )


def test_rule_engine_returns_all_defined_rules():
    engine = RuleEngine()

    results = engine.evaluate(
        email=create_email(),
        url_analyses=[],
        header_analysis=HeaderAnalysis(),
        attachment_analysis=AttachmentAnalysis(),
    )

    rule_ids = [result.rule_id for result in results]

    assert len(results) == 13

    assert rule_ids == [
        "HEADER_FROM_REPLY_TO_MISMATCH",
        "HEADER_FROM_RETURN_PATH_MISMATCH",
        "HEADER_SPF_FAILURE",
        "HEADER_DKIM_FAILURE",
        "HEADER_DMARC_FAILURE",
        "URL_IP_ADDRESS",
        "URL_UNUSUAL_PORT",
        "URL_SUSPICIOUS_CHARACTERS",
        "URL_ENCODING",
        "ATTACHMENT_DANGEROUS_EXTENSION",
        "ATTACHMENT_DOUBLE_EXTENSION",
        "ATTACHMENT_MIME_MISMATCH",
        "ATTACHMENT_UNUSUAL_FILENAME",
    ]


def test_header_rules_trigger_for_mismatches_and_failures():
    engine = RuleEngine()

    results = engine.evaluate(
        email=create_email(),
        url_analyses=[],
        header_analysis=create_header_analysis(),
        attachment_analysis=AttachmentAnalysis(),
    )

    triggered = {
        result.rule_id: result
        for result in results
        if result.triggered
    }

    assert "HEADER_FROM_REPLY_TO_MISMATCH" in triggered
    assert "HEADER_FROM_RETURN_PATH_MISMATCH" in triggered
    assert "HEADER_SPF_FAILURE" in triggered
    assert "HEADER_DKIM_FAILURE" in triggered
    assert "HEADER_DMARC_FAILURE" in triggered

    assert triggered["HEADER_FROM_REPLY_TO_MISMATCH"].observations == [
        "from_domain=example.com",
        "reply_to_domain=reply.example.net",
    ]

    assert triggered["HEADER_FROM_RETURN_PATH_MISMATCH"].observations == [
        "from_domain=example.com",
        "return_path_domain=mail.example.net",
    ]

    assert triggered["HEADER_SPF_FAILURE"].observations == [
        "spf_status=fail"
    ]


def test_url_rules_trigger_for_detected_url_indicators():
    engine = RuleEngine()

    results = engine.evaluate(
        email=create_email(),
        url_analyses=create_url_analysis(),
        header_analysis=HeaderAnalysis(),
        attachment_analysis=AttachmentAnalysis(),
    )

    triggered = {
        result.rule_id: result
        for result in results
        if result.triggered
    }

    assert "URL_IP_ADDRESS" in triggered
    assert "URL_UNUSUAL_PORT" in triggered
    assert "URL_SUSPICIOUS_CHARACTERS" in triggered
    assert "URL_ENCODING" in triggered

    assert triggered["URL_IP_ADDRESS"].observations == [
        "url=http://192.168.1.10:8080/login"
    ]

    assert triggered["URL_UNUSUAL_PORT"].observations == [
        "url=http://192.168.1.10:8080/login"
    ]

    assert triggered["URL_SUSPICIOUS_CHARACTERS"].observations == [
        "url=https://example.com/@login"
    ]

    assert triggered["URL_ENCODING"].observations == [
        "url=https://example.com/login%20now"
    ]


def test_attachment_rules_trigger_for_attachment_indicators():
    engine = RuleEngine()

    results = engine.evaluate(
        email=create_email(),
        url_analyses=[],
        header_analysis=HeaderAnalysis(),
        attachment_analysis=create_attachment_analysis(),
    )

    triggered = {
        result.rule_id: result
        for result in results
        if result.triggered
    }

    assert "ATTACHMENT_DANGEROUS_EXTENSION" in triggered
    assert "ATTACHMENT_DOUBLE_EXTENSION" in triggered
    assert "ATTACHMENT_MIME_MISMATCH" in triggered
    assert "ATTACHMENT_UNUSUAL_FILENAME" in triggered

    expected_observation = ["filename=invoice.pdf.exe"]

    assert triggered["ATTACHMENT_DANGEROUS_EXTENSION"].observations == expected_observation
    assert triggered["ATTACHMENT_DOUBLE_EXTENSION"].observations == expected_observation
    assert triggered["ATTACHMENT_MIME_MISMATCH"].observations == expected_observation
    assert triggered["ATTACHMENT_UNUSUAL_FILENAME"].observations == expected_observation


def test_rule_engine_does_not_trigger_rules_without_matching_observations():
    engine = RuleEngine()

    results = engine.evaluate(
        email=create_email(),
        url_analyses=[],
        header_analysis=HeaderAnalysis(),
        attachment_analysis=AttachmentAnalysis(),
    )

    assert all(result.triggered is False for result in results)
    assert all(result.observations == [] for result in results)


def test_authentication_rules_only_trigger_on_fail_status():
    engine = RuleEngine()

    header_analysis = HeaderAnalysis(
        spf_statuses=["pass", "neutral"],
        dkim_statuses=["pass"],
        dmarc_statuses=["pass"],
    )

    results = engine.evaluate(
        email=create_email(),
        url_analyses=[],
        header_analysis=header_analysis,
        attachment_analysis=AttachmentAnalysis(),
    )

    triggered = {
        result.rule_id
        for result in results
        if result.triggered
    }

    assert "HEADER_SPF_FAILURE" not in triggered
    assert "HEADER_DKIM_FAILURE" not in triggered
    assert "HEADER_DMARC_FAILURE" not in triggered


def test_rule_result_contains_structured_rule_information():
    engine = RuleEngine()

    results = engine.evaluate(
        email=create_email(),
        url_analyses=[],
        header_analysis=create_header_analysis(),
        attachment_analysis=AttachmentAnalysis(),
    )

    result = results[0]

    assert result.rule_id == "HEADER_FROM_REPLY_TO_MISMATCH"
    assert result.description
    assert isinstance(result.triggered, bool)
    assert isinstance(result.observations, list)
def test_rule_engine_handles_empty_inputs():
    engine = RuleEngine()

    results = engine.evaluate(
        email=create_email(),
        url_analyses=[],
        header_analysis=HeaderAnalysis(),
        attachment_analysis=AttachmentAnalysis(),
    )

    assert len(results) == 13
    assert all(result.triggered is False for result in results)
    assert all(result.observations == [] for result in results)


def test_header_mismatch_rules_do_not_trigger_when_domains_are_missing():
    engine = RuleEngine()

    header_analysis = HeaderAnalysis(
        from_present=True,
        reply_to_present=True,
        return_path_present=True,
        from_domain=None,
        reply_to_domain="example.com",
        return_path_domain="example.net",
        from_reply_to_domain_mismatch=False,
        from_return_path_domain_mismatch=False,
    )

    results = engine.evaluate(
        email=create_email(),
        url_analyses=[],
        header_analysis=header_analysis,
        attachment_analysis=AttachmentAnalysis(),
    )

    triggered = {
        result.rule_id
        for result in results
        if result.triggered
    }

    assert "HEADER_FROM_REPLY_TO_MISMATCH" not in triggered
    assert "HEADER_FROM_RETURN_PATH_MISMATCH" not in triggered


def test_authentication_rules_ignore_non_failure_statuses():
    engine = RuleEngine()

    header_analysis = HeaderAnalysis(
        spf_statuses=["pass", "softfail", "neutral"],
        dkim_statuses=["pass", "none"],
        dmarc_statuses=["pass", "none"],
    )

    results = engine.evaluate(
        email=create_email(),
        url_analyses=[],
        header_analysis=header_analysis,
        attachment_analysis=AttachmentAnalysis(),
    )

    triggered = {
        result.rule_id
        for result in results
        if result.triggered
    }

    assert "HEADER_SPF_FAILURE" not in triggered
    assert "HEADER_DKIM_FAILURE" not in triggered
    assert "HEADER_DMARC_FAILURE" not in triggered


def test_authentication_failure_matching_is_case_and_whitespace_insensitive():
    engine = RuleEngine()

    header_analysis = HeaderAnalysis(
        spf_statuses=[" PASS ", "FAIL "],
        dkim_statuses=[" Fail"],
        dmarc_statuses=["FAIL"],
    )

    results = engine.evaluate(
        email=create_email(),
        url_analyses=[],
        header_analysis=header_analysis,
        attachment_analysis=AttachmentAnalysis(),
    )

    triggered = {
        result.rule_id: result
        for result in results
        if result.triggered
    }

    assert "HEADER_SPF_FAILURE" in triggered
    assert "HEADER_DKIM_FAILURE" in triggered
    assert "HEADER_DMARC_FAILURE" in triggered

    assert triggered["HEADER_SPF_FAILURE"].observations == [
        "spf_status=FAIL "
    ]
    assert triggered["HEADER_DKIM_FAILURE"].observations == [
        "dkim_status= Fail"
    ]
    assert triggered["HEADER_DMARC_FAILURE"].observations == [
        "dmarc_status=FAIL"
    ]


def test_multiple_urls_are_all_reported_for_the_same_rule():
    engine = RuleEngine()

    url_analyses = [
        URLAnalysis(
            original_url="http://192.168.1.10/login",
            normalized_url="http://192.168.1.10/login",
            scheme="http",
            hostname="192.168.1.10",
            port=None,
            domain="192.168.1.10",
            registered_domain=None,
            subdomain=None,
            tld=None,
            path="/login",
            query=None,
            fragment=None,
            url_length=27,
            has_ip_address=True,
            has_unusual_port=False,
            has_suspicious_characters=False,
            has_encoding=False,
            has_subdomain=False,
            suspicious_indicators=["ip_address_url"],
        ),
        URLAnalysis(
            original_url="http://10.0.0.5/account",
            normalized_url="http://10.0.0.5/account",
            scheme="http",
            hostname="10.0.0.5",
            port=None,
            domain="10.0.0.5",
            registered_domain=None,
            subdomain=None,
            tld=None,
            path="/account",
            query=None,
            fragment=None,
            url_length=25,
            has_ip_address=True,
            has_unusual_port=False,
            has_suspicious_characters=False,
            has_encoding=False,
            has_subdomain=False,
            suspicious_indicators=["ip_address_url"],
        ),
    ]

    results = engine.evaluate(
        email=create_email(),
        url_analyses=url_analyses,
        header_analysis=HeaderAnalysis(),
        attachment_analysis=AttachmentAnalysis(),
    )

    ip_rule = next(
        result
        for result in results
        if result.rule_id == "URL_IP_ADDRESS"
    )

    assert ip_rule.triggered is True
    assert ip_rule.observations == [
        "url=http://192.168.1.10/login",
        "url=http://10.0.0.5/account",
    ]


def test_multiple_attachments_are_all_reported_for_the_same_rule():
    engine = RuleEngine()

    attachment_analysis = AttachmentAnalysis(
        attachment_present=True,
        attachment_count=2,
        attachments=[
            AttachmentAnalysisItem(
                filename="invoice.exe",
                extension=".exe",
                content_type="application/octet-stream",
                has_filename=True,
                has_extension=True,
                is_double_extension=False,
                is_potentially_dangerous_extension=True,
                is_filename_mime_mismatch=False,
                size_bytes=1000,
            ),
            AttachmentAnalysisItem(
                filename="script.js",
                extension=".js",
                content_type="application/javascript",
                has_filename=True,
                has_extension=True,
                is_double_extension=False,
                is_potentially_dangerous_extension=True,
                is_filename_mime_mismatch=False,
                size_bytes=500,
            ),
        ],
        dangerous_extensions=["invoice.exe", "script.js"],
        double_extensions=[],
        mime_mismatches=[],
        unusual_filenames=[],
    )

    results = engine.evaluate(
        email=create_email(),
        url_analyses=[],
        header_analysis=HeaderAnalysis(),
        attachment_analysis=attachment_analysis,
    )

    dangerous_rule = next(
        result
        for result in results
        if result.rule_id == "ATTACHMENT_DANGEROUS_EXTENSION"
    )

    assert dangerous_rule.triggered is True
    assert dangerous_rule.observations == [
        "filename=invoice.exe",
        "filename=script.js",
    ]


def test_rule_engine_evaluation_is_deterministic():
    engine = RuleEngine()

    first_results = engine.evaluate(
        email=create_email(),
        url_analyses=create_url_analysis(),
        header_analysis=create_header_analysis(),
        attachment_analysis=create_attachment_analysis(),
    )

    second_results = engine.evaluate(
        email=create_email(),
        url_analyses=create_url_analysis(),
        header_analysis=create_header_analysis(),
        attachment_analysis=create_attachment_analysis(),
    )

    assert first_results == second_results