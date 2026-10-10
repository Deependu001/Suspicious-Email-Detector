import requests
import streamlit as st


DEFAULT_API_URL = "http://127.0.0.1:8000"
REQUEST_TIMEOUT_SECONDS = 60


st.set_page_config(
    page_title="Suspicious Email Detector",
    page_icon="Shield",
    layout="wide",
)


def display_value(value, default="Not available"):
    """Return a readable value for optional API fields."""
    if value is None or value == "":
        return default
    return value


def display_list(values):
    """Display a list safely."""
    if not values:
        st.write("None")
        return

    for value in values:
        st.write(f"- {value}")


def render_email_information(email):
    """Render basic information extracted from the email."""
    st.subheader("Email Information")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**From**")
        st.write(display_value(email.get("sender")))

        st.markdown("**Reply-To**")
        st.write(display_value(email.get("reply_to")))

        st.markdown("**Subject**")
        st.write(display_value(email.get("subject")))

        st.markdown("**Date**")
        st.write(display_value(email.get("date")))

    with col2:
        st.markdown("**Recipients**")
        display_list(email.get("recipients", []))

        st.markdown("**CC**")
        display_list(email.get("cc", []))

        st.markdown("**Return-Path**")
        st.write(display_value(email.get("return_path")))

        st.markdown("**Message-ID**")
        st.write(display_value(email.get("message_id")))


def render_rules(rule_results):
    """Render rule-engine results."""
    st.subheader("Detection Rules")

    triggered_rules = [
        rule for rule in rule_results if rule.get("triggered")
    ]

    if not triggered_rules:
        st.success("No detection rules were triggered.")
        return

    st.warning(f"{len(triggered_rules)} detection rule(s) triggered.")

    for rule in triggered_rules:
        rule_id = rule.get("rule_id", "Unknown rule")
        description = rule.get(
            "description",
            "No description available.",
        )
        observations = rule.get("observations", [])

        with st.expander(rule_id):
            st.write(description)

            if observations:
                st.markdown("**Observations**")
                display_list(observations)


def render_urls(url_analyses):
    """Render URL analysis results."""
    st.subheader("URL Analysis")

    if not url_analyses:
        st.info("No URLs were extracted from this email.")
        return

    st.write(f"Analyzed URLs: {len(url_analyses)}")

    for index, analysis in enumerate(url_analyses, start=1):
        original_url = analysis.get(
            "original_url",
            "Unknown URL",
        )

        with st.expander(f"URL {index}: {original_url}"):
            col1, col2 = st.columns(2)

            with col1:
                st.markdown("**Normalized URL**")
                st.write(
                    display_value(
                        analysis.get("normalized_url")
                    )
                )

                st.markdown("**Scheme**")
                st.write(display_value(analysis.get("scheme")))

                st.markdown("**Hostname**")
                st.write(display_value(analysis.get("hostname")))

                st.markdown("**Domain**")
                st.write(display_value(analysis.get("domain")))

                st.markdown("**Registered Domain**")
                st.write(
                    display_value(
                        analysis.get("registered_domain")
                    )
                )

            with col2:
                st.markdown("**Port**")
                st.write(display_value(analysis.get("port")))

                st.markdown("**Subdomain**")
                st.write(display_value(analysis.get("subdomain")))

                st.markdown("**URL Length**")
                st.write(display_value(analysis.get("url_length")))

                st.markdown("**IP Address**")
                st.write(
                    "Yes"
                    if analysis.get("has_ip_address")
                    else "No"
                )

                st.markdown("**Unusual Port**")
                st.write(
                    "Yes"
                    if analysis.get("has_unusual_port")
                    else "No"
                )

            st.markdown("**Suspicious Indicators**")
            suspicious_indicators = analysis.get(
                "suspicious_indicators",
                [],
            )
            display_list(suspicious_indicators)


def render_header_analysis(header_analysis):
    """Render header analysis results."""
    st.subheader("Header Analysis")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**From / Reply-To mismatch**")
        st.write(
            "Yes"
            if header_analysis.get(
                "from_reply_to_domain_mismatch"
            )
            else "No"
        )

        st.markdown("**From / Return-Path mismatch**")
        st.write(
            "Yes"
            if header_analysis.get(
                "from_return_path_domain_mismatch"
            )
            else "No"
        )

        st.markdown("**Received headers**")
        st.write(
            header_analysis.get(
                "received_header_count",
                0,
            )
        )

        st.markdown("**Authentication-Results present**")
        st.write(
            "Yes"
            if header_analysis.get(
                "authentication_results_present"
            )
            else "No"
        )

    with col2:
        st.markdown("**SPF status**")
        display_list(
            header_analysis.get(
                "spf_statuses",
                [],
            )
        )

        st.markdown("**DKIM status**")
        display_list(
            header_analysis.get(
                "dkim_statuses",
                [],
            )
        )

        st.markdown("**DMARC status**")
        display_list(
            header_analysis.get(
                "dmarc_statuses",
                [],
            )
        )


def render_attachment_analysis(attachment_analysis):
    """Render attachment analysis results."""
    st.subheader("Attachment Analysis")

    attachment_count = attachment_analysis.get(
        "attachment_count",
        0,
    )

    if not attachment_count:
        st.info("No attachments were detected.")
        return

    st.write(f"Attachments analyzed: {attachment_count}")

    dangerous_extensions = attachment_analysis.get(
        "dangerous_extensions",
        [],
    )
    double_extensions = attachment_analysis.get(
        "double_extensions",
        [],
    )
    mime_mismatches = attachment_analysis.get(
        "mime_mismatches",
        [],
    )
    unusual_filenames = attachment_analysis.get(
        "unusual_filenames",
        [],
    )

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**Dangerous extensions**")
        display_list(dangerous_extensions)

        st.markdown("**Double extensions**")
        display_list(double_extensions)

    with col2:
        st.markdown("**MIME mismatches**")
        display_list(mime_mismatches)

        st.markdown("**Unusual filenames**")
        display_list(unusual_filenames)


def render_explainability(explainability):
    """Render deterministic explainability information."""
    st.subheader("Explainability")

    explanations = explainability.get(
        "explanations",
        [],
    )

    if not explanations:
        st.info("No explainability indicators were returned.")
        return

    for explanation in explanations:
        category = explanation.get(
            "category",
            "Analysis",
        )
        message = explanation.get(
            "message",
            "No explanation available.",
        )
        observations = explanation.get(
            "observations",
            [],
        )

        with st.expander(category):
            st.write(message)

            if observations:
                st.markdown("**Observations**")
                display_list(observations)


def render_pipeline_result(result):
    """Render the complete PipelineResult returned by FastAPI."""
    st.divider()
    st.header("Security Analysis Result")

    risk_score = result.get("risk_score", 0.0)
    ml_probability = result.get(
        "ml_phishing_probability",
        0.0,
    )

    score_col, probability_col = st.columns(2)

    with score_col:
        st.metric(
            "Risk Score",
            f"{risk_score:.1f} / 100",
        )

    with probability_col:
        st.metric(
            "ML Phishing Probability",
            f"{ml_probability * 100:.1f}%",
        )

    st.divider()

    render_email_information(
        result.get("email", {})
    )

    st.divider()

    render_rules(
        result.get("rule_results", [])
    )

    st.divider()

    render_urls(
        result.get("url_analyses", [])
    )

    st.divider()

    render_header_analysis(
        result.get("header_analysis", {})
    )

    st.divider()

    render_attachment_analysis(
        result.get("attachment_analysis", {})
    )

    st.divider()

    render_explainability(
        result.get("explainability", {})
    )

    st.divider()

    with st.expander("Raw API Response"):
        st.json(result)


def analyze_email(api_url, raw_email):
    """Send raw email to the FastAPI analysis endpoint."""
    if not api_url.strip():
        return None, "FastAPI Base URL cannot be empty."

    if not raw_email.strip():
        return None, "Please enter a raw email before analyzing."

    endpoint = f"{api_url.rstrip('/')}/analyze"

    try:
        response = requests.post(
            endpoint,
            json={"raw_email": raw_email},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except requests.exceptions.InvalidURL:
        return None, "The FastAPI Base URL is invalid."
    except requests.exceptions.Timeout:
        return None, (
            "The FastAPI backend did not respond within "
            f"{REQUEST_TIMEOUT_SECONDS} seconds."
        )
    except requests.exceptions.ConnectionError:
        return None, (
            "Unable to connect to the FastAPI backend. "
            "Please make sure the API is running."
        )
    except requests.RequestException as exc:
        return None, f"Unable to contact the FastAPI backend: {exc}"

    if not response.ok:
        try:
            error_payload = response.json()
        except ValueError:
            error_payload = {}

        error_detail = error_payload.get(
            "detail",
            response.text or "The API returned an error.",
        )

        return None, (
            f"Analysis failed (HTTP {response.status_code}): "
            f"{error_detail}"
        )

    try:
        result = response.json()
    except ValueError:
        return None, (
            "The FastAPI backend returned an invalid JSON response."
        )

    if not isinstance(result, dict):
        return None, (
            "The FastAPI backend returned an unexpected response format."
        )

    return result, None


st.title(
    "Explainable Suspicious Email & Phishing Detection System"
)

st.markdown(
    """
    Analyze suspicious and potentially phishing emails using the existing
    FastAPI detection backend.
    """
)

st.divider()

st.subheader("Email Analysis")

api_url = st.text_input(
    "FastAPI Base URL",
    value=DEFAULT_API_URL,
    help="URL where the FastAPI backend is running.",
)

raw_email = st.text_area(
    "Raw Email",
    height=350,
    placeholder=(
        "Paste a complete RFC 5322 email here, including headers and body..."
    ),
)

analyze_clicked = st.button(
    "Analyze Email",
    type="primary",
    use_container_width=True,
)

if analyze_clicked:
    pipeline_result, error_message = analyze_email(
        api_url,
        raw_email,
    )

    if error_message:
        st.error(error_message)
    else:
        st.session_state["pipeline_result"] = pipeline_result
        st.success("Email analysis completed successfully.")


if "pipeline_result" in st.session_state:
    render_pipeline_result(
        st.session_state["pipeline_result"]
    )