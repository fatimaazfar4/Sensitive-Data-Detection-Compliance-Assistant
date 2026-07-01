"""
app.py
-------
Streamlit UI for the Sensitive Data Detection & Compliance Assistant.

Run with:  streamlit run app.py
"""

import os
import pandas as pd
import streamlit as st

try:
    from dotenv import load_dotenv
    load_dotenv()  # reads .env in the project root, if present, into os.environ
except ImportError:
    pass  # python-dotenv not installed — fine, user can still export the var manually

from file_parser import extract_text
from detector import detect, summarize_counts
from risk import classify
from summarizer import generate_summary, answer_question
from redact import redact_text
from audit_log import log_event, read_log

st.set_page_config(page_title="Sensitive Data Compliance Assistant", page_icon="🛡️", layout="wide")

RISK_COLORS = {"Low Risk": "🟢", "Medium Risk": "🟡", "High Risk": "🔴"}

# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------
if "results" not in st.session_state:
    st.session_state.results = None  # dict: filename, text, findings, risk_info
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.title("🛡️ Compliance Assistant")
    st.caption("Sensitive Data Detection & Compliance Assistant")

    api_key_present = bool(os.environ.get("ANTHROPIC_API_KEY"))
    if api_key_present:
        st.success("AI mode: Claude API connected")
    else:
        st.warning("AI mode: OFF (no ANTHROPIC_API_KEY set)\n\nRunning in rule-based fallback mode — "
                    "detection, risk scoring, summaries and Q&A all still work, "
                    "just using templates instead of an LLM.")

    st.divider()
    st.markdown("**Supported formats:** PDF, TXT, CSV")
    st.markdown("**Detected categories:**")
    st.markdown(
        "- Aadhaar / PAN Numbers\n"
        "- Email & Phone\n"
        "- Credit Card & Bank Details\n"
        "- API Keys / Passwords\n"
        "- Employee IDs\n"
        "- Confidential Business Markers"
    )

    st.divider()
    with st.expander("📜 Audit Log (last 20 events)"):
        for entry in reversed(read_log(20)):
            st.text(f"{entry['timestamp'][:19]} — {entry['event']} — {entry.get('filename','')}")

# ---------------------------------------------------------------------------
# Main: upload
# ---------------------------------------------------------------------------
st.title("Sensitive Data Detection & Compliance Assistant")
st.write("Upload a document to scan it for sensitive/confidential data, get a risk classification, "
         "an AI-generated compliance summary, and ask follow-up questions.")

uploaded = st.file_uploader("Upload a document (PDF, TXT, or CSV)", type=["pdf", "txt", "csv"])

if uploaded is not None:
    file_bytes = uploaded.read()
    if st.session_state.results is None or st.session_state.results.get("filename") != uploaded.name:
        with st.spinner("Extracting text and scanning for sensitive data..."):
            try:
                text = extract_text(uploaded.name, file_bytes)
            except Exception as e:
                st.error(f"Could not read file: {e}")
                st.stop()

            findings = detect(text)
            risk_info = classify(findings)

            st.session_state.results = {
                "filename": uploaded.name,
                "text": text,
                "findings": findings,
                "risk_info": risk_info,
                "summary": None,
            }
            st.session_state.chat_history = []
            log_event("scan", {
                "filename": uploaded.name,
                "findings_count": len(findings),
                "risk_level": risk_info["level"],
            })

if st.session_state.results is not None:
    res = st.session_state.results
    findings = res["findings"]
    risk_info = res["risk_info"]

    st.divider()

    # --- Risk banner -------------------------------------------------
    col1, col2, col3 = st.columns(3)
    col1.metric("Sensitive items found", len(findings))
    col2.metric("Risk classification", f"{RISK_COLORS[risk_info['level']]} {risk_info['level']}")
    col3.metric("Sensitivity score", risk_info["score"])

    tabs = st.tabs(["🔍 Detected Data", "📄 Compliance Summary", "🕶️ Redacted View", "💬 Ask Questions"])

    # --- Tab 1: Detected data ----------------------------------------
    with tabs[0]:
        if not findings:
            st.info("No sensitive data patterns were detected in this document.")
        else:
            counts = summarize_counts(findings)
            st.subheader("Summary by category")
            st.bar_chart(pd.DataFrame.from_dict(counts, orient="index", columns=["Count"]))

            st.subheader("Detailed findings (values masked)")
            df = pd.DataFrame(
                [
                    {"Category": f.category, "Masked Value": f.masked_value, "Risk": f.risk, "Line": f.line_no}
                    for f in findings
                ]
            )
            st.dataframe(df, use_container_width=True, hide_index=True)

    # --- Tab 2: Compliance summary -------------------------------------
    with tabs[1]:
        if res["summary"] is None:
            with st.spinner("Generating compliance summary..."):
                res["summary"] = generate_summary(findings, risk_info, res["filename"])
        st.markdown(res["summary"])
        st.caption(f"Risk rationale: {risk_info['rationale']}")

    # --- Tab 3: Redacted view -------------------------------------------
    with tabs[2]:
        mode = st.radio("Redaction mode", ["mask", "tag"], horizontal=True,
                         format_func=lambda x: "Partial mask (****1234)" if x == "mask" else "Full tag ([REDACTED: Category])")
        redacted = redact_text(res["text"], findings, mode=mode)
        st.text_area("Redacted document", redacted, height=400)
        st.download_button("Download redacted text", redacted, file_name=f"redacted_{res['filename']}.txt")

    # --- Tab 4: Q&A -------------------------------------------------------
    with tabs[3]:
        st.write("Ask things like: *What sensitive data exists in the document?*, "
                 "*How many email addresses are present?*, *Summarize this document.*, "
                 "*What compliance risks are identified?*")

        for role, msg in st.session_state.chat_history:
            with st.chat_message(role):
                st.markdown(msg)

        question = st.chat_input("Ask a question about this document...")
        if question:
            st.session_state.chat_history.append(("user", question))
            with st.chat_message("user"):
                st.markdown(question)
            with st.chat_message("assistant"):
                with st.spinner("Thinking..."):
                    answer = answer_question(question, findings, risk_info, res["filename"], res["text"])
                st.markdown(answer)
            st.session_state.chat_history.append(("assistant", answer))
            log_event("question", {"filename": res["filename"], "question": question})
else:
    st.info("👆 Upload a PDF, TXT, or CSV file to get started.")
