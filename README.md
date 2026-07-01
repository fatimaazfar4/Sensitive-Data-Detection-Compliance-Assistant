# Sensitive Data Detection & Compliance Assistant

This project is a Streamlit-based prototype that uploads PDF, TXT, and CSV files, detects sensitive and confidential information, classifies document risk, generates a compliance summary, and supports follow-up questions through a chat-style interface.

## Setup Instructions

### Prerequisites
- Python 3.10 or newer
- pip

### Local setup

```bash
git clone https://github.com/fatimaazfar4/Sensitive-Data-Detection-Compliance-Assistant.git
cd Sensitive-Data-Detection-Compliance-Assistant

python -m venv .venv
.venv\\Scripts\\activate      # On Windows
pip install -r requirements.txt
```

### Configure the optional AI layer

The app works without an API key using the built-in rule-based fallback. To enable Anthropic Claude-based summaries and Q&A, create a .env file in the project root with:

```env
ANTHROPIC_API_KEY=your_key_here
```

### Run the app

```bash
streamlit run app.py
```

Then open http://localhost:8501 or the port shown by Streamlit and upload the sample document from the sample_docs folder.

## Architecture Overview

The application follows a modular pipeline:

1. File parsing layer
   - Reads PDF, TXT, and CSV uploads
2. Detection layer
   - Uses regex and light validation logic to detect sensitive patterns
3. Risk layer
   - Aggregates findings into a document-level risk score
4. Summary and Q&A layer
   - Produces compliance summaries and answers questions with rule-based fallback or optional Claude API support
5. Redaction and audit layer
   - Supports redacted output and local audit logging

Core modules:
- app.py: Streamlit UI and workflow orchestration
- file_parser.py: File text extraction
- detector.py: Sensitive data detection
- risk.py: Risk classification logic
- summarizer.py: Summary and Q&A generation
- redact.py: Masking/redaction output
- audit_log.py: Local JSONL audit trail

## AI/ML Approach Used

The solution uses a hybrid approach:

- Rule-based detection for deterministic, auditable compliance checks
- Regex-based entity extraction with validation logic such as Luhn checks for card numbers
- Optional LLM support for natural-language summary and chat-style Q&A
- Fallback logic so the application remains useful even without an API key

This design is appropriate for compliance-focused tools because it avoids hallucinated facts and keeps the detection logic transparent and explainable.

## Challenges Faced

- Avoiding false positives in sensitive-data matching
- Distinguishing similar patterns such as Aadhaar numbers versus bank account numbers
- Keeping the AI layer privacy-safe by avoiding raw sensitive values in prompts
- Making the risk scoring explainable rather than relying on an opaque model

## Future Improvements

- OCR support for scanned PDFs
- Multi-document and batch upload support
- RAG-based retrieval for larger documents
- Better policy profiles for different compliance frameworks
- Deployment to cloud hosting for public demo access

## Working Prototype Deployment Link

Local prototype deployment:
- http://localhost:8502

This is the current working local prototype for the assignment demo.
