"""
file_parser.py
----------------
Extracts raw text from the three supported upload formats: PDF, TXT, CSV.
"""

import io
import csv
import pdfplumber


def parse_txt(file_bytes: bytes) -> str:
    return file_bytes.decode("utf-8", errors="ignore")


def parse_csv(file_bytes: bytes) -> str:
    text_stream = io.StringIO(file_bytes.decode("utf-8", errors="ignore"))
    reader = csv.reader(text_stream)
    lines = []
    for row in reader:
        lines.append(", ".join(row))
    return "\n".join(lines)


def parse_pdf(file_bytes: bytes) -> str:
    lines = []
    with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text() or ""
            lines.append(page_text)
    return "\n".join(lines)


def extract_text(filename: str, file_bytes: bytes) -> str:
    lower = filename.lower()
    if lower.endswith(".pdf"):
        return parse_pdf(file_bytes)
    if lower.endswith(".csv"):
        return parse_csv(file_bytes)
    if lower.endswith(".txt"):
        return parse_txt(file_bytes)
    raise ValueError(f"Unsupported file type: {filename}. Supported: .pdf, .txt, .csv")
