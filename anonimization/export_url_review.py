#!/usr/bin/env python3
"""Export URLs with query strings or fragments from an .eml dataset to CSV."""

import argparse
import csv
import email
import html
import re
from email import policy
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

URL_RE = re.compile(r"(?i)(?:https?://|www\.)[^\s<>\"']+")
SENSITIVE_KEY_RE = re.compile(
    r"email|token|user|recipient|subscriber|session|auth|nonce|client|uid|rid|sig|track|click|campaign|utm",
    re.IGNORECASE,
)
TRAILING_PUNCTUATION = ".,;:!?)]}"


def extract_urls(text: str):
    for match in URL_RE.finditer(html.unescape(text)):
        url = match.group(0).rstrip(TRAILING_PUNCTUATION)
        if url:
            yield url


def message_texts(message):
    for name, value in message.items():
        yield f"header:{name}", str(value)

    for index, part in enumerate(message.walk()):
        if part.get_content_maintype() != "text":
            continue
        if part.get_content_disposition() == "attachment":
            continue
        try:
            text = part.get_content()
        except (LookupError, UnicodeError):
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            try:
                text = payload.decode(charset, errors="replace")
            except LookupError:
                text = payload.decode("utf-8", errors="replace")
        if isinstance(text, str):
            yield f"part:{index}:{part.get_content_type()}", text


def export_urls(dataset_root: Path, output_path: Path, include_all: bool = False) -> int:
    rows = []
    for path in sorted(dataset_root.rglob("*.eml")):
        message = email.message_from_bytes(path.read_bytes(), policy=policy.default)
        seen = set()
        for location, text in message_texts(message):
            for url in extract_urls(text):
                if url in seen:
                    continue
                seen.add(url)
                parsed = urlsplit(url if "://" in url else f"https://{url}")
                if not include_all and not parsed.query and not parsed.fragment:
                    continue
                parameters = parse_qsl(parsed.query, keep_blank_values=True)
                keys = [key for key, _ in parameters]
                priority = any(SENSITIVE_KEY_RE.search(key) for key in keys)
                row = {
                    "file": path.relative_to(dataset_root).as_posix(),
                    "location": location,
                    "url": url,
                    "query_keys": "|".join(keys),
                    "priority_review": "yes" if priority else "no",
                }
                if include_all:
                    row["has_query"] = "yes" if parsed.query else "no"
                    row["has_fragment"] = "yes" if parsed.fragment else "no"
                rows.append(row)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8-sig", newline="") as csv_file:
        fields = ["file", "location", "url", "query_keys", "priority_review"]
        if include_all:
            fields.extend(["has_query", "has_fragment"])
        writer = csv.DictWriter(csv_file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset_root", type=Path, help="Root directory containing .eml files")
    parser.add_argument("output_csv", type=Path, help="CSV file to create for manual review")
    parser.add_argument(
        "--all-urls",
        action="store_true",
        help="Export URLs without query strings or fragments too",
    )
    args = parser.parse_args()

    count = export_urls(args.dataset_root, args.output_csv, include_all=args.all_urls)
    print(f"Exported {count} URL records to {args.output_csv}")
    print("No URLs were opened or requested.")


if __name__ == "__main__":
    main()
