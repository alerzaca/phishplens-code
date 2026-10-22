# phishplens-code

Code supporting the **PhishPLENS** dataset (Polish–English phishing email corpus). It contains the preprocessing and pseudonymization scripts described in the *Preprocessing and pseudonymization* section of the paper. Python 3.9+, standard library only.

## Contents (`anonimization/`)

| File | Purpose |
|---|---|
| `email_processor.py` | Stage 1: decodes text content (Content-Type / Content-Transfer-Encoding), keeps only whitelisted headers (exact and prefix matches), replaces IPv4/IPv6 addresses with `1.2.3.4` / `1:2:3:4:5:6:7:8`, removes attachment payloads (replaced by `[ATTACHMENT CONTENT REMOVED]`). |
| `email_recipient_anonymizer.py` | Stage 2: replaces names and email addresses with fictional identities (surname suffix `ano`, handle = first letter of first name + surname), consistent within a single file. |
| `email_header_utils.py` | Header-parsing helpers used by stage 2. |
| `email_processing_pipeline.py` | Runs the full pipeline (stage 1 → stage 2) on a directory of `.eml` files. |
| `export_url_review.py` | Exports URLs with query strings/fragments to CSV for manual review during URL sanitization (no URL is opened). |

## Usage

```bash
python anonimization/email_processing_pipeline.py [--include-gmail] <input_dir> <output_dir>
python anonimization/export_url_review.py <dataset_dir> urls_for_review.csv
```

## Not automated

URL sanitization, phone numbers, physical addresses, and embedded images were handled or verified manually and are not covered by these scripts.
