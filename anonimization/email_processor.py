import sys
import re
import quopri
import base64
import html
import ipaddress
from email.header import decode_header
from pathlib import Path


class EmailProcessor:
    HEADER_LINE_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9-]*:')
    
    ## Whitelisted headers (exact matches)
    EXACT_HEADERS = {
        'return-path', 'delivered-to', 'from', 'to', 'subject', 'cc', 'bcc',
        'content-type', 'date', 'reply-to', 'user-agent',
        'content-language', 'organization', 'authentication-results',
        'mime-version', 'content-transfer-encoding',
        'received-spf', 'content-disposition',
    }
    
    ## Whitelisted header prefixes
    PREFIX_HEADERS = {
        'x-spam',
        'spam',
        'dkim',
        'arc',
        'list',
    }

    def _decode_header(self, header_value: str) -> str:
        if not header_value:
            return header_value
        
        decoded_parts = []
        for decoded_bytes, charset in decode_header(header_value):
            if isinstance(decoded_bytes, bytes):
                try:
                    decoded_str = decoded_bytes.decode(charset or 'utf-8', errors='ignore')
                except (LookupError, AttributeError):
                    decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                decoded_parts.append(decoded_str)
            else:
                decoded_parts.append(str(decoded_bytes))
        
        return ''.join(decoded_parts)
    
    def _replace_ips(self, text: str) -> str:
        def replace_ip(match):
            token = match.group(0)
            candidate = token.strip('[](){}<>,;"\'')

            try:
                parsed = ipaddress.ip_address(candidate)
                if parsed.version == 4:
                    return '1.2.3.4'
                return '1:2:3:4:5:6:7:8'
            except ValueError:
                return token

        ip_pattern = r'\b(?:\d{1,3}(?:\.\d{1,3}){3}|(?:[0-9A-Fa-f:]{2,}))\b'
        text = re.sub(ip_pattern, replace_ip, text)

        return text

    def _truncate_urls(self, text: str) -> str:
        # URLs are intentionally preserved in full form.
        return text
        

    def _is_header_whitelisted(self, header_name: str) -> bool:
        lower_name = header_name.lower()
        
        if lower_name in self.EXACT_HEADERS:
            return True
        
        for prefix in self.PREFIX_HEADERS:
            if lower_name.startswith(prefix):
                return True
        
        return False
    
    def _process_header_value(self, header_value: str) -> str:
        header_value = self._decode_header(header_value)
        header_value = self._replace_ips(header_value)
        return self._truncate_urls(header_value)
    
    def _extract_charset(self, content_type_header: str) -> str:
        if not content_type_header:
            return 'utf-8'  # Default
        
        # Look for charset parameter
        match = re.search(r'charset\s*=\s*["\']?([^\s;"\'\']+)', content_type_header, re.IGNORECASE)
        if match:
            charset = match.group(1).strip()
            return charset
        return 'utf-8'  # Default

    def _extract_header_value(self, headers_section: str, header_name: str) -> str:
        lines = headers_section.split('\n')
        target = header_name.lower()
        current_name = None
        values = {}

        for line in lines:
            if not line:
                continue
            if line[0] in ' \t' and current_name is not None:
                values[current_name] = values[current_name] + ' ' + line.strip()
                continue
            if ':' not in line:
                current_name = None
                continue
            name, value = line.split(':', 1)
            current_name = name.strip().lower()
            values[current_name] = value.strip()

        return values.get(target, '')

    def _extract_boundary(self, content_type_header: str) -> str:
        if not content_type_header:
            return ''

        match = re.search(
            r"boundary\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^\s;]+))",
            content_type_header,
            re.IGNORECASE,
        )
        if not match:
            return ''

        return match.group(1) or match.group(2) or match.group(3) or ''
    
    def _decode_content(self, content: str, encoding: str, charset: str = 'utf-8', decode_entities: bool = True) -> str:
        if not encoding:
            return content
        
        encoding = encoding.lower().strip()
        charset = charset.lower().strip()
        
        # Handle common charset aliases (only actual aliases, not identity mappings)
        charset_map = {
            'utf8': 'utf-8',
            'iso-8859-1': 'latin-1',
            'windows-1250': 'cp1250',
            'windows-1252': 'cp1252',
        }
        charset = charset_map.get(charset, charset)
        
        if encoding == 'quoted-printable':
            try:
                # For quoted-printable, we need to decode the QP encoding first
                # QP uses ASCII representation, so we encode as latin-1 (safe for all bytes)
                decoded_bytes = quopri.decodestring(content.encode('latin-1'))
                # Now decode using the actual charset (with fallback to utf-8)
                try:
                    decoded_text = decoded_bytes.decode(charset, errors='replace')
                except (LookupError, UnicodeDecodeError):
                    decoded_text = decoded_bytes.decode('utf-8', errors='replace')
                if decode_entities:
                    return html.unescape(decoded_text)
                return decoded_text
            except Exception:
                return content
        elif encoding == 'base64':
            try:
                # Remove whitespace and decode
                cleaned = re.sub(r'\s+', '', content)
                if not cleaned:
                    return content

                padding = len(cleaned) % 4
                if padding:
                    cleaned += '=' * (4 - padding)

                try:
                    decoded_bytes = base64.b64decode(cleaned, validate=False)
                except Exception:
                    decoded_bytes = base64.urlsafe_b64decode(cleaned)
                # Decode using the specified charset (with fallback to utf-8)
                try:
                    decoded_text = decoded_bytes.decode(charset, errors='replace')
                except (LookupError, UnicodeDecodeError):
                    decoded_text = decoded_bytes.decode('utf-8', errors='replace')
                if decode_entities:
                    return html.unescape(decoded_text)
                return decoded_text
            except Exception:
                return content
        else:
            # 7bit, 8bit, binary, or unknown - return as-is
            return content

    def _is_textual_content_type(self, content_type: str) -> bool:
        lower_type = (content_type or '').lower()
        if not lower_type:
            return True

        if lower_type.startswith('text/'):
            return True

        return lower_type.startswith('message/')
    
    def _process_part(self, part_text: str) -> str:
        headers_section, body_section = self._split_headers_body(part_text)

        content_type = self._extract_header_value(headers_section, 'content-type')
        content_encoding = self._extract_header_value(headers_section, 'content-transfer-encoding')
        content_disposition = self._extract_header_value(headers_section, 'content-disposition')

        lower_type = content_type.lower()
        lower_disposition = content_disposition.lower()

        if 'multipart/' in lower_type:
            boundary = self._extract_boundary(content_type)
            if boundary:
                processed_body = self._process_multipart_body(body_section, boundary)
            else:
                processed_body = body_section
        else:
            if 'attachment' in lower_disposition:
                processed_body = '[ATTACHMENT CONTENT REMOVED]\n'
            elif 'image/' in lower_type:
                processed_body = body_section
            elif not self._is_textual_content_type(content_type):
                processed_body = body_section
            else:
                charset = self._extract_charset(content_type)
                processed_body = body_section
                if content_encoding:
                    decode_entities = 'text/html' not in lower_type
                    processed_body = self._decode_content(processed_body, content_encoding, charset, decode_entities=decode_entities)
                processed_body = self._replace_ips(processed_body)
                processed_body = self._truncate_urls(processed_body)

        if processed_body:
            return f"{headers_section}\n\n{processed_body}"
        return headers_section

    def _process_multipart_body(self, body_section: str, boundary: str) -> str:
        lines = body_section.split('\n')
        marker = f'--{boundary}'
        closing_marker = f'--{boundary}--'

        result_lines = []
        i = 0

        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            if stripped == marker or stripped == closing_marker:
                # MIME boundary delimiters must stay byte-for-byte intact.
                result_lines.append(line)
                i += 1

                if stripped == closing_marker:
                    while i < len(lines):
                        result_lines.append(lines[i])
                        i += 1
                    break

                part_start = i
                while i < len(lines) and lines[i].strip() not in (marker, closing_marker):
                    i += 1

                part_text = '\n'.join(lines[part_start:i])
                if part_text.strip():
                    result_lines.append(self._process_part(part_text))
                else:
                    result_lines.append(part_text)
                continue

            result_lines.append(self._replace_ips(line))
            i += 1

        return '\n'.join(result_lines)

    def _split_headers_body(self, email_content: str):
        normalized = email_content.replace('\r\n', '\n').replace('\r', '\n')
        header_end = normalized.find('\n\n')
        if header_end == -1:
            return normalized, ''
        return normalized[:header_end], normalized[header_end + 2:]

    def _decode_body(self, headers_section: str, body_section: str) -> str:
        main_content_type = self._extract_header_value(headers_section, 'content-type')
        main_content_encoding = self._extract_header_value(headers_section, 'content-transfer-encoding')
        is_textual = self._is_textual_content_type(main_content_type or '')
        is_multipart = 'multipart/' in main_content_type.lower() if main_content_type else False

        if is_multipart:
            boundary = self._extract_boundary(main_content_type)
            if boundary:
                return self._process_multipart_body(body_section, boundary)
            return body_section

        processed_body = body_section
        if main_content_encoding and is_textual:
            charset = self._extract_charset(main_content_type) if main_content_type else 'utf-8'
            decode_entities = 'text/html' not in (main_content_type or '').lower()
            processed_body = self._decode_content(processed_body, main_content_encoding, charset, decode_entities=decode_entities)

        if is_textual:
            processed_body = self._replace_ips(processed_body)
            return self._truncate_urls(processed_body)

        return processed_body

    def _whitelist_header_block(self, block_text: str) -> str:
        lines = block_text.replace('\r\n', '\n').replace('\r', '\n').split('\n')
        result_lines = []
        i = 0

        while i < len(lines):
            line = lines[i]

            if self.HEADER_LINE_RE.match(line):
                header_lines = [line]
                i += 1

                while i < len(lines) and lines[i] and lines[i][0] in ' \t':
                    header_lines.append(lines[i])
                    i += 1

                header_name = line.split(':', 1)[0]
                if self._is_header_whitelisted(header_name):
                    full_header_text = '\n'.join(header_lines)
                    colon_pos = full_header_text.find(':')
                    if colon_pos != -1:
                        header_value = full_header_text[colon_pos + 1:]
                        processed_value = self._process_header_value(header_value)
                        result_lines.append(f"{header_name}:{processed_value}")
                continue

            # Drop orphan continuation lines inside a header block.
            if line and line[0] in ' \t':
                i += 1
                continue

            i += 1

        return '\n'.join(result_lines)

    def _looks_like_forwarded_header_block(self, block_lines: list[str]) -> bool:
        header_names = []
        for line in block_lines:
            if not self.HEADER_LINE_RE.match(line):
                return False
            header_names.append(line.split(':', 1)[0].strip().lower())

        if len(header_names) < 2:
            return False

        strong_headers = {
            'from', 'to', 'subject', 'date', 'return-path', 'delivered-to',
            'content-type', 'mime-version', 'received', 'reply-to'
        }
        return any(name in strong_headers for name in header_names)

    def _whitelist_forwarded_header_blocks(self, body: str) -> str:
        if not body:
            return body

        lines = body.replace('\r\n', '\n').replace('\r', '\n').split('\n')
        result = []
        i = 0

        while i < len(lines):
            line = lines[i]
            if not self.HEADER_LINE_RE.match(line):
                result.append(line)
                i += 1
                continue

            start = i
            block_lines = []
            while i < len(lines) and lines[i].strip() != '':
                if lines[i] and lines[i][0] in ' \t':
                    block_lines.append(lines[i])
                    i += 1
                    continue
                if self.HEADER_LINE_RE.match(lines[i]):
                    block_lines.append(lines[i])
                    i += 1
                    continue
                break

            if self._looks_like_forwarded_header_block([l for l in block_lines if l and l[0] not in ' \t']):
                cleaned_block = self._whitelist_header_block('\n'.join(block_lines))
                if cleaned_block:
                    result.extend(cleaned_block.split('\n'))
            else:
                result.extend(lines[start:i])

            if i < len(lines) and lines[i].strip() == '':
                result.append(lines[i])
                i += 1

        return '\n'.join(result)
    
    def process_email(self, email_path: str) -> str:

        try:
            with open(email_path, 'r', encoding='utf-8', errors='ignore') as f:
                email_content = f.read()

            headers_section, body_section = self._split_headers_body(email_content)

            ## 1) Always decode body first
            processed_body = self._decode_body(headers_section, body_section)
            processed_body = self._whitelist_forwarded_header_blocks(processed_body)

            ## 2) Whitelist top-level MIME headers only
            whitelisted_headers = self._whitelist_header_block(headers_section)

            ## 3) Reconstruct with exactly one empty line between headers and body
            if processed_body:
                cleaned_body = processed_body.lstrip('\n')
                return f"{whitelisted_headers}\n\n{cleaned_body}"
            return whitelisted_headers
            
        except Exception as e:
            print(f"Error processing {email_path}: {e}")
            raise


def main():
    args = sys.argv[1:]

    if len(args) < 2:
        print("Usage: python email_processor.py <input_dir1> [<input_dir2> ...] <output_dir>")
        sys.exit(1)

    input_dirs = [Path(d) for d in args[:-1]]
    output_dir = Path(args[-1])

    for input_dir in input_dirs:
        if not input_dir.exists() or not input_dir.is_dir():
            print(f"Error: Input directory does not exist: {input_dir}")
            sys.exit(1)

    output_dir.mkdir(parents=True, exist_ok=True)
    
    processor = EmailProcessor()
    total_processed = 0
    total_errors = 0
    
    for input_dir in input_dirs:
        eml_files = list(input_dir.glob('*.eml'))
        
        for eml_file in eml_files:
            try:
                processed_content = processor.process_email(str(eml_file))
                
                output_file = output_dir / eml_file.name
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(processed_content)
                
                total_processed += 1
                if total_processed % 100 == 0:
                    print(f"Processed {total_processed} files")
                    
            except Exception as e:
                print(f"Error processing {eml_file.name}: {e}")
                total_errors += 1
    
    print(f"\n{'='*50}")
    print(f"Processing complete!")
    print(f"Total files processed: {total_processed}")
    print(f"Total errors: {total_errors}")
    print(f"Output directory: {output_dir}")
    print(f"{'='*50}")


if __name__ == '__main__':
    main()
