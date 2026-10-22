import re
import sys
import random
from pathlib import Path
from typing import Dict, Iterable, Set, Tuple
from email.utils import getaddresses

from email_header_utils import is_agh_email

## Names for anonymization, most popular only, mostly Polish but mixed up with common English ones
FIRST_NAMES = [
    "Jan", "Piotr", "Andrzej", "Tomasz", "Krzysztof", "Marek", "Michal",
    "Pawel", "Wojciech", "Jakub", "Lukasz", "Kamil", "Marcin", "Adam",
    "Anna", "Maria", "Katarzyna", "Agnieszka", "Ewa", "Zofia",
    "Magdalena", "Monika", "Aleksandra", "Malgorzata",
    "John", "James", "Michael", "David", "Robert",
    "Mary", "Jennifer", "Sarah", "Lisa"
]

LAST_NAMES = [
    "Nowak", "Kowalski", "Wisniewski", "Lewandowski", "Wojcik",
    "Kaminski", "Kowalczyk", "Zielinski", "Szymanski", "Wozniak",
    "Jankowski", "Mazur", "Kwiatkowski", "Krawczyk", "Piotrowski",
    "Nowakowski", "Michalski", "Adamczyk", "Witkowski",
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Miller"
]

## Recipient headers to anonymize
RECIPIENT_HEADERS = ['delivered-to', 'to', 'cc', 'bcc']

## Sender headers to extract sender addresses from
SENDER_HEADERS = ['return-path', 'from', 'sender']

## Placeholder patterns that should always be anonymized (from previous processing)
PLACEHOLDER_PATTERNS = ['anonimized', 'anonymized', 'anonymyzed']

## Generic greeting targets that are not personal identities
GENERIC_GREETING_WORDS = {
    'customer', 'client', 'user', 'sir', 'madam', 'team', 'friend', 'colleague',
    'beneficiary', 'winner', 'uzytkowniku', 'użytkowniku', 'kliencie', 'klient',
    'administrator', 'admin', 'member'
}

class RecipientAnonymizer:
    def __init__(self, extra_domains: Iterable[str] = ()):
        normalized: Set[str] = set()
        for domain in extra_domains:
            cleaned = (domain or '').strip().lower().strip('.')
            if cleaned:
                normalized.add(cleaned)
        self.extra_domains = normalized

    def _is_extra_domain_email(self, email: str) -> bool:
        if '@' not in email:
            return False
        domain = email.rsplit('@', 1)[1].lower().strip('.')
        return domain in self.extra_domains

    def should_anonymize_email(self, email: str) -> bool:
        return self.is_agh_email(email) or self._is_extra_domain_email(email)

    def is_agh_email(self, email: str) -> bool:
        return is_agh_email(email)
    
    def extract_email_from_header(self, field_value: str) -> str:
        field_value = field_value.strip()

        addresses = getaddresses([field_value])
        for _, email in addresses:
            if email:
                return email.lower()
        
        ## Pattern: Name <email@example.com> or "Name" <email@example.com>
        match = re.search(r'<([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})>', field_value, re.IGNORECASE)
        if match:
            return match.group(1).lower()
        
        ## Just email address
        match = re.match(r'^([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})$', field_value, re.IGNORECASE)
        if match:
            return match.group(1).lower()
        
        return ''
    
    def parse_name_parts(self, full_name: str) -> Tuple[str, str]:
        if not full_name:
            return ('', '')
        
        parts = full_name.split()
        if len(parts) == 0:
            return ('', '')
        elif len(parts) == 1:
            return (parts[0], '')
        else:
            ## First word is first name, last word is last name
            return (parts[0], parts[-1])
    
    def generate_anonymous_identity(self, used_names: set, used_email_locals: set) -> Tuple[str, str]:
        max_attempts = 1000
        for _ in range(max_attempts):
            first_name = random.choice(FIRST_NAMES)
            last_name = random.choice(LAST_NAMES)
            full_name = f"{first_name} {last_name}ano"
            email_local = f"{first_name[0].lower()}{last_name.lower()}ano"
            
            if full_name not in used_names and email_local not in used_email_locals:
                used_names.add(full_name)
                used_email_locals.add(email_local)
                return (full_name, email_local)
        
        ## If we somehow exhausted all combinations (very unlikely)
        raise RuntimeError(f"Could not generate unique identity after {max_attempts} attempts. "
                         f"Already used {len(used_names)} identities in this email.")
    
    def is_placeholder_email(self, email: str) -> bool:
        email_lower = email.lower()
        return any(pattern in email_lower for pattern in PLACEHOLDER_PATTERNS)
    
    def anonymize_single_recipient(self, recipient: str, email_to_identity: Dict[str, Tuple[str, str]], 
                                   used_names: set, sender_emails: set, used_email_locals: set,
                                   create_missing: bool = True) -> str:
        email = self.extract_email_from_header(recipient)
        
        if not email:
            return recipient.strip()
        
        email = email.lower()
        
        ## ONLY anonymize if it's supported domain OR a placeholder pattern
        is_placeholder = self.is_placeholder_email(email)
        is_target_domain = self.should_anonymize_email(email)
        
        if not is_target_domain and not is_placeholder:
            ## Not target domain - leave as-is
            return recipient.strip()
        
        ## Don't anonymize if this is a sender's email address (attacker, not victim)
        ## Exception: always anonymize placeholder emails
        if not is_placeholder and email in sender_emails:
            return recipient.strip()
        
        ## Get or create anonymous identity
        if email in email_to_identity:
            anon_name, anon_local = email_to_identity[email]
        else:
            if not create_missing:
                return recipient.strip()
            anon_name, anon_local = self.generate_anonymous_identity(used_names, used_email_locals)
            email_to_identity[email] = (anon_name, anon_local)
        
        ## Extract domain
        domain = email.split('@')[1]
        anon_email = f"{anon_local}@{domain}"
        
        ## Check if original has name attached
        if '<' in recipient:
            return f"{anon_name} <{anon_email}>"
        else:
            return anon_email
    
    def _extract_all_emails(self, text: str) -> list:
        if not text:
            return []
        return [e.lower() for e in re.findall(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', text)]

    def _collect_header_discovery_data(self, current_header_name: str, current_header_lines: list,
                                       sender_emails: set, email_to_real_name: Dict[str, str],
                                       candidate_emails: set):
        if not current_header_name or not current_header_lines:
            return

        if current_header_name in SENDER_HEADERS:
            self._extract_sender_emails(current_header_lines, sender_emails)
            return

        full_header = '\n'.join(current_header_lines)
        colon_pos = full_header.find(':')
        if colon_pos == -1:
            return

        header_value = full_header[colon_pos + 1:]

        if current_header_name in RECIPIENT_HEADERS:
            self.extract_recipient_identities(header_value, email_to_real_name, sender_emails)
            candidate_emails.update(self.extract_candidate_emails_from_text(header_value, sender_emails))
            return

        if current_header_name == 'return-path':
            bounce_email = self.extract_bounce_recipient_email(header_value.strip())
            if bounce_email:
                is_placeholder = self.is_placeholder_email(bounce_email)
                if is_placeholder or (self.should_anonymize_email(bounce_email) and bounce_email not in sender_emails):
                    candidate_emails.add(bounce_email)

    def extract_candidate_emails_from_text(self, text: str, sender_emails: set) -> set:
        candidates = set()
        for email in self._extract_all_emails(text):
            is_placeholder = self.is_placeholder_email(email)
            is_target_domain = self.should_anonymize_email(email)
            if not is_target_domain and not is_placeholder:
                continue
            if not is_placeholder and email in sender_emails:
                continue
            candidates.add(email)
        return candidates

    def _select_primary_recipient_identity(self, lines: list, email_to_identity: Dict[str, Tuple[str, str]],
                                           sender_emails: set) -> Tuple[str, str]:
        header_entries = []
        current_header_name = None
        current_header_lines = []

        for line in lines:
            if line.strip() == '':
                break

            if line and line[0] in ' \t':
                if current_header_lines:
                    current_header_lines.append(line)
                continue

            if current_header_name and current_header_lines:
                full_header = '\n'.join(current_header_lines)
                colon_pos = full_header.find(':')
                if colon_pos != -1:
                    header_entries.append((current_header_name, full_header[colon_pos + 1:]))

            if ':' in line:
                current_header_name = line.split(':', 1)[0].strip().lower()
                current_header_lines = [line]
            else:
                current_header_name = None
                current_header_lines = []

        if current_header_name and current_header_lines:
            full_header = '\n'.join(current_header_lines)
            colon_pos = full_header.find(':')
            if colon_pos != -1:
                header_entries.append((current_header_name, full_header[colon_pos + 1:]))

        for preferred_header in ['delivered-to', 'to', 'cc', 'bcc']:
            for header_name, header_value in header_entries:
                if header_name != preferred_header:
                    continue

                for email in self._extract_all_emails(header_value):
                    is_placeholder = self.is_placeholder_email(email)
                    is_target_domain = self.should_anonymize_email(email)

                    if not is_target_domain and not is_placeholder:
                        continue

                    if not is_placeholder and email in sender_emails:
                        continue

                    if email in email_to_identity:
                        return email_to_identity[email]

        return ('', '')

    def _anonymize_body_salutations(self, body_text: str, primary_fake_name: str) -> str:
        if not body_text or not primary_fake_name:
            return body_text

        salutation_re = re.compile(
            r'(?P<prefix>\b(?:Dear|Hello|Hi|Witaj|Cześć|Czesc|Szanowny|Szanowna)\s+)'
            r'(?P<token>[A-Za-zĄąĆćĘęŁłŃńÓóŚśŹźŻż][A-Za-zĄąĆćĘęŁłŃńÓóŚśŹźŻż\-]{1,40})'
            r'(?P<suffix>\s*(?:,|!|\.|:)?(?:<br\s*/?>)?)',
            re.IGNORECASE
        )

        def replace_salutation(match):
            token = match.group('token')
            token_norm = token.strip().lower()

            if token_norm in GENERIC_GREETING_WORDS:
                return match.group(0)

            if token_norm.endswith('ano') or '@' in token_norm:
                return match.group(0)

            if len(token_norm) < 3:
                return match.group(0)

            return f"{match.group('prefix')}{primary_fake_name}{match.group('suffix')}"

        return salutation_re.sub(replace_salutation, body_text)
    
    def extract_recipient_identities(self, field_value: str, email_to_real_name: Dict[str, str], sender_emails: set):
        recipients = getaddresses([field_value])

        for name, email in recipients:
            if not email:
                continue
            
            email = email.lower()
            
            ## Only process target-domain emails or placeholders
            is_placeholder = self.is_placeholder_email(email)
            is_target_domain = self.should_anonymize_email(email)
            
            if not is_target_domain and not is_placeholder:
                continue
            
            ## Don't process sender emails (unless placeholder)
            if not is_placeholder and email in sender_emails:
                continue
            
            if name:
                email_to_real_name[email] = name.strip().strip('"\'')
    
    def anonymize_recipient_header(self, field_value: str, email_to_identity: Dict[str, Tuple[str, str]], 
                                   used_names: set, sender_emails: set, used_email_locals: set,
                                   create_missing: bool = True) -> str:
        recipients = getaddresses([field_value])
        if not recipients:
            return field_value.strip()

        anonymized_recipients = []
        for display_name, email in recipients:
            recipient_repr = f"{display_name} <{email}>" if display_name and email else (email or display_name)
            if recipient_repr:
                anonymized = self.anonymize_single_recipient(
                    recipient_repr,
                    email_to_identity,
                    used_names,
                    sender_emails,
                    used_email_locals,
                    create_missing=create_missing,
                )
                anonymized_recipients.append(anonymized)

        return ', '.join(anonymized_recipients)
    
    def build_replacement_map(self, email_to_identity: Dict[str, Tuple[str, str]], 
                             email_to_real_name: Dict[str, str]) -> Dict[str, str]:
        replacements = {}
        
        for real_email, (fake_full_name, fake_local) in email_to_identity.items():
            ## Extract parts from real email
            real_local = real_email.split('@')[0]
            domain = real_email.split('@')[1]
            fake_email = f"{fake_local}@{domain}"
            
            ## 1. Full email address (most specific - do first)
            replacements[real_email] = fake_email
            ## Case variations
            replacements[real_email.upper()] = fake_email.upper()
            replacements[real_email.lower()] = fake_email
            replacements[real_email.capitalize()] = fake_email
            
            ## Also add common formatting prefixes (_, *, -, .) that might appear in email body
            for prefix in ['_', '*', '-', '.']:
                prefixed_email = f"{prefix}{real_email}"
                prefixed_fake = f"{prefix}{fake_email}"
                replacements[prefixed_email] = prefixed_fake
                replacements[prefixed_email.upper()] = prefixed_fake.upper()
                replacements[prefixed_email.lower()] = prefixed_fake.lower()
            
            ## 2. Real name from header (if we extracted one)
            if real_email in email_to_real_name:
                real_full_name = email_to_real_name[real_email]
                real_first, real_last = self.parse_name_parts(real_full_name)
                fake_first, fake_last = self.parse_name_parts(fake_full_name)
                
                ## Full name replacements
                if real_full_name:
                    replacements[real_full_name] = fake_full_name
                    ## Case variations
                    replacements[real_full_name.upper()] = fake_full_name.upper()
                    replacements[real_full_name.lower()] = fake_full_name.lower()
                
                ## Last name alone (careful - only if not too short)
                if real_last and len(real_last) > 3:
                    replacements[real_last] = fake_last
                    replacements[real_last.upper()] = fake_last.upper()
                    replacements[real_last.lower()] = fake_last.lower()
                    replacements[real_last.capitalize()] = fake_last.capitalize()
                
                ## First name alone (only if not too common/short)
                if real_first and len(real_first) > 4:
                    replacements[real_first] = fake_first
                    replacements[real_first.upper()] = fake_first.upper()
                    replacements[real_first.lower()] = fake_first.lower()
                    replacements[real_first.capitalize()] = fake_first.capitalize()
            
            ## 3. Email local part (username) - only if not too short
            if len(real_local) > 4:
                replacements[real_local] = fake_local
                replacements[real_local.upper()] = fake_local.upper()
                replacements[real_local.lower()] = fake_local.lower()
        
        return replacements
    
    def anonymize_body(self, body_text: str, replacements: Dict[str, str]) -> str:
        ## Sort by length (descending) to replace longer patterns first
        sorted_patterns = sorted(replacements.items(), key=lambda x: len(x[0]), reverse=True)
        
        result = body_text
        for real_text, fake_text in sorted_patterns:
            if real_text in result:
                ## Use word boundaries where appropriate to avoid partial matches
                ## But also support matches within other text (like email addresses)
                result = result.replace(real_text, fake_text)
        
        return result
    
    def anonymize_email_file(self, content: str) -> str:
        ## Local state for this email file only
        email_to_identity: Dict[str, Tuple[str, str]] = {}
        email_to_real_name: Dict[str, str] = {}  # Map email -> real full name
        used_names = set()
        used_email_locals = set()
        sender_emails = set()
        candidate_emails = set()
        
        lines = content.split('\n')
        
        ## First pass: collect sender emails and recipient identities (names)
        header_section = True
        current_header_name = None
        current_header_lines = []
        
        for line in lines:
            if header_section and line.strip() == '':
                ## Process last header before body
                self._collect_header_discovery_data(
                    current_header_name,
                    current_header_lines,
                    sender_emails,
                    email_to_real_name,
                    candidate_emails,
                )
                header_section = False
                break
            
            if header_section:
                if line and line[0] in ' \t':
                    if current_header_lines:
                        current_header_lines.append(line)
                    continue
                
                self._collect_header_discovery_data(
                    current_header_name,
                    current_header_lines,
                    sender_emails,
                    email_to_real_name,
                    candidate_emails,
                )
                
                if ':' in line:
                    current_header_name = line.split(':', 1)[0].strip().lower()
                    current_header_lines = [line]
                else:
                    current_header_name = None
                    current_header_lines = []
        
        ## Discover all candidates from decoded content before any anonymization
        candidate_emails.update(self.extract_candidate_emails_from_text(content, sender_emails))

        ## Build a frozen identity map once, before any header/body anonymization
        for candidate_email in sorted(candidate_emails):
            if candidate_email not in email_to_identity:
                anon_name, anon_local = self.generate_anonymous_identity(used_names, used_email_locals)
                email_to_identity[candidate_email] = (anon_name, anon_local)
        
        ## Build replacement map now (before second pass) so we can apply it to headers too
        replacements = {}
        if email_to_identity:
            replacements = self.build_replacement_map(email_to_identity, email_to_real_name)

        ## Select primary recipient identity to fix personalized body greetings
        primary_fake_name, _ = self._select_primary_recipient_identity(lines, email_to_identity, sender_emails)
        
        ## Second pass: anonymize recipient headers
        result_lines = []
        header_section = True
        current_header_name = None
        current_header_lines = []
        
        for idx, line in enumerate(lines):
            ## Check if we've reached the end of headers (empty line)
            if header_section and line.strip() == '':
                ## Process any pending header
                if current_header_name and current_header_lines:
                    self._process_and_append_header(
                        current_header_name, current_header_lines, 
                        result_lines, email_to_identity, used_names, used_email_locals, sender_emails, replacements
                    )
                header_section = False
                result_lines.append(line)
                current_header_name = None
                current_header_lines = []
                
                ## Now process the body - collect remaining lines
                body_start_index = idx + 1
                body_lines = lines[body_start_index:]
                body_text = '\n'.join(body_lines)
                
                ## Anonymize body using replacement map
                if replacements:
                    body_text = self.anonymize_body(body_text, replacements)

                ## Anonymize greeting leftovers (e.g. Dear bogdan) with contextual fake identity
                body_text = self._anonymize_body_salutations(body_text, primary_fake_name)
                
                ## Add anonymized body to result
                result_lines.append(body_text)
                break
            
            ## Process header lines
            if header_section:
                ## Check if this is a continuation line (starts with space or tab)
                if line and line[0] in ' \t':
                    if current_header_lines:
                        current_header_lines.append(line)
                    continue
                
                ## New header - process previous one if it exists
                if current_header_name and current_header_lines:
                    self._process_and_append_header(
                        current_header_name, current_header_lines,
                        result_lines, email_to_identity, used_names, used_email_locals, sender_emails, replacements
                    )
                
                ## Start new header
                if ':' in line:
                    current_header_name = line.split(':', 1)[0].strip().lower()
                    current_header_lines = [line]
                else:
                    current_header_name = None
                    current_header_lines = []
                    result_lines.append(line)
        
        return '\n'.join(result_lines)
    
    def _extract_sender_emails(self, header_lines: list, sender_emails: set):
        full_header = '\n'.join(header_lines)
        colon_pos = full_header.find(':')
        if colon_pos != -1:
            header_value = full_header[colon_pos + 1:]
            for _, email in getaddresses([header_value]):
                if email:
                    email = email.lower()
                    ## Only add non-AGH emails as senders (attackers)
                    if not self.is_agh_email(email):
                        sender_emails.add(email)
    
    def extract_bounce_recipient_email(self, bounce_addr: str) -> str:
        match = re.search(r'<([^>]+)>|(\S+)', bounce_addr)
        if not match:
            return ''

        full_bounce = match.group(1) or match.group(2)
        encoded_match = re.search(r'[+\-]([^@]+)@', full_bounce)
        if not encoded_match:
            return ''

        encoded_email = encoded_match.group(1)
        if '=' not in encoded_email:
            return ''

        parts_by_dash = encoded_email.split('-')
        actual_encoded_email = parts_by_dash[-1]
        recipient_email = actual_encoded_email.replace('=', '@').lower()

        if '@' not in recipient_email or '.' not in recipient_email.split('@')[-1]:
            return ''

        return recipient_email

    def anonymize_bounce_address(self, bounce_addr: str, email_to_identity: Dict[str, Tuple[str, str]]) -> str:
        recipient_email = self.extract_bounce_recipient_email(bounce_addr)
        if not recipient_email:
            return bounce_addr

        is_placeholder = self.is_placeholder_email(recipient_email)
        if not is_placeholder and not self.should_anonymize_email(recipient_email):
            return bounce_addr
        
        if recipient_email not in email_to_identity:
            return bounce_addr

        _, anon_local = email_to_identity[recipient_email]
        
        ## Create the anonymized encoded email (with = instead of @)
        domain = recipient_email.split('@')[1]
        anon_email_encoded = f"{anon_local}={domain}"
        
        ## Replace the original encoded email with the anonymized one
        actual_encoded_email = recipient_email.replace('@', '=')
        return bounce_addr.replace(actual_encoded_email, anon_email_encoded)
    
    def _process_and_append_header(self, header_name: str, header_lines: list, 
                                   result_lines: list, email_to_identity: Dict, used_names: set,
                                   used_email_locals: set, sender_emails: set, replacements: Dict[str, str]):
        ## Join all lines of this header
        full_header = '\n'.join(header_lines)
        
        if header_name in RECIPIENT_HEADERS:
            ## Extract the value (everything after first colon, may span lines)
            colon_pos = full_header.find(':')
            if colon_pos != -1:
                header_value = full_header[colon_pos + 1:]
                ## Anonymize the value
                anonymized_value = self.anonymize_recipient_header(
                    header_value,
                    email_to_identity,
                    used_names,
                    sender_emails,
                    used_email_locals,
                    create_missing=False,
                )
                ## Reconstruct header - keep original header name from first line
                result_lines.append(f"{header_lines[0].split(':', 1)[0]}: {anonymized_value}")
        elif header_name == 'return-path':
            ## Special handling for bounce addresses in Return-Path
            colon_pos = full_header.find(':')
            if colon_pos != -1:
                header_value = full_header[colon_pos + 1:].strip()
                ## Check if it's a bounce address and anonymize embedded recipient emails
                anonymized_value = self.anonymize_bounce_address(
                    header_value, email_to_identity
                )
                ## Reconstruct header
                result_lines.append(f"{header_lines[0].split(':', 1)[0]}: {anonymized_value}")
        elif header_name == 'subject' and replacements:
            ## Apply replacement map to Subject header to anonymize any AGH emails
            colon_pos = full_header.find(':')
            if colon_pos != -1:
                header_value = full_header[colon_pos + 1:]
                ## Apply all replacements
                anonymized_value = self.anonymize_body(header_value, replacements)
                ## Reconstruct header
                result_lines.append(f"{header_lines[0].split(':', 1)[0]}:{anonymized_value}")
        else:
            ## Not a recipient header - keep all lines as-is
            result_lines.extend(header_lines)
    
    def process_email_file(self, input_path: Path, output_path: Path):
        try:
            with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            ## Anonymize recipient headers only
            anonymized_content = self.anonymize_email_file(content)
            
            ## Write output
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(anonymized_content)
        
        except RuntimeError as e:
            print(f"ERROR: {e}")
            print(f"Skipping file: {input_path.name}")
            raise
    
    def process_directory(self, input_dir: Path, output_dir: Path):
        input_dir = Path(input_dir)
        output_dir = Path(output_dir)
        
        eml_files = list(input_dir.glob('*.eml'))
        print(f"Found {len(eml_files)} email files to process")
        processed_ok = 0
        failed = 0
        
        for i, eml_file in enumerate(eml_files, 1):
            output_file = output_dir / eml_file.name
            
            try:
                self.process_email_file(eml_file, output_file)
                processed_ok += 1
            except Exception as e:
                failed += 1
                print(f"Error processing {eml_file.name}: {e}")

            if i % 100 == 0 or i == len(eml_files):
                print(f"Progress: {i}/{len(eml_files)}")
        
        print(f"Processed: {processed_ok}, Failed: {failed}, Total: {len(eml_files)}")

def normalize_domain(domain: str) -> str:
    cleaned = (domain or '').strip().lower().strip('.')
    if not cleaned:
        return ''
    if '@' in cleaned:
        cleaned = cleaned.rsplit('@', 1)[1]
    return cleaned.strip('.').lower()


def parse_extra_domains(args: list) -> Tuple[list, set]:
    parsed_args = []
    extra_domains = set()
    index = 0

    while index < len(args):
        arg = args[index]

        if arg == '--include-gmail':
            extra_domains.add('gmail.com')
        elif arg == '--include-domain':
            if index + 1 >= len(args):
                raise ValueError('Missing value for --include-domain')
            raw_domains = args[index + 1]
            for domain in re.split(r'[\s,]+', raw_domains):
                normalized = normalize_domain(domain)
                if normalized:
                    extra_domains.add(normalized)
            index += 1
        elif arg.startswith('--include-domain='):
            raw_domains = arg.split('=', 1)[1]
            for domain in re.split(r'[\s,]+', raw_domains):
                normalized = normalize_domain(domain)
                if normalized:
                    extra_domains.add(normalized)
        else:
            parsed_args.append(arg)

        index += 1

    return parsed_args, extra_domains


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)

    try:
        parsed_args, extra_domains = parse_extra_domains(args)
    except ValueError as exc:
        print(f"Error: {exc}")
        print("Usage: python email_recipient_anonymizer.py [--include-gmail] [--include-domain DOMAIN]... <input_dir> <output_dir>")
        sys.exit(1)

    if len(parsed_args) != 2:
        print("Usage: python email_recipient_anonymizer.py [--include-gmail] [--include-domain DOMAIN]... <input_dir> <output_dir>")
        sys.exit(1)

    input_dir = Path(parsed_args[0])
    output_dir = Path(parsed_args[1])
    
    if not input_dir.exists():
        print(f"Error: Input directory {input_dir} does not exist")
        sys.exit(1)
    
    anonymizer = RecipientAnonymizer(extra_domains=extra_domains)
    anonymizer.process_directory(input_dir, output_dir)


if __name__ == '__main__':
    main()
