import re
from email.utils import getaddresses
from typing import Iterable, Iterator, Set, Tuple

AGH_DOMAIN = 'agh.edu.pl'
EMAIL_RE = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', re.IGNORECASE)


def is_agh_domain(domain: str, agh_domain: str = AGH_DOMAIN) -> bool:
    cleaned = domain.lower().strip('.')
    return cleaned == agh_domain or cleaned.endswith(f'.{agh_domain}')


def is_agh_email(email: str, agh_domain: str = AGH_DOMAIN) -> bool:
    if '@' not in email:
        return False
    domain = email.rsplit('@', 1)[1]
    return is_agh_domain(domain, agh_domain)


def extract_emails_from_header_value(value: str) -> Set[str]:
    emails: Set[str] = set()

    for _, parsed_email in getaddresses([value]):
        if parsed_email:
            emails.add(parsed_email.lower())

    if emails:
        return emails

    for match in EMAIL_RE.findall(value or ''):
        emails.add(match.lower())

    return emails


def iter_top_level_headers(content: str) -> Iterator[Tuple[str, str]]:
    lines = content.replace('\r\n', '\n').replace('\r', '\n').split('\n')
    current_name = ''
    current_value = ''

    for line in lines:
        if line.strip() == '':
            if current_name:
                yield current_name, current_value
            return

        if line and line[0] in ' \t':
            if current_name:
                current_value += ' ' + line.strip()
            continue

        if current_name:
            yield current_name, current_value

        if ':' in line:
            name, value = line.split(':', 1)
            current_name = name.strip().lower()
            current_value = value.strip()
        else:
            current_name = ''
            current_value = ''

    if current_name:
        yield current_name, current_value


def extract_header_emails(content: str, target_headers: Iterable[str]) -> Set[str]:
    targets = {header.lower() for header in target_headers}
    found: Set[str] = set()

    for header_name, header_value in iter_top_level_headers(content):
        if header_name in targets and header_value:
            found.update(extract_emails_from_header_value(header_value))

    return found
