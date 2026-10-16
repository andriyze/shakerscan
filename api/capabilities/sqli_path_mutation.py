"""SQL proof path inputs are anchored to one immutable templated route segment."""
from dataclasses import replace
import re
from urllib.parse import quote, unquote, urlsplit, urlunsplit

_VALUES = {
    '{int}': re.compile(r'[0-9]+\Z'),
    '{uuid}': re.compile(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z'),
}


def prepare_path_candidate(request, candidate):
    """Validate before traffic and remove the sqlmap-only marker from the control."""
    if candidate.get('parameter_location') != 'path':
        return request, None
    index = candidate.get('path_segment_index')
    if (request.method != 'GET' or isinstance(index, bool) or not isinstance(index, int)
            or index < 1 or candidate.get('parameter_name') != f'path_{index}'
            or candidate.get('field_path', f'path_{index}') != f'path_{index}'):
        raise ValueError('SQLi proof path candidate has invalid segment authority')
    canonical = str(candidate.get('canonical_path') or '').split('/')
    parsed = urlsplit(request.url)
    segments = parsed.path.split('/')
    if (len(canonical) != len(segments) or index >= len(canonical)
            or canonical[index] not in _VALUES or parsed.fragment):
        raise ValueError('SQLi proof path candidate differs from its route')
    for position, (template, actual) in enumerate(zip(canonical, segments)):
        if position == index and actual.endswith('*'):
            actual = actual[:-1]
            segments[position] = actual
        pattern = _VALUES.get(template)
        if not (pattern.fullmatch(actual) if pattern else actual == template):
            raise ValueError('SQLi proof path request differs from its route')
    return replace(request, url=urlunsplit(parsed._replace(path='/'.join(segments)))), index


def path_field_value(request, index):
    return unquote(urlsplit(request.url).path.split('/')[index])


def replace_path_field(request, index, replacement):
    parsed = urlsplit(request.url)
    segments = parsed.path.split('/')
    # Encode delimiters too: the payload remains one segment of the same exact origin.
    segments[index] = quote(replacement, safe='')
    return replace(request, url=urlunsplit(parsed._replace(path='/'.join(segments))))
