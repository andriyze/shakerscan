"""Bounded runtime diagnostic grammars for observed server-error responses."""
from html.parser import HTMLParser
import json
import re

_MAX_CHARS = 262_144
_HEADER = re.compile(r'(?m)^[A-Za-z_][A-Za-z_0-9.]{0,200}(?:Error|Exception):[^\r\n]{0,2000}|^Error:[^\r\n]{0,2000}')
_PYTHON_FILE = re.compile(r'''(?m)^[ \t]+File ["'](?:/|[A-Za-z]:[\\/])[^"'\r\n]{1,1024}["'], line [0-9]{1,8}\b''')
# A JDK 9+ frame may name its class loader and module before the class: "java.base/java.lang.X",
# "app//com.example.X", "loader/module@1.0/com.example.X" (and JBoss Modules' "mod@1.0//").
_JAVA_FRAME = re.compile(
    r'(?m)^[ \t]+at (?:[\w.$@+-]{1,200}/)?(?:[\w.$-]{0,200}(?:@[\w.+-]{1,64})?/)?'
    r'[A-Za-z_$][\w.$]{0,300}\([^\r\n()]{1,200}\.java:[0-9]{1,8}\)'
)
_JS_FRAME = re.compile(r'(?m)^[ \t]+at (?:[^\r\n()]{0,200}\()?(?:/|[A-Za-z]:[\\/])[^()\r\n]{1,1024}:[0-9]{1,8}:[0-9]{1,8}\)?[ \t]*$')
_PHP_ERROR = re.compile(r'(?m)^(?:PHP )?(?:Fatal error|Parse error):[^\r\n]{1,2000}\bin (?:/|[A-Za-z]:[\\/])[^\r\n]{1,1024} on line [0-9]{1,8}\b')


class _DiagnosticText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)

    def handle_starttag(self, tag, attrs):
        if tag == 'br':
            self.parts.append('\n')


def runtime_error_disclosed(text: str, content_type: str) -> bool:
    """Require runtime structure and file/line frames, never a generic error word."""
    text = text[:_MAX_CHARS]
    if 'json' in content_type:
        try:
            document = json.loads(text)
        except (ValueError, RecursionError):
            return False
        if not isinstance(document, dict):
            return False
        objects = [document]
        if isinstance(document.get('error'), dict):
            objects.append(document['error'])
        # Only diagnostic fields, not arbitrary response data or example arrays.
        text = '\n'.join(value for obj in objects for key in ('trace', 'stack', 'stackTrace')
                         if isinstance(value := obj.get(key), str))
    elif 'html' in content_type or text.lstrip().lower().startswith(('<html', '<!doctype html')):
        parser = _DiagnosticText()
        try:
            parser.feed(text)
            parser.close()
        except (AssertionError, ValueError, RecursionError):
            return False
        text = ''.join(parser.parts)
    if _PHP_ERROR.search(text):
        return True
    if not _HEADER.search(text):
        return False
    return bool(
        ('Traceback (most recent call last):' in text and _PYTHON_FILE.search(text))
        or len(_JAVA_FRAME.findall(text)) >= 2
        or len(_JS_FRAME.findall(text)) >= 2
    )
