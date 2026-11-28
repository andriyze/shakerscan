"""Ordinary markup, style sheets and scripts come back from the body masking unchanged, while
real secret shapes in them stay withheld (unit fixtures; every value is synthetic).

Hunt windows of ordinary pages showed ``[withheld:N]`` in place of ``<!DOCTYPE``, font names and
words such as ``options``: three passes read code as data. A style sheet's ``format('woff2');`` and
a script's ``f('a'), g('b');`` were read as rows of a SQL dump with unknown columns, which fail
closed (every quoted string withheld); ``nonce: options && options.nonce`` and ``tokenCache =
createCache()`` were read as secret-named settings; ``key: props && normalizeKey(props),`` as a
descriptor naming a key, which withheld its whole object. Each withheld word was then sealed and
withheld wherever a later response of the Hunt echoed it.
"""
from __future__ import annotations

import base64
import json
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "api", ROOT / "scanner", ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from runtime import archive_body_masking as masking  # noqa: E402

ACTION = str(uuid.UUID(int=811))


def _mask(text: str, *, window: bool = False) -> tuple[str, list[str]]:
    collector = masking.WithheldValues(ACTION)
    with masking.collecting_withheld_values(collector):
        masked = masking.mask_body_text(text, window=window)
    return masked, collector.values


# --- Ordinary content: unchanged ---------------------------------------------------------------

SIGN_IN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in</title>
<link rel="preconnect" href="https://fonts.gstatic.example">
<style>
@font-face{font-family:'VT323';font-style:normal;font-weight:400;font-display:swap;src:url(https://fonts.gstatic.example/s/vt323/v18/a.woff2) format('woff2');unicode-range:U+0100-02BA, U+02BD-02C5;}
@font-face{font-family:'Roboto';font-style:italic;font-weight:400;src:url('/fonts/roboto.woff2') format('woff2'),url('/fonts/roboto.woff') format('woff');}
body { font-family: "Helvetica Neue", Arial, sans-serif; color: #333; }
.btn:disabled { opacity: .5; background-image: url('data:image/svg+xml;utf8,<svg/>'); }
.icon{background:url('/i/search.svg') no-repeat;}.logo{background:url('/i/logo.png');}
</style>
<script type="module">
import { createApp } from "./app.js";
export default function init(status) {
  const state = { status: "idle", disabled: false, type: "submit" };
  return createApp(state);
}
</script>
</head>
<body>
<form method="post" action="/login">
<label for="username">Username</label>
<input type="text" name="username" autocomplete="username">
<label for="password">Password</label>
<input type="password" name="password" autocomplete="current-password">
<a class="label-link" id="forgot-password" href="/password_reset">Forgot password?</a>
<button type="submit" disabled>Sign in</button>
<select name="role"><option value="default" selected>default</option></select>
</form>
</body>
</html>
"""

# A library bundle: option objects whose keys name a nonce or a key, caches named for tokens,
# arrow functions and comparisons, calls with quoted arguments in a row.
LIBRARY_SCRIPT = """(function (global, factory) {
  "use strict";
  var preservedScriptAttributes = { type: true, src: true, nonce: true, noModule: true };
  function DOMEval(code, node, doc) {
    doc = doc || document;
    var i, val, script = doc.createElement("script");
    script.text = code;
    if (node) {
      for (i in preservedScriptAttributes) {
        val = node[i] || node.getAttribute && node.getAttribute(i);
        if (val) { script.setAttribute(i, val); }
      }
    }
    doc.head.appendChild(script).parentNode.removeChild(script);
  }
  function globalEval(code, options, doc) {
    DOMEval(code, { nonce: options && options.nonce }, doc);
  }
  var classCache = createCache(),
    tokenCache = createCache(),
    compilerCache = createCache();
  function tokenize(selector, parseOnly) {
    var matched, match, tokens, type, soFar = selector, groups = [];
    var cached = tokenCache[selector + " "];
    if (cached) { return parseOnly ? 0 : cached.slice(0); }
    while (soFar) {
      if (!matched || (match = rcomma.exec(soFar))) {
        if (match) { soFar = soFar.slice(match[0].length) || soFar; }
        groups.push((tokens = []));
      }
      matched = false;
    }
    return parseOnly ? soFar.length : soFar ? find.error(selector) : tokenCache(selector, groups).slice(0);
  }
  var isIntegerKey = (key) => isString(key) && key !== "NaN" && key[0] !== "-" && "" + parseInt(key, 10) === key;
  var getKey = ({ key }) => key != null ? key : null;
  function createVNode(type, props, children, patchFlag, dynamicProps, shapeFlag) {
    const vnode = {
      __v_isVNode: true,
      __v_skip: true,
      type,
      props,
      key: props && normalizeKey(props),
      ref: props && normalizeRef(props),
      scopeId: currentScopeId,
      slotScopeIds: null,
      children,
      component: null,
      staticCount: 0,
      shapeFlag,
      patchFlag,
      dynamicProps,
      dynamicChildren: null,
      appContext: null,
      ctx: currentRenderingInstance
    };
    return vnode;
  }
  function setStyle(style, name, val) {
    const normalizedKey = key.startsWith(`--`) ? key : hyphenate(key);
    if (token === undefined || token == null) { return; }
    style.setProperty(normalizedKey, val);
  }
  var request = {
    token: options.token,
    secret: config.secret
  };
  var apiKey = enabled ? 1 : 0;
  var htmlEscapes = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  var reIsPlainProp = /^\\w*$/, defaults = ['constructor', 'hasOwnProperty', 'isPrototypeOf'];
  log('start'), log('stop'); warn('x'), warn('y');
  emit('update:modelValue'), emit('change');
  return factory(global, 'jQuery', 'default');
})(this, function (window, name, mode) { return window; });
"""

# Documentation: a highlighted code sample whose output is a list of tuples.
CODE_SAMPLE_PAGE = """<!doctype html>
<html class="no-js" lang="en">
<body>
<pre><code><span class="n">fruits</span> <span class="o">=</span> <span class="p">[</span><span class="s1">'Banana'</span><span class="p">,</span> <span class="s1">'Apple'</span><span class="p">,</span> <span class="s1">'Lime'</span><span class="p">]</span>
<span class="nb">print</span><span class="p">(</span><span class="s1">'The product is:'</span><span class="p">)</span>
<span class="go">[(0, 'Banana'), (1, 'Apple'), (2, 'Lime')]</span>
<span class="go">['BANANA', 'APPLE', 'LIME']</span></code></pre>
<script src="/static/js/libs/jquery-1.8.2.min.js"></script>
<script>window.jQuery || document.write('<script src="/static/js/libs/jquery.js"><\\/script>');</script>
<script>$(function () { $('.menu').toggle(); $('.search').focus(); });</script>
</body>
</html>
"""

STYLE_SHEET = """:root{--font-family-sans:'Inter','Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;}
.search{background-image:url("data:image/svg+xml;charset=utf-8,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 56 56'%3E%3Cpath fill='%23eee' d='M0 0h56v56H0z'/%3E%3C/svg%3E");}
.toggle{background-image:url('/i/toggle.svg');-webkit-filter:url('#filter');filter:url('#filter');}
@import url('https://fonts.googleapis.example/css2?family=Roboto');
.btn[disabled],.btn:disabled{cursor:default;}
input[type='submit'],input[type='password']{font-family:'Courier New',monospace;}
"""


@pytest.mark.parametrize("name", ["SIGN_IN_PAGE", "LIBRARY_SCRIPT", "CODE_SAMPLE_PAGE", "STYLE_SHEET"])
@pytest.mark.parametrize("window", [False, True])
def test_ordinary_pages_scripts_and_styles_come_back_unchanged(name, window):
    text = globals()[name]
    masked, values = _mask(text, window=window)
    assert values == [], values
    assert masked == text


@pytest.mark.parametrize("name", ["SIGN_IN_PAGE", "LIBRARY_SCRIPT", "CODE_SAMPLE_PAGE", "STYLE_SHEET"])
def test_any_window_of_ordinary_content_withholds_nothing(name):
    text = globals()[name] * 3
    for start in range(0, len(text) - 200, 97):
        masked, values = _mask(text[start:start + 1500], window=start > 0)
        assert values == [], (start, values)


# --- Real secret shapes: still withheld -------------------------------------------------------

# Assembled at run time, so no scanner reads a credential in this file.
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN = "gh" + "p_" + "R7fQ2mVx9LkP4sT1wZ8yN3bC6dH0jA5eG2uK"
STRIPE_KEY = "sk_live_" + "PLANTEDkeyAAAAAAAAAAAA"
JWT = ".".join([
    base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("="),
    base64.urlsafe_b64encode(json.dumps({"sub": "4711", "role": "admin"}).encode()).decode().rstrip("="),
    "Xq9bT4mZr7Kd2Lw5Pn8Vs1Hc6Gf3Jy0Ae4Ru7Ow2Ik",
])
PASSWORD = "hunter2" + "SECRET"
PRIVATE_KEY = ("-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7bq9Xk2Lm4Qp8Rt1Vw3Yz6Bc9Df2Gh5Jk8Mn1Pq4St7\n"
               "Vw0Yz3Bc6Df9Gh2Jk5Mn8Pq1St4Vw7Yz0Bc3Df6Gh9Jk2Mn5Pq8St1Vw4Yz7Bc0\n-----END RSA PRIVATE KEY-----")
DB_PASSWORD = "Pq7" + "sTw9xZ2"


@pytest.mark.parametrize(("text", "secret"), [
    # Provider formats anywhere, in markup and in scripts.
    (f"<p>Use {AWS_KEY} with region us-east-1</p>", AWS_KEY),
    (f"aws_secret_access_key = {AWS_SECRET}\n", AWS_SECRET),
    (f"<script>const client = new Octokit({{ auth: '{GITHUB_TOKEN}' }});</script>", GITHUB_TOKEN),
    (f"{LIBRARY_SCRIPT}\nvar stripe = Stripe('{STRIPE_KEY}');\n", STRIPE_KEY),
    # A JWT and a bearer header.
    (f'<script>const token = "{JWT}"; localStorage.setItem("token", token);</script>', JWT),
    (f"Authorization: Bearer {JWT}\nAccept: */*\n", JWT),
    # Passwords in forms and JSON, and quoted in a script.
    (f'<form><input type="password" name="password" value="{PASSWORD}"></form>', PASSWORD),
    (json.dumps({"user": "admin", "password": PASSWORD, "theme": "default"}), PASSWORD),
    (f'{SIGN_IN_PAGE}<script>const config = {{ password: "{PASSWORD}", status: "ok" }};</script>', PASSWORD),
    (f"{LIBRARY_SCRIPT}\nvar apiKey = '{STRIPE_KEY}';\n", STRIPE_KEY),
    (f"login=admin&password={PASSWORD}&remember=1", PASSWORD),
    # A private key and connection strings.
    (f"<pre>{PRIVATE_KEY}</pre>", PRIVATE_KEY.splitlines()[1]),
    (f"DATABASE_URL=postgres://app:{DB_PASSWORD}@db.internal:5432/app\n", DB_PASSWORD),
    (f'<add name="Main" connectionString="Server=db;Database=app;User Id=app;Password={DB_PASSWORD};"/>',
     DB_PASSWORD),
    # Settings files and an unquoted script value that is not an expression.
    (f"DB_PASSWORD={DB_PASSWORD}\nSECRET_KEY={STRIPE_KEY}\n", DB_PASSWORD),
    (f"database:\n  user: app\n  password: {DB_PASSWORD}\n", DB_PASSWORD),
    (f"{LIBRARY_SCRIPT}\nvar session = {{ token: {GITHUB_TOKEN} }};\n", GITHUB_TOKEN),
    (f"{LIBRARY_SCRIPT}\nvar auth = {{ token: {JWT} }};\n", JWT),
    # A SQL dump window that opens inside its rows (unknown columns: fail closed).
    (f"),(17,'u17@fixture.test','{PASSWORD}','2024-02-19 14:07:31'),"
     f"(18,'u18@fixture.test','{DB_PASSWORD}','2024-02-19 14:07:31');", PASSWORD),
])
def test_real_secret_shapes_stay_withheld(text, secret):
    masked, values = _mask(text)
    assert secret not in masked
    assert any(secret in value for value in values)


# A page that carries an inline script and, outside it, a settings block. The script makes the body
# read as code; the settings are not in it.
_SCRIPTED_PAGE = (
    "<html><head><script>const menu = function () { return a === b; }; var go = () => 1;</script>"
    "</head><body><pre>{block}</pre></body></html>"
)


@pytest.mark.parametrize("line, secret", [
    ("DB_PASSWORD=Winter2024", "Winter2024"),
    ("password: hunter2", "hunter2"),
    ("api_key = a1b2c3d4e5f6a7b8c9d0", "a1b2c3d4e5f6a7b8c9d0"),
    ("Admin password is: tiger", "tiger"),
    ("client_secret: correcthorsebatterystaple", "correcthorsebatterystaple"),
])
def test_a_setting_beside_an_inline_script_is_withheld(line, secret):
    masked = masking.mask_body_text(_SCRIPTED_PAGE.replace("{block}", f"APP_ENV=production\n{line}\n"))
    assert secret not in masked
    assert "const menu = function ()" in masked  # the script itself comes back as written


def test_an_expression_inside_the_script_of_such_a_page_is_still_shown():
    page = (
        "<html><script>const run = function (options) { return options === null; };\n"
        "var settings = {\n  token: options.token,\n  nonce: options && options.nonce\n};\n"
        "tokenCache = createCache();</script><pre>API_TOKEN=Winter2024x</pre></html>"
    )
    masked = masking.mask_body_text(page)
    assert "token: options.token," in masked and "tokenCache = createCache();" in masked
    assert "Winter2024x" not in masked


def test_an_env_line_in_a_body_that_reads_as_script_is_withheld():
    # No tags at all: a debug dump with a source excerpt above the process environment.
    body = (
        "function handler(req) {\n  const user = () => req.user;\n  return user === null;\n}\n\n"
        "DB_PASSWORD=Winter2024\nSESSION_SECRET=correcthorse\n"
    )
    masked = masking.mask_body_text(body)
    assert "Winter2024" not in masked and "correcthorse" not in masked
