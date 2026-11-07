"""Deterministic property tests ported from docs fuzz.py (fixed seeds, N cases per category)."""
import random

from newton_mcp import redact

KEY = b"k" * 32
N = 250
BS = chr(92)
ALNUM = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
SECRET_OPTS = ["key", "password", "passwd", "psk", "sae_password", "wpa_psk", "private_key", "preshared_key", "auth_secret", "secret",
               "token", "pin", "community", "key1", "wpa_passphrase", "pass", "pwd", "pincode", "wps_pin", "auth_pass", "ro_community",
               "uuid", "Key", "PASSWORD", "api_key", "my_token", "shared_secret"]
KV_SECRET = ["password", "psk", "secret", "token", "wpa_passphrase", "key", "passwd", "pwd", "pass", "api_key", "Password", "KEY"]
COLON_SECRET = ["password", "Password", "key", "Key", "secret", "token", "passwd", "psk", "pin", "PASSWORD"]
PLAIN_OPTS = ["ssid", "mode", "hostname", "channel", "proto", "ipaddr", "device", "encryption", "update_url", "notes", "msg", "description", "bypass", "compass"]
NONSECRET_K = ["ssid", "mode", "hostname", "channel", "proto", "ipaddr", "device", "encryption", "bypass", "compass", "description"]
PKGS, SECS, OPS = (["wireless", "network", "ddns", "system", "firewall", "x-pkg"],
                   ["default_radio0", "@wifi-iface[0]", "cfg0592bd", "@rule[3]", "wan"], ["", "", "", "+", "-", "^"])
PUNCT_ANY = [" ", ",", ";", "&", "'", '"', "\\", ":", "=", "/", "@", "#", "(", ")", "{", "}", "[", "]", "<", ">", "|", "$", "`",
             "!", "*", "+", "-", ".", "_", "%", "?", "~", "^"]
PUNCT_NOSPACE_NOQUOTE = [p for p in PUNCT_ANY if p not in " '\""]
PUNCT_QUERY = [p for p in PUNCT_NOSPACE_NOQUOTE if p not in "&#"]
PUNCT_SQ = [p for p in PUNCT_ANY if p != "'"]
PUNCT_DQ = [p for p in PUNCT_ANY if p not in '"\\']
PRE_WORDS = ["uci:", "hostapd: using", "set", "x", "error: parse", "diff:", "see", "log line", "add_list"]
TAILS = [" tail", " end of line", " ok.", " and more words", ""]


def frag(r):
    return "".join(r.choice(ALNUM) for _ in range(8))


def joined(r, parts, puncts, maxp=2):
    out = parts[0]
    for p in parts[1:]:
        out += "".join(r.choice(puncts) for _ in range(r.randint(1, maxp))) + p
    return out


def run_case(fails, text, frags=(), expect_in=(), unchanged=False):
    out = redact.redact_text(text, KEY)
    ok = out == text if unchanged else all(f not in out for f in frags) and all(e in out for e in expect_in)
    if redact.redact_text(out, KEY) != out:
        fails.append((text, out, "not idempotent"))
    if not ok:
        fails.append((text, out, frags))


def assert_clean(fails, cat):
    assert not fails, f"{cat}: {len(fails)} failures; first 3 (in, out, info): {fails[:3]!r}"


def test_line_start_secret_assignments():
    r, fails = random.Random(101), []
    for _ in range(N):
        f = [frag(r), frag(r), frag(r)]
        value = joined(r, f, PUNCT_ANY, 3)
        form, q = r.choice(["dotted", "file", "list", "kv", "colon"]), r.choice(["", "'", '"'])
        if form == "dotted":
            text = f"{r.choice(PKGS)}.{r.choice(SECS)}.{r.choice(SECRET_OPTS)}{r.choice(OPS)}={q}{value}{q}"
        elif form in ("file", "list"):
            text = f"config wifi-iface 'x'\n\t{'option' if form == 'file' else 'list'} {r.choice(SECRET_OPTS)} {q}{value}{q}"
        elif form == "kv":
            text = f"{r.choice(['', ' ', chr(9)])}{r.choice(KV_SECRET)}{r.choice(['', '+'])}={value}"
        else:
            text = f"{r.choice(['', ' '])}{r.choice(COLON_SECRET)}: {value}"
        run_case(fails, text, f)
    assert_clean(fails, "L")


def test_multiline_quoted_values_keep_next_line():
    r, fails = random.Random(102), []
    for _ in range(N):
        f = [frag(r), frag(r), frag(r)]
        qq = r.choice(["'", '"'])
        body = f[0] + "\n" + joined(r, f[1:2], PUNCT_SQ if qq == "'" else PUNCT_DQ, 2) + "\n" + f[2]
        if r.random() < 0.5:
            text = f"{r.choice(PKGS)}.{r.choice(SECS)}.{r.choice(SECRET_OPTS)}={qq}{body}{qq}\nwireless.x.ssid='NEXTLINE'"
        else:
            text = f"config wifi-iface 'x'\n\toption {r.choice(SECRET_OPTS)} {qq}{body}{qq}\n\toption ssid 'NEXTLINE'"
        run_case(fails, text, f, expect_in=["NEXTLINE"])
    assert_clean(fails, "M")


def test_midline_quoted_values_keep_tail():
    r, fails = random.Random(103), []
    for _ in range(N):
        f = [frag(r), frag(r), frag(r)]
        pre, tail, qq = r.choice(PRE_WORDS), r.choice(TAILS), r.choice(["'", '"'])
        punct, esc = (PUNCT_SQ, "'\\''") if qq == "'" else (PUNCT_DQ, '\\"')
        body = f[0] + r.choice(punct) + (esc if r.random() < 0.5 else "") + f[1] + r.choice(punct) + f[2]
        lhs = r.choice([f"{r.choice(PKGS)}.{r.choice(SECS)}.{r.choice(SECRET_OPTS)}{r.choice(OPS)}=", f"{r.choice(KV_SECRET)}=",
                        f"{r.choice(COLON_SECRET)}: "])
        text = f"{pre} {lhs}{qq}{body}{qq}{tail}"
        run_case(fails, text, f, expect_in=[tail] if tail else ())
    assert_clean(fails, "Q")


def test_midline_unquoted_values_consume_tail():
    r, fails = random.Random(104), []
    for _ in range(N):
        f = [frag(r), frag(r), frag(r)]
        pre, tail = r.choice(PRE_WORDS), r.choice(TAILS)
        body = joined(r, f, PUNCT_NOSPACE_NOQUOTE, 2)
        lhs = r.choice([f"{r.choice(PKGS)}.{r.choice(SECS)}.{r.choice(SECRET_OPTS)}{r.choice(OPS)}=", f"{r.choice(KV_SECRET)}=",
                        f"{r.choice(COLON_SECRET)}: "])
        text = f"{pre} {lhs}{body}{tail}"
        run_case(fails, text, f)
    assert_clean(fails, "U")


def test_url_query_values_keep_query_tail():
    r, fails = random.Random(105), []
    for _ in range(N):
        f = [frag(r), frag(r)]
        body = joined(r, f, PUNCT_QUERY, 2)
        text = f"GET /cgi-bin/x{r.choice(['?', '?user=a&'])}{r.choice(KV_SECRET)}={body}&z=1 HTTP/1.1"
        run_case(fails, text, f, expect_in=["&z=1 HTTP/1.1"])
    assert_clean(fails, "P")


def test_nested_secret_inside_plain_option_value():
    r, fails = random.Random(106), []
    for _ in range(N):
        f = [frag(r)]
        qq, inner_name = r.choice(["'", '"']), r.choice(KV_SECRET)
        inner = r.choice([f"https://h/u?host=h&{inner_name}={f[0]}", f"update failed {inner_name}={f[0]} rc=1", f"{inner_name}={f[0]}",
                          f"wireless.x.{r.choice(SECRET_OPTS)}={f[0]}"])
        if r.random() < 0.5:
            text = f"{r.choice(PKGS)}.{r.choice(SECS)}.{r.choice(PLAIN_OPTS)}{r.choice(OPS)}={qq}{inner}{qq}"
        else:
            text = f"{r.choice(PRE_WORDS)} {r.choice(PLAIN_OPTS)}={qq}{inner}{qq} rc=1"
        run_case(fails, text, f)
    assert_clean(fails, "N")


def test_non_secret_assignments_unchanged():
    r, fails = random.Random(107), []
    for _ in range(N):
        vals = joined(r, [r.choice(["LabNet", "ap", "Quasar", "36", "psk2+ccmp", "lan", "x"]) for _ in range(2)], PUNCT_NOSPACE_NOQUOTE, 1)
        qk, kform, opt = r.choice(["", "'", '"']), r.choice(["dotted", "kv", "file", "colon"]), r.choice(NONSECRET_K)
        if kform == "dotted":
            text = f"{r.choice(PKGS)}.{r.choice(SECS)}.{opt}={qk}{vals}{qk}"
        elif kform == "kv":
            text = f"{r.choice(PRE_WORDS)} {opt}={qk}{vals}{qk} end"
        elif kform == "file":
            text = f"\toption {opt} '{vals}'"
        else:
            text = f"{opt.capitalize()}: {vals}"
        run_case(fails, text, unchanged=True)
    assert_clean(fails, "K")


def test_json_containers_and_escaped_quote_openers():
    r, fails = random.Random(108), []
    names = ["psk", "password", "key", "secret", "token", "pin", "passphrase"]
    for _ in range(N):
        f = [frag(r), frag(r)]
        nm, kvn = r.choice(names), r.choice(KV_SECRET)
        shapes = {
            "arr_nested": f'{{"{nm}": [["{f[0]}"], ["{f[1]}"]], "mode": "ap"}}',
            "arr_obj": f'{{"{nm}": [{{"k": "{f[0]}"}}, {{"v": ["{f[1]}"]}}]}}',
            "arr_cut": f'{{"{nm}": ["{f[0]}", "{f[1]}',
            "arr_mixed": f'{{"{nm}": [1, true, null, "{f[0]}", {{"a": "{f[1]}"}}]}}',
            "arr_bare": f'{{"{nm}": [{f[0]}, {f[1]}]}}',
            "obj": f'{{"{nm}": {{"value": "{f[0]}", "n": "{f[1]}"}}}}',
            "esc_dq_json": f'{{"msg": "update failed {kvn}={BS}"{f[0]} {f[1]}{BS}" rc=1"}}',
            "esc_sq_text": f"x {kvn}={BS}'{f[0]} {f[1]}{BS}' y",
        }
        expect = {
            "arr_nested": ['"mode": "ap"'],
            "arr_obj": [],
            "arr_cut": [],
            "arr_mixed": [],
            "arr_bare": [],
            "obj": [],
            "esc_dq_json": [" rc=1"],
            "esc_sq_text": [" y"],
        }
        shape = r.choice(list(shapes))
        run_case(fails, shapes[shape], frags=f, expect_in=expect[shape])
    assert_clean(fails, "J")
