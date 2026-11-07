from __future__ import annotations

import re

import pytest

from newton_mcp import redact


SECRET = "ObviousFakeSecret987"
KEY = b"k" * 32
PH = r"<redacted:[0-9a-f]{8}>"

NAMES = [
    "pass", "pwd", "pw", "pincode", "pin_code", "uuid", "credential",
    "credentials", "ro_community", "rw_community", "wps_pin", "auth_pass",
    "client_pwd", "node_uuid", "community", "pin",
]
OPERATORS = ["+=", "-=", "^="]
FORMS = ["dotted_line_start", "dotted_midline", "kv_line_start", "kv_midline"]


def _form_text(form: str, name: str, op: str) -> str:
    if form == "dotted_line_start":
        return f"wireless.x.{name}{op}'{SECRET}'"
    if form == "dotted_midline":
        return f"see wireless.x.{name}{op}'{SECRET}' ok"
    if form == "kv_line_start":
        return f"{name}{op}{SECRET}"
    return f"see {name}{op}{SECRET} ok"


@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("operator", OPERATORS)
@pytest.mark.parametrize("name", NAMES)
def test_operator_forms_redact_catalog_only_names(name, operator, form):
    text = _form_text(form, name, operator)
    out = redact.redact_text(text, KEY)
    assert SECRET not in out
    assert operator in out
    assert "<redacted:" in out


@pytest.mark.parametrize("operator", OPERATORS)
@pytest.mark.parametrize("name", NAMES)
def test_dotted_operator_placeholder_equals_plain_assignment_placeholder(name, operator):
    op_text = f"wireless.x.{name}{operator}'{SECRET}'"
    plain_text = f"wireless.x.{name}='{SECRET}'"
    op_token = re.search(PH, redact.redact_text(op_text, KEY))
    plain_token = re.search(PH, redact.redact_text(plain_text, KEY))
    assert op_token is not None and plain_token is not None
    assert op_token.group(0) == plain_token.group(0)


PASSES = ["_redact_dotted_anywhere", "_redact_kv_anywhere", "_redact_colon_anywhere"]


class CountingStr(str):
    calls = 0

    def find(self, *args, **kwargs):
        type(self).calls += 1
        return super().find(*args, **kwargs)


@pytest.mark.parametrize("name", PASSES)
def test_midline_passes_search_for_the_line_end_once_per_line(name):
    func = getattr(redact, name)
    fmt = "<redacted:{fp}>"

    if name == "_redact_dotted_anywhere":
        secret_token = "key=a"
        single = "x " + "wireless.x.key=a " * 3000
        multi = "\n".join("x " + "wireless.x.key=a " * 20 for _ in range(60))
    elif name == "_redact_kv_anywhere":
        secret_token = "password=a"
        single = "x " + "password=a " * 3000
        multi = "\n".join("x " + "password=a " * 20 for _ in range(60))
    else:
        secret_token = "password: a"
        single = "x " + "password: a " * 3000
        multi = "\n".join("x " + "password: a " * 20 for _ in range(60))

    CountingStr.calls = 0
    out = func(CountingStr(single), KEY, fmt)
    assert CountingStr.calls <= 3
    assert secret_token not in out

    CountingStr.calls = 0
    out = func(CountingStr(multi), KEY, fmt)
    assert CountingStr.calls <= 70
    assert secret_token not in out
