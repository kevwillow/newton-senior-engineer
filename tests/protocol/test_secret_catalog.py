"""One secret-name catalog consumed by both maskers.

Every name in mcp/newton_mcp/secret_names.txt must be masked by
newton_mcp.redact.redact_text AND by scripts/owrt-change.sh mask_secrets, so a
name added to the catalog is covered by both maskers automatically.  Both
consumers fail closed when the catalog is missing, empty or malformed.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from newton_mcp import redact

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "owrt-change.sh"
CATALOG = REPO / "mcp" / "newton_mcp" / "secret_names.txt"
SECRET_VALUE = "hunter2value"

# The exact/suffix/contains words redact.py held before the catalog file
# existed (frozen copies: dropping any of them from secret_names.txt must
# fail these tests).
OLD_EXACT = {
    "key", "password", "passwd", "psk", "sae_password", "wpa_psk",
    "private_key", "preshared_key", "auth_secret", "priv_key_pwd", "secret",
    "token", "pin", "community", "pass", "pwd", "pw", "pincode",
    "pin_code", "passphrase", "uuid", "credential", "credentials",
    "ro_community", "rw_community",
}
OLD_SUFFIX = {
    "key", "password", "secret", "psk", "token", "pass", "pwd", "pw",
    "pin", "community", "uuid",
}
OLD_CONTAINS = {
    "key", "password", "passwd", "psk", "secret", "passphrase",
    "private_key", "priv_key",
}
# triage #4 additions that must be named explicitly (deleting them from the
# catalog removes them from the generated loop below, so they are pinned here).
REQUIRED_EXACT = {"r0kh", "r1kh", "authkey", "apikey", "passphrase"}
ALLOW_NAMES = frozenset(
    {
        "authoritative",
        "auth_server",
        "auth_port",
        "auth_cache",
        "acct_server",
        "acct_port",
        "rsn_preauth",
        "maxauthtries",
        "no_ubusauth",
    }
)


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    redact.reset_key_cache()
    yield
    redact.reset_key_cache()


def catalog_rules():
    rules = []
    for raw in CATALOG.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        kind, _, word = line.partition(" ")
        rules.append((kind, word))
    return rules


def catalog_names():
    """Expand every rule into option names that must be masked."""
    names = []
    for kind, word in catalog_rules():
        if kind == "exact":
            names.extend([word, word.upper()])
        elif kind == "suffix":
            names.append("x_" + word)
        elif kind == "contains":
            names.append("x" + word + "y")
        elif kind == "allow":
            continue
        else:
            raise AssertionError(f"unknown catalog rule kind {kind!r}")
    return names


# ---- bash side: run the real mask_secrets from scripts/owrt-change.sh ------

BASH_FUNCTIONS = ("log", "mask", "oneline", "die", "load_secret_catalog", "mask_secrets")


def _extract_functions(script_text: str, wanted) -> str:
    out = []
    lines = script_text.splitlines(keepends=True)
    i = 0
    while i < len(lines):
        head = re.match(r"^([A-Za-z_]\w*)\(\)", lines[i])
        if head and head.group(1) in wanted:
            block = [lines[i]]
            if not lines[i].rstrip("\n").endswith("}"):
                i += 1
                while i < len(lines) and lines[i] != "}\n":
                    block.append(lines[i])
                    i += 1
                if i >= len(lines):
                    raise AssertionError(f"unterminated function block near {block[0]!r}")
                block.append(lines[i])
            out.append("".join(block))
        i += 1
    return "".join(out)


def bash_mask(lines: list[str], tmp_path: Path, catalog: Path = CATALOG) -> list[str]:
    """Run the real load_secret_catalog + mask_secrets in a bash subprocess."""
    harness = tmp_path / "mask-harness.sh"
    audit = tmp_path / "audit.log"
    harness.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f"ROUTER=catalog-test\nAUDIT={shlex_quote(str(audit))}\n"
        f"SECRET_CATALOG={shlex_quote(str(catalog))}\n"
        + _extract_functions(SCRIPT.read_text(), BASH_FUNCTIONS)
        + "\nload_secret_catalog\n"
        "while IFS= read -r line || [[ -n $line ]]; do mask_secrets \"$line\"; done\n"
    )
    result = subprocess.run(
        ["/usr/bin/env", "bash", str(harness)],
        input="\n".join(lines) + ("\n" if lines else ""),
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.splitlines()


def shlex_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


# ---- the point of the round: every catalog name through both maskers -------

@pytest.mark.parametrize("name", catalog_names())
def test_every_catalog_name_is_masked_by_redact(name):
    for form in (
        f"uci set a.b.{name}={SECRET_VALUE}",
        f"\toption {name} '{SECRET_VALUE}'",
        f"{name}={SECRET_VALUE}",
    ):
        out = redact.redact_text(form)
        assert SECRET_VALUE not in out, f"{name!r} leaked in {form!r}: {out!r}"
        assert "<redacted:" in out


@pytest.mark.parametrize("name", catalog_names())
def test_every_catalog_name_is_masked_by_bash_mask_secrets(name, tmp_path):
    line = f"pkg.sec.{name}='{SECRET_VALUE}'"
    (out,) = bash_mask([line], tmp_path)
    assert SECRET_VALUE not in out
    assert out == f"pkg.sec.{name}='<masked>'"


@pytest.mark.parametrize("name", sorted(REQUIRED_EXACT | {n.upper() for n in REQUIRED_EXACT}))
def test_triage4_names_are_masked_by_both_maskers(name, tmp_path):
    for form in (
        f"uci set a.b.{name}={SECRET_VALUE}",
        f"\toption {name} '{SECRET_VALUE}'",
        f"{name}={SECRET_VALUE}",
    ):
        assert SECRET_VALUE not in redact.redact_text(form)
    line = f"pkg.sec.{name}='{SECRET_VALUE}'"
    (out,) = bash_mask([line], tmp_path)
    assert out == f"pkg.sec.{name}='<masked>'"
    assert SECRET_VALUE not in out


@pytest.mark.parametrize("name", sorted({"hostname", "proto", "ipaddr"} | ALLOW_NAMES))
def test_non_secret_names_pass_through_both_maskers(name, tmp_path):
    for form in (
        f"uci set a.b.{name}={SECRET_VALUE}",
        f"\toption {name} '{SECRET_VALUE}'",
        f"{name}={SECRET_VALUE}",
    ):
        assert redact.redact_text(form) == form
    line = f"pkg.sec.{name}='{SECRET_VALUE}'"
    (out,) = bash_mask([line], tmp_path)
    assert out == line


@pytest.mark.parametrize("name", ["Auth-Server", "MaxAuthTries"])
def test_allow_names_are_normalized_before_both_maskers(name, tmp_path):
    for form in (
        f"uci set a.b.{name}={SECRET_VALUE}",
        f"\toption {name} '{SECRET_VALUE}'",
        f"{name}={SECRET_VALUE}",
    ):
        assert redact.redact_text(form) == form
    line = f"pkg.sec.{name}='{SECRET_VALUE}'"
    (out,) = bash_mask([line], tmp_path)
    assert out == line


# ---- new contains rules (added 2026-10-10): token / community / uuid / pwd
# Catalog names that CONTAIN one of the four new words must be redacted by
# BOTH maskers (triage #4 -- a name with `token` inside should be as secret
# as an option named exactly `token`).  pin and pw remain exact-only on
# purpose; this test asserts the four added names specifically.


@pytest.mark.parametrize(
    "name",
    ["x_token_y", "my_community_z", "a_uuid_b", "the_pwd_value", "x_credential_y"],
)
def test_new_contains_words_are_masked_by_both_maskers(name, tmp_path):
    for form in (
        f"uci set a.b.{name}={SECRET_VALUE}",
        f"\toption {name} '{SECRET_VALUE}'",
        f"{name}={SECRET_VALUE}",
    ):
        out = redact.redact_text(form)
        assert SECRET_VALUE not in out, f"{name!r} leaked in {form!r}: {out!r}"
        assert "<redacted:" in out
    line = f"pkg.sec.{name}='{SECRET_VALUE}'"
    (out,) = bash_mask([line], tmp_path)
    assert SECRET_VALUE not in out, out
    assert out == line.replace(SECRET_VALUE, "<masked>"), out


def test_bash_masks_the_full_fail_closed_set_in_one_load(tmp_path):
    lines = [
        "wireless.default_radio0.r0kh='ro-secret'",
        "wireless.default_radio0.r1kh+='r1-secret'",
        "system.cfg.authkey^='auth-secret'",
        "rpcd.login.apikey-='api-secret'",
        "system.x.wpa_passphrase='pass-secret'",
        "dhcp.lab.limit='60'",
    ]
    out = bash_mask(lines, tmp_path)
    assert out == [
        "wireless.default_radio0.r0kh='<masked>'",
        "wireless.default_radio0.r1kh+='<masked>'",
        "system.cfg.authkey^='<masked>'",
        "rpcd.login.apikey-='<masked>'",
        "system.x.wpa_passphrase='<masked>'",
        "dhcp.lab.limit='60'",
    ]
    joined = "\n".join(out)
    for value in ("ro-secret", "r1-secret", "auth-secret", "api-secret", "pass-secret"):
        assert value not in joined


# ---- catalog layout: every line parses, nothing old was dropped ------------

def test_catalog_file_parses_and_keeps_every_old_name():
    exact, suffix, contains, allow = redact._load_secret_catalog(CATALOG)
    assert OLD_EXACT <= exact
    assert REQUIRED_EXACT <= exact
    assert OLD_SUFFIX <= suffix
    assert OLD_CONTAINS <= contains
    assert ALLOW_NAMES <= allow
    # every line parses as a rule (loader raises on comments-only is fine;
    # this file has real rules of all three kinds)
    assert exact and suffix and contains


def test_allow_rules_never_duplicate_exact_secret_rules():
    rules = catalog_rules()
    allow = {word for kind, word in rules if kind == "allow"}
    exact = {word for kind, word in rules if kind == "exact"}
    assert ALLOW_NAMES <= allow
    assert allow.isdisjoint(exact)


def test_catalog_loader_accepts_allow_and_allows_an_empty_list(tmp_path):
    required = "exact key\nsuffix pass\ncontains auth\n"
    empty = tmp_path / "empty-allow.txt"
    empty.write_text(required)
    assert redact._load_secret_catalog(empty)[-1] == frozenset()

    populated = tmp_path / "allow.txt"
    populated.write_text(required + "allow auth_server\n")
    assert redact._load_secret_catalog(populated)[-1] == frozenset({"auth_server"})


@pytest.mark.parametrize(
    "content, message",
    [
        (None, "unreadable"),  # missing file
        ("# only a comment\n", "empty"),
        ("exact key\nbogus key\n", "not 'exact"),
        ("exact key\nsuffix pass\ncontains KEY\n", "not 'exact"),
    ],
)
def test_malformed_catalog_makes_the_loader_fail_closed(tmp_path, content, message):
    path = tmp_path / "secret_names.txt"
    if content is not None:
        path.write_text(content)
    with pytest.raises(RuntimeError, match=message):
        redact._load_secret_catalog(path)


def test_unknown_catalog_kind_fails_closed_in_both_parsers(tmp_path):
    catalog = tmp_path / "secret_names.txt"
    catalog.write_text("exact key\nsuffix pass\ncontains auth\nallow auth_server\nbogus key\n")
    with pytest.raises(RuntimeError, match="not 'exact"):
        redact._load_secret_catalog(catalog)

    harness = tmp_path / "load-harness.sh"
    harness.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f"ROUTER=catalog-test\nAUDIT={shlex_quote(str(tmp_path / 'audit.log'))}\n"
        f"SECRET_CATALOG={shlex_quote(str(catalog))}\n"
        + _extract_functions(SCRIPT.read_text(), BASH_FUNCTIONS)
        + "\nload_secret_catalog\n"
    )
    result = subprocess.run(
        ["/usr/bin/env", "bash", str(harness)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
    )
    assert result.returncode != 0
    assert "secret-name catalog" in result.stdout


def test_missing_catalog_makes_redact_import_raise(tmp_path):
    """A copy of the package without secret_names.txt must fail at import."""
    package = tmp_path / "newton_mcp"
    shutil.copytree(REPO / "mcp" / "newton_mcp", package)
    (package / "secret_names.txt").unlink()
    result = subprocess.run(
        [sys.executable, "-c", "import newton_mcp.redact"],
        env={**os.environ, "PYTHONPATH": str(tmp_path)},
        cwd=tmp_path, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=60,
    )
    assert result.returncode != 0
    assert "secret-name catalog" in result.stderr


# ---- owrt-change.sh fails closed at startup ---------------------------------

def _make_layout(tmp_path: Path, catalog_text: str | None):
    (tmp_path / "scripts").mkdir()
    shutil.copy2(SCRIPT, tmp_path / "scripts" / "owrt-change.sh")
    pkg = tmp_path / "mcp" / "newton_mcp"
    pkg.mkdir(parents=True)
    if catalog_text is not None:
        (pkg / "secret_names.txt").write_text(catalog_text)


def _run_plan(tmp_path: Path, home: Path):
    changes = home / "change.uci"
    changes.write_text("set system.@system[0].hostname='x'\n")
    return subprocess.run(
        [str(tmp_path / "scripts" / "owrt-change.sh"), "plan", "root@192.0.2.1", str(changes)],
        env={
            "PATH": os.environ["PATH"],
            "HOME": str(home),
            "XDG_STATE_HOME": str(home / "state"),
        },
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
    )


def test_missing_catalog_kills_owrt_change_plan_at_startup(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    _make_layout(tmp_path, None)
    result = _run_plan(tmp_path, home)
    assert result.returncode == 1
    assert "secret-name catalog" in result.stdout
    assert SECRET_VALUE not in result.stdout


def test_unknown_catalog_kind_kills_owrt_change_plan_at_startup(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    _make_layout(tmp_path, "exact key\nfrobnicate key\n")
    result = _run_plan(tmp_path, home)
    assert result.returncode == 1
    assert "secret-name catalog" in result.stdout
