"""The Samba AD collector (SPEC-1.3 section 7).

The samba python bindings are not installed on this machine, so the
tests run the collector against the fakes of ``fake_samba.py``: they
reproduce the shapes the lab DC was measured with (``domain_dn`` returns
a str, ``get_config_basedn`` returns an object whose ``str()`` is the
DN, the keys of a result hold ``"dn"``, every value is bytes and an
``LdbError`` carries ``(32, "...")``).

The tests here are the ones the spec asks for: the document a full
run produces must satisfy the contract of ``wire.parse``, every status
and error code must be the one of the contract, the deadline must
truncate, a binary value must be base64 and a text value text, the
settings must be the nine parameters of the spec, an argument must be
refused, stdin must never be read, an unsafe install must be refused, a
hostile Groups.xml must be refused and a cpassword must be counted
without its value ever reaching the document.
"""

from __future__ import annotations

import base64
import contextlib
import importlib.machinery
import importlib.util
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

import fake_samba
import measured
from newton_mcp.ad import catalogue, forbidden, model, queryset, wire


COLLECTOR_PATH = (
    Path(__file__).resolve().parents[2]
    / "newton_mcp"
    / "ad"
    / "collector"
    / "newton-ad-samba"
)

MODULE_NAMES = (
    "ldb",
    "samba",
    "samba.samdb",
    "samba.auth",
    "samba.ndr",
    "samba.param",
    "samba.dcerpc",
    "samba.dcerpc.security",
    "samba.dcerpc.misc",
)


def load_collector():
    """The collector as a module.

    The collector is a program without a ``.py`` suffix, so it is loaded
    from its path.  It imports the samba bindings inside its run, so
    loading it here needs no bindings at all.
    """
    loader = importlib.machinery.SourceFileLoader(
        "newton_ad_samba", str(COLLECTOR_PATH)
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@pytest.fixture
def fake():
    """The fake samba and ldb modules, and a fresh fake directory."""
    saved = {name: sys.modules.get(name) for name in MODULE_NAMES}
    fake_samba.reset()
    fake_samba.install()
    try:
        yield fake_samba
    finally:
        for name, module in saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


@pytest.fixture
def collector():
    """The collector module."""
    return load_collector()


@pytest.fixture
def install(tmp_path: Path, collector, monkeypatch) -> Path:
    """The installed files of the collector, in a temporary tree.

    The install check wants the files and the two directories to be
    owned by root.  The test runs as the maintainer, so the uid the
    collector wants is patched to the uid of the test.  The parents of
    the install are checked as well, so the walk of them stops at the
    root of the temporary tree.
    """
    sbin = tmp_path / "sbin"
    lib = tmp_path / "lib" / "newton-ad"
    sbin.mkdir()
    lib.mkdir(parents=True)
    (sbin / "newton-ad-samba").write_bytes(COLLECTOR_PATH.read_bytes())
    (lib / "queries.json").write_bytes(queryset.QUERIES_PATH.read_bytes())
    (lib / "forbidden.json").write_bytes(forbidden.dump_json())
    # The umask of the machine may make a group write, and the install
    # check refuses that.  The setup script installs the same modes.
    sbin.chmod(0o755)
    lib.chmod(0o755)
    (sbin / "newton-ad-samba").chmod(0o755)
    (lib / "queries.json").chmod(0o644)
    (lib / "forbidden.json").chmod(0o644)
    monkeypatch.setattr(collector, "INSTALL_OWNER_UID", os.getuid())
    monkeypatch.setattr(collector, "SBIN_DIR", str(sbin))
    monkeypatch.setattr(collector, "LIB_DIR", str(lib))
    monkeypatch.setattr(collector, "INSTALL_ROOT", str(tmp_path))
    return lib


@pytest.fixture
def sysvol(tmp_path: Path, fake) -> Path:
    """The SYSVOL tree of the fake DC."""
    fake.PARM["path"] = str(tmp_path)
    policies = tmp_path / "sysvol" / "lab.newton.test" / "Policies"
    policies.mkdir(parents=True)
    return policies


def run(collector, capsys, monkeypatch, argv=(), sudo_user="newton-ssh"):
    """Run the collector and return its code, its stdout and its stderr."""
    if sudo_user is None:
        monkeypatch.delenv("SUDO_USER", raising=False)
    else:
        monkeypatch.setenv("SUDO_USER", sudo_user)
    code = collector.main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def document_of(out: str):
    """The document of a run, checked against the contract."""
    return wire.parse(out.encode("utf-8"), queryset.load())


# ---- the document -----------------------------------------------------------


def test_a_full_run_produces_a_document_the_contract_accepts(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """The document of a full run over the fake satisfies the contract."""
    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    document = document_of(out)
    assert document.collector == "samba"
    assert document.collector_version == "1.3.0"
    assert document.querysetsha == queryset.load().sha256
    assert set(document.queries) == set(queryset.load().ids)
    assert document.is_dc is True


def test_the_document_names_the_domain_of_the_dc(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """The naming contexts of the document are the ones of the DC."""
    _, out, _ = run(collector, capsys, monkeypatch)

    document = document_of(out)
    assert document.domain.domain_dn == fake_samba.DOMAIN_DN
    assert document.domain.config_dn == fake_samba.CONFIG_DN
    assert document.domain.schema_dn == fake_samba.SCHEMA_DN
    assert document.domain.domain_sid == fake_samba.DOMAIN_SID
    assert document.domain.dns == fake_samba.DOMAIN_DNS


def test_the_identity_is_the_domain_account(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """The identity is the domain account, with its token groups.

    The account that logs in is the local one, ``newton-ssh``, and the
    identity of the document is the domain account ``newton-audit``.
    """
    _, out, _ = run(collector, capsys, monkeypatch)

    document = document_of(out)
    assert document.identity.user == fake_samba.AUDIT_NAME
    assert document.identity.user == "newton-audit"
    assert document.identity.sid == fake_samba.AUDIT_SID
    assert fake_samba.DOMAIN_USERS_SID in document.identity.token_group_sids


def test_the_names_of_the_two_accounts_are_module_constants(collector) -> None:
    """The login account and the domain account are named in the module.

    They are two accounts and not one, and the collector needs both of
    them: the one that logs in and the one the identity is read from.
    """
    assert collector.LOGIN_NAME == "newton-ssh"
    assert collector.AUDIT_NAME == "newton-audit"


def test_a_run_without_a_sudo_user_produces_no_document(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """Without SUDO_USER there is no identity, so there is no document."""
    code, out, err = run(collector, capsys, monkeypatch, sudo_user=None)

    assert code == 1
    assert out == ""
    assert err.strip() != ""


def test_a_sudo_user_that_is_not_the_login_account_produces_no_document(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A SUDO_USER that is not newton-ssh is refused.

    The account that logs in is the local one.  The domain account
    resolves locally as well, so a run under it would be a run of a
    different account than the one the key belongs to.
    """
    code, out, err = run(
        collector, capsys, monkeypatch, sudo_user="newton-audit"
    )

    assert code == 1
    assert out == ""
    assert err.strip() != ""


def test_the_document_is_one_line_of_json(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """The document is compact JSON with one newline at the end."""
    _, out, _ = run(collector, capsys, monkeypatch)

    assert out.endswith("\n")
    assert out.count("\n") == 1
    assert ", " not in out
    payload = json.loads(out)
    assert payload["collector"] == "samba"


def test_the_document_never_carries_a_password_attribute(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """The presence query finds the account and reads no password."""
    _, out, _ = run(collector, capsys, monkeypatch)

    document = document_of(out)
    result = document.queries["pw_attr_presence"]
    assert result.status == "ok"
    assert result.rows
    for row in result.rows:
        assert set(row.a) <= {"objectSid"}


# ---- the status and the error code -----------------------------------------


def test_a_query_the_directory_does_not_hold_is_unavailable(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A missing object is ``unavailable`` with the code ``no_such_object``."""
    fake.FAILURES["(objectClass=foreignSecurityPrincipal)"] = (
        32,
        "No such object",
    )

    _, out, _ = run(collector, capsys, monkeypatch)

    result = document_of(out).queries["fsps"]
    assert result.status == "unavailable"
    assert result.error_code == "no_such_object"
    assert result.rows == ()


def test_an_access_error_is_denied(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """An access error is ``denied`` with the code ``access_denied``."""
    fake.FAILURES["(objectClass=group)"] = (50, "Access denied")

    _, out, _ = run(collector, capsys, monkeypatch)

    result = document_of(out).queries["groups"]
    assert result.status == "denied"
    assert result.error_code == "access_denied"


def test_another_error_is_an_error(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """Every other error is ``error`` with the code ``other``."""
    fake.FAILURES["(objectClass=group)"] = (80, "Something else went wrong")

    _, out, _ = run(collector, capsys, monkeypatch)

    result = document_of(out).queries["groups"]
    assert result.status == "error"
    assert result.error_code == "other"


def test_the_text_of_an_error_never_reaches_the_document(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """No exception text is ever printed."""
    fake.FAILURES["(objectClass=group)"] = (50, "Access denied on the group")

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0
    assert "Access denied on the group" not in out
    assert "Access denied on the group" not in err


# ---- the deadline -----------------------------------------------------------


def test_the_deadline_truncates_every_remaining_query(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """When the deadline passes, every query is ``truncated``."""
    monkeypatch.setattr(collector, "DEADLINE_SECONDS", 0)

    _, out, _ = run(collector, capsys, monkeypatch)

    document = document_of(out)
    for result in document.queries.values():
        assert result.status == "truncated"
        assert result.error_code == "time_limit"
        assert result.rows == ()
    assert document.files["gpp"].status == "truncated"
    assert document.files["gpp"].error_code == "time_limit"
    assert document.files["gpttmpl"].status == "truncated"
    assert document.files["gpttmpl"].error_code == "time_limit"


# ---- the encoding -----------------------------------------------------------


def test_a_binary_value_is_base64_and_a_text_value_is_text(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """The binary attributes are base64 and the other ones are text."""
    _, out, _ = run(collector, capsys, monkeypatch)

    document = document_of(out)
    row = document.queries["users"].rows[0]
    assert base64.b64decode(row.a["objectSid"][0]) == fake_samba.sid_bytes(
        fake_samba.AUDIT_SID
    )
    assert row.a["sAMAccountName"] == ("newton-audit",)
    assert row.a["userAccountControl"] == ("512",)
    assert row.a["whenCreated"] == ("20261108024224.0Z",)


def test_a_value_that_is_not_utf8_makes_the_query_an_error(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A value that does not decode makes the query ``error``."""
    for obj in fake_samba.OBJECTS:
        if obj.dn.startswith("CN=Administrator,"):
            obj.attributes["sAMAccountName"] = [b"\xff\xfe\x00bad"]

    _, out, _ = run(collector, capsys, monkeypatch)

    result = document_of(out).queries["users"]
    assert result.status == "error"
    assert result.error_code == "other"
    assert result.rows == ()


# ---- the settings -----------------------------------------------------------


def test_the_settings_are_the_nine_parameters_of_the_spec(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """The settings are the nine loadparm parameters, in order."""
    _, out, _ = run(collector, capsys, monkeypatch)

    section = document_of(out).settings
    assert section.status == "ok"
    assert section.error_code == ""
    assert [item.key for item in section.items] == [
        "ldap server require strong auth",
        "ntlm auth",
        "server signing",
        "server min protocol",
        "kerberos encryption types",
        "allow nt4 crypto",
        "reject md5 clients",
        "server schannel",
        "tls enabled",
    ]
    assert all(item.source == "loadparm" for item in section.items)


def test_a_boolean_setting_is_written_as_true_or_false(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A boolean setting is TRUE or FALSE, and a text one is text."""
    _, out, _ = run(collector, capsys, monkeypatch)

    values = {item.key: item.value for item in document_of(out).settings.items}
    assert values["allow nt4 crypto"] == "FALSE"
    assert values["reject md5 clients"] == "TRUE"
    assert values["tls enabled"] == "TRUE"
    assert values["ldap server require strong auth"] == "Yes"
    assert values["ntlm auth"] == "ntlmv2-only"
    assert values["server min protocol"] == "SMB2_02"


def test_the_settings_are_not_collected_when_the_host_is_not_a_dc(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A host that is not a DC collects no settings."""
    fake.PARM["server role"] = "member server"

    _, out, _ = run(collector, capsys, monkeypatch)

    section = document_of(out).settings
    assert section.status == "not_collected"
    assert section.error_code == "not_a_dc"
    assert section.items == ()


# ---- the input --------------------------------------------------------------


def test_an_argument_is_refused_with_exit_2() -> None:
    """The collector takes no argument at all."""
    result = subprocess.run(
        [sys.executable, str(COLLECTOR_PATH), "--anything"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert "takes no arguments" in result.stderr


def test_a_run_without_an_install_produces_no_document() -> None:
    """Without the installed files there is no document."""
    result = subprocess.run(
        [sys.executable, str(COLLECTOR_PATH)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert result.stdout == ""


def test_the_collector_never_reads_stdin(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """The collector never reads stdin."""
    class Exploding:
        def read(self, *args, **kwargs):
            raise AssertionError("the collector read stdin")

        def readline(self, *args, **kwargs):
            raise AssertionError("the collector read stdin")

        def readlines(self, *args, **kwargs):
            raise AssertionError("the collector read stdin")

        def __iter__(self):
            raise AssertionError("the collector read stdin")

    monkeypatch.setattr(sys, "stdin", Exploding())

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    assert out


def test_the_source_of_the_collector_never_names_stdin() -> None:
    """The collector names no standard input at all."""
    text = COLLECTOR_PATH.read_text(encoding="utf-8").lower()

    assert "stdin" not in text
    assert "input(" not in text


# ---- the install ------------------------------------------------------------


def test_an_install_that_may_be_written_is_refused(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A file that its group may write is not a safe install."""
    target = install / "queries.json"
    target.chmod(0o664)

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 2
    assert out == ""
    assert "the install is not safe" in err


def test_an_install_that_is_not_owned_by_root_is_refused(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A file that root does not own is not a safe install."""
    monkeypatch.setattr(collector, "INSTALL_OWNER_UID", os.getuid() + 1)

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 2
    assert out == ""
    assert "the install is not safe" in err


def test_a_directory_of_the_install_that_may_be_written_is_refused(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A directory that others may write is not a safe install."""
    install.chmod(0o777)

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 2
    assert out == ""
    assert "the install is not safe" in err


def test_a_query_set_that_asks_for_a_forbidden_attribute_is_refused(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A query set that asks for a password attribute is refused."""
    queries = json.loads((install / "queries.json").read_text(encoding="utf-8"))
    queries["queries"][1]["attrs"].append("unicodePwd")
    (install / "queries.json").write_text(json.dumps(queries), encoding="utf-8")

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 2
    assert out == ""
    assert "forbidden attribute" in err


def test_a_query_set_whose_filter_names_a_forbidden_attribute_is_refused(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A filter that names a password attribute is refused."""
    queries = json.loads((install / "queries.json").read_text(encoding="utf-8"))
    queries["queries"][1]["filter"] = "(&(objectClass=user)(unicodePwd=*))"
    (install / "queries.json").write_text(json.dumps(queries), encoding="utf-8")

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 2
    assert out == ""
    assert "forbidden attribute" in err


# ---- the SYSVOL scan --------------------------------------------------------


def _write_gpo(policies: Path, guid: str, files: dict[str, str]) -> Path:
    """Write the files of one GPO and return its directory."""
    directory = policies / guid
    directory.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return directory


def test_a_cpassword_is_counted_and_its_value_never_reaches_the_document(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A cpassword is counted on the DC and its value never leaves it."""
    secret = "P@ssw0rd-that-must-never-be-seen"
    _write_gpo(
        sysvol,
        "{4A06E176-48DD-4B65-B2B0-214B24EB0F59}",
        {
            "Machine/Preferences/Groups/Groups.xml": (
                '<?xml version="1.0" encoding="utf-8"?>\n'
                "<GroupPolicyContainer>\n"
                '  <Machine><Group><GroupSettings>'
                f'<Setting name="cpassword" cpassword="{secret}"/>'
                "</GroupSettings></Group></Machine>\n"
                "</GroupPolicyContainer>\n"
            )
        },
    )

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    document = document_of(out)
    section = document.files["gpp"]
    assert section.status == "ok"
    assert len(section.items) == 1
    item = section.items[0]
    assert item.kind == "cpassword"
    assert item.count == 1
    assert item.gpo == "{4A06E176-48DD-4B65-B2B0-214B24EB0F59}"
    assert item.path == "Machine/Preferences/Groups/Groups.xml"
    assert secret not in out


def test_the_scan_finds_the_file_of_a_gpo_folder_in_upper_case(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """Samba provisions the folders of a GPO in upper case.

    Measured on the lab DC: the folders of a GPO are ``MACHINE`` and
    ``USER``, and the scan finds the file under them and reports the
    path the way the Windows collector reports it.
    """
    secret = "P@ssw0rd-that-must-never-be-seen"
    _write_gpo(
        sysvol,
        "{4A06E176-48DD-4B65-B2B0-214B24EB0F59}",
        {
            "MACHINE/Preferences/Groups/Groups.xml": (
                '<?xml version="1.0" encoding="utf-8"?>\n'
                "<GroupPolicyContainer>\n"
                "  <Machine><Group><GroupSettings>"
                f'<Setting name="cpassword" cpassword="{secret}"/>'
                "</GroupSettings></Group></Machine>\n"
                "</GroupPolicyContainer>\n"
            )
        },
    )

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    document = document_of(out)
    section = document.files["gpp"]
    assert section.status == "ok"
    assert len(section.items) == 1
    item = section.items[0]
    assert item.kind == "cpassword"
    assert item.count == 1
    assert item.path == "Machine/Preferences/Groups/Groups.xml"
    assert secret not in out


def test_an_autologon_entry_is_counted(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A Registry.xml with a DefaultPassword is an autologon entry."""
    _write_gpo(
        sysvol,
        "{4A06E176-48DD-4B65-B2B0-214B24EB0F59}",
        {
            "Machine/Preferences/Registry.xml": (
                '<?xml version="1.0" encoding="utf-8"?>\n'
                "<Registry>\n"
                '  <Properties name="DefaultPassword" type="Expandable"'
                ' value="secret"/>\n'
                "</Registry>\n"
            )
        },
    )

    _, out, _ = run(collector, capsys, monkeypatch)

    items = document_of(out).files["gpp"].items
    assert len(items) == 1
    assert items[0].kind == "autologon"
    assert items[0].count == 1


def test_a_hostile_groups_xml_is_refused(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A file with a DTD or an entity is refused and never parsed."""
    secret = "P@ssw0rd-that-must-never-be-seen"
    _write_gpo(
        sysvol,
        "{4A06E176-48DD-4B65-B2B0-214B24EB0F59}",
        {
            "Machine/Preferences/Groups/Groups.xml": (
                '<?xml version="1.0" encoding="utf-8"?>\n'
                '<!DOCTYPE GroupPolicyContainer [\n'
                '  <!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
                "<GroupPolicyContainer>\n"
                '  <Machine><Group><GroupSettings>'
                f'<Setting name="cpassword" cpassword="{secret}"/>'
                "</GroupSettings></Group></Machine>\n"
                "</GroupPolicyContainer>\n"
            )
        },
    )

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    section = document_of(out).files["gpp"]
    assert section.status == "ok"
    assert section.items == ()
    raw = json.loads(out)["files"]["gpp"]
    assert raw["parse_refused"] == 1
    assert secret not in out


def test_a_folder_that_is_not_a_gpo_is_skipped_and_counted(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A folder whose name is not a GUID is skipped and counted."""
    (sysvol / "not-a-guid").mkdir()

    _, out, _ = run(collector, capsys, monkeypatch)

    section = document_of(out).files["gpp"]
    assert section.skipped_nonguid == 1
    assert section.items == ()


def test_a_gpttmpl_is_read_as_utf16(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """The GptTmpl.inf of a GPO is read, and it is read as UTF-16.

    Only the keys the checks read are emitted, and only when their
    value is a number.
    """
    directory = _write_gpo(
        sysvol,
        "{31B2F340-016D-11D2-945F-00C04FB984F9}",
        {},
    )
    inf = directory / "Machine" / "Microsoft" / "Windows NT" / "SecEdit"
    inf.mkdir(parents=True, exist_ok=True)
    text = (
        "[System Access]\r\n"
        "MinimumPasswordAge=1\r\n"
        "\r\n"
        "[Kerberos Policy]\r\n"
        "MaxTicketAge=10\r\n"
        "MaxRenewAge=7\r\n"
        "MaxServiceAge=600\r\n"
        "MaxClockSkew=5\r\n"
    )
    (inf / "GptTmpl.inf").write_bytes(text.encode("utf-16"))

    _, out, _ = run(collector, capsys, monkeypatch)

    items = document_of(out).files["gpttmpl"].items
    assert len(items) == 4
    assert items[0].gpo == "{31B2F340-016D-11D2-945F-00C04FB984F9}"
    assert items[0].section == "Kerberos Policy"
    assert items[0].key == "MaxTicketAge"
    assert items[0].value == "10"
    assert items[1].key == "MaxRenewAge"
    assert items[1].value == "7"
    assert items[2].key == "MaxServiceAge"
    assert items[2].value == "600"
    assert items[3].key == "MaxClockSkew"
    assert items[3].value == "5"


def test_a_missing_sysvol_is_unavailable(
    collector, install, fake, capsys, monkeypatch
) -> None:
    """A host without a SYSVOL reports it as unavailable."""
    fake.PARM["path"] = "/nonexistent-sysvol"

    _, out, _ = run(collector, capsys, monkeypatch)

    document = document_of(out)
    assert document.files["gpp"].status == "unavailable"
    assert document.files["gpp"].error_code == "no_such_object"
    assert document.files["gpttmpl"].status == "unavailable"


# ---- the searches ------------------------------------------------------------


def test_the_descriptor_control_is_asked_for_only_when_it_is_wanted(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """The control of the descriptor is asked for only by the queries that
    want a descriptor."""
    run(collector, capsys, monkeypatch)

    context = {
        "domain_dn": fake_samba.DOMAIN_DN,
        "config_dn": fake_samba.CONFIG_DN,
        "schema_dn": fake_samba.SCHEMA_DN,
    }
    queries = queryset.load()
    for call in fake_samba.CALLS:
        wanted = [
            query
            for query in queries.queries
            if query.filter == call.expression
            and _expand(query.base, context) == call.base
        ]
        if not wanted:
            continue
        query = wanted[0]
        if query.sd:
            assert "sd_flags:1:5" in call.controls
        else:
            assert "sd_flags:1:5" not in call.controls


def _expand(template: str, context: dict) -> str:
    """A base of the query set, with the naming contexts in it."""
    text = template
    for placeholder, name in (
        ("{domain}", "domain_dn"),
        ("{config}", "config_dn"),
        ("{schema}", "schema_dn"),
    ):
        text = text.replace(placeholder, context[name])
    return text


def test_the_identity_is_looked_up_by_the_audit_account(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """The account is looked up by its name, escaped for the filter."""
    run(collector, capsys, monkeypatch)

    lookups = [
        call
        for call in fake_samba.CALLS
        if call.expression.startswith("(sAMAccountName=")
    ]
    assert len(lookups) == 1
    assert lookups[0].expression == "(sAMAccountName=newton-audit)"
    assert lookups[0].base == fake_samba.DOMAIN_DN


def test_the_searches_ask_for_a_page_of_five_hundred_rows(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """Every search of the query set asks for the page of the spec."""
    run(collector, capsys, monkeypatch)

    context = {
        "domain_dn": fake_samba.DOMAIN_DN,
        "config_dn": fake_samba.CONFIG_DN,
        "schema_dn": fake_samba.SCHEMA_DN,
    }
    queries = queryset.load()
    for call in fake_samba.CALLS:
        wanted = [
            query
            for query in queries.queries
            if query.filter == call.expression
            and _expand(query.base, context) == call.base
        ]
        if not wanted:
            continue
        assert "paged_results:1:500" in call.controls


def test_the_collector_asks_again_with_the_other_name_of_the_filter(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """The older bindings name the filter of a search ``expressions``.

    The collector asks with the name of the newer bindings and falls
    back to the name of the older ones, so a Samba that names it the
    other way still produces a document.
    """

    class OldSamDB(fake_samba.FakeSamDB):
        def search(
            self,
            base=None,
            scope=None,
            expressions=None,
            attrs=None,
            controls=None,
        ):
            return fake_samba.FakeSamDB.search(
                self,
                base=base,
                scope=scope,
                expression=expressions,
                attrs=attrs,
                controls=controls,
            )

    monkeypatch.setattr(sys.modules["samba.samdb"], "SamDB", OldSamDB)

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    document = document_of(out)
    assert document.queries["users"].rows


def test_the_sid_is_built_the_other_way_when_the_unpack_fails(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """The collector builds a SID with the dom_sid of the bindings when
    the unpack of the NDR object is not there."""

    def broken_unpack(_cls, _raw):
        raise TypeError("no unpack here")

    monkeypatch.setattr(sys.modules["samba.ndr"], "ndr_unpack", broken_unpack)

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    document = document_of(out)
    assert document.identity.sid == fake_samba.AUDIT_SID
    assert fake_samba.DOMAIN_USERS_SID in document.identity.token_group_sids


# ---- the bindings of the lab DC (measured 2026-11-08) -----------------------


def test_the_session_comes_from_the_module_the_bindings_have(fake) -> None:
    """The real bindings offer ``samba.auth.system_session``.

    Measured on the lab DC (Samba 4.22.11): ``from samba.auth import
    system_session`` works and there is no ``samba.auth.system`` module
    at all.
    """
    from samba.auth import system_session

    assert system_session() == "system-session"
    assert "samba.auth.system" not in sys.modules
    with pytest.raises(ImportError):
        importlib.import_module("samba.auth.system")


def test_the_collector_imports_the_session_where_the_bindings_have_it() -> None:
    """The collector asks for the session in the module that holds it."""
    text = COLLECTOR_PATH.read_text(encoding="utf-8")

    assert "from samba.auth import system_session" in text
    assert "samba.auth.system" not in text


def test_the_unpack_comes_from_the_module_the_bindings_have(fake) -> None:
    """The real bindings offer ``samba.ndr.ndr_unpack``.

    Measured on the lab DC: ``from samba.ndr import ndr_unpack`` works
    and ``samba.dcerpc.misc`` has no ``ndr_unpack`` in it.
    """
    from samba.dcerpc import security
    from samba.ndr import ndr_unpack

    raw = fake_samba.sid_bytes(fake_samba.AUDIT_SID)
    assert str(ndr_unpack(security.dom_sid, raw)) == fake_samba.AUDIT_SID
    assert not hasattr(sys.modules["samba.dcerpc.misc"], "ndr_unpack")


def test_the_collector_imports_the_unpack_where_the_bindings_have_it() -> None:
    """The collector asks for the unpack in the module that holds it."""
    text = COLLECTOR_PATH.read_text(encoding="utf-8")

    assert "from samba.ndr import ndr_unpack" in text
    assert "samba.dcerpc.misc" not in text


def test_the_fake_escapes_a_value_the_way_the_bindings_escape_it(fake) -> None:
    """``ldb.binary_encode`` returns text, not bytes.

    Every byte that is not printable ASCII is escaped, and so are the
    three characters that carry a meaning in a filter.  The hexadecimal
    digits of the escape are in upper case, the way the bindings write
    them (measured on Samba 4.22.11: ``ldb.binary_encode("a*b(")`` is
    the str ``"a\\2Ab\\28"``).
    """
    import ldb

    escaped = ldb.binary_encode("a*b(")
    assert isinstance(escaped, str)
    assert escaped == "a\\2Ab\\28"


def test_the_fake_escapes_every_byte_that_is_not_printable_ascii(fake) -> None:
    """A byte outside of the printable ASCII is escaped in upper case.

    The escape is two hexadecimal digits in upper case, the way the
    bindings write it (``ldb.binary_encode("a\\x01b")`` is the str
    ``"a\\01b"``).
    """
    import ldb

    assert ldb.binary_encode("a\x01b") == "a\\01b"
    assert ldb.binary_encode("a\x7fb") == "a\\7Fb"
    assert ldb.binary_encode(b"a\xffb") == "a\\FFb"
    assert ldb.binary_encode("plain text 42") == "plain text 42"


def test_the_collector_escapes_a_filter_value_the_way_ldb_does(
    collector, fake
) -> None:
    """The collector takes the text of ``binary_encode`` as it is."""
    import ldb

    assert collector._escape(ldb, "a*b(") == "a\\2Ab\\28"


def test_the_identity_is_looked_up_with_the_escaping_of_ldb(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """The name of the account is escaped the way ldb escapes it."""
    monkeypatch.setattr(collector, "AUDIT_NAME", "a*b(")

    # No account has that name, so the run ends with exit 1: the search
    # that brought it is what is looked at.
    run(collector, capsys, monkeypatch)

    lookups = [
        call
        for call in fake_samba.CALLS
        if call.expression.startswith("(sAMAccountName=")
    ]
    assert len(lookups) == 1
    assert lookups[0].expression == "(sAMAccountName=a\\2Ab\\28)"


# ---- the security descriptor -----------------------------------------------


def test_the_search_of_a_query_that_wants_a_descriptor_asks_for_it(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """The search of a query that wants a descriptor asks for it.

    Real ldb returns only the attributes the search names, so the
    descriptor has to be one of them: the control alone does not bring
    it.
    """
    run(collector, capsys, monkeypatch)

    calls = [
        call
        for call in fake_samba.CALLS
        if call.expression == "(objectClass=*)"
        and call.base == fake_samba.DOMAIN_DN
    ]
    assert calls
    for call in calls:
        assert "ntsecuritydescriptor" in [name.lower() for name in call.attrs]


def test_a_query_that_wants_no_descriptor_asks_for_none(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A query that wants no descriptor does not ask for one."""
    run(collector, capsys, monkeypatch)

    calls = [
        call
        for call in fake_samba.CALLS
        if call.expression == "(&(objectCategory=person)(objectClass=user))"
    ]
    assert calls
    for call in calls:
        assert "ntsecuritydescriptor" not in [name.lower() for name in call.attrs]


def test_the_descriptor_is_not_asked_for_twice(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A query that asks for the descriptor by name asks for it once."""
    queries = json.loads((install / "queries.json").read_text(encoding="utf-8"))
    for query in queries["queries"]:
        if query["id"] == "domain_head":
            query["attrs"].append("nTSecurityDescriptor")
    (install / "queries.json").write_text(json.dumps(queries), encoding="utf-8")

    _, out, _ = run(collector, capsys, monkeypatch)

    calls = [
        call
        for call in fake_samba.CALLS
        if call.expression == "(objectClass=*)"
        and call.base == fake_samba.DOMAIN_DN
    ]
    assert calls
    for call in calls:
        names = [name.lower() for name in call.attrs]
        assert names.count("ntsecuritydescriptor") == 1
    # The query set of the install is not the one of the package, so the
    # document is read as it is and not through the contract.
    raw = json.loads(out)
    value = raw["queries"]["domain_head"]["rows"][0]["a"]["nTSecurityDescriptor"][0]
    assert base64.b64decode(value) == fake_samba.DOMAIN_DESCRIPTOR


def test_the_row_of_the_domain_head_carries_the_descriptor(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """The row of the domain head carries the descriptor of the DC."""
    _, out, _ = run(collector, capsys, monkeypatch)

    document = document_of(out)
    row = document.queries["domain_head"].rows[0]
    assert base64.b64decode(row.a["nTSecurityDescriptor"][0]) == (
        fake_samba.DOMAIN_DESCRIPTOR
    )


def test_the_row_of_the_admin_sd_holder_carries_the_descriptor(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """The row of the AdminSDHolder carries the descriptor of the DC."""
    _, out, _ = run(collector, capsys, monkeypatch)

    document = document_of(out)
    row = document.queries["adminsdholder"].rows[0]
    assert base64.b64decode(row.a["nTSecurityDescriptor"][0]) == (
        fake_samba.ADMINSDHOLDER_DESCRIPTOR
    )


def test_the_descriptor_is_base64_and_not_text(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """The descriptor is the base64 of its raw bytes."""
    _, out, _ = run(collector, capsys, monkeypatch)

    raw = json.loads(out)
    value = raw["queries"]["domain_head"]["rows"][0]["a"]["nTSecurityDescriptor"][0]
    assert base64.b64decode(value) == fake_samba.DOMAIN_DESCRIPTOR


# ---- the fake directory ----------------------------------------------------


def test_a_result_holds_only_the_attributes_that_were_asked_for(fake) -> None:
    """A result of the fake holds the attributes of the search only.

    Real ldb returns the attributes the search named and nothing else.
    """
    message = fake_samba.FakeMessage(
        fake_samba.OBJECTS[0], ["objectSid", "nTSecurityDescriptor"]
    )

    assert "objectSid" in message.keys()
    assert "nTSecurityDescriptor" in message.keys()
    assert "msDS-Behavior-Version" not in message.keys()
    assert "userPassword" not in message.keys()
    assert "dn" in message.keys()


def test_a_result_matches_the_attribute_names_without_their_case(fake) -> None:
    """The attributes of a result are matched without their case."""
    message = fake_samba.FakeMessage(fake_samba.OBJECTS[0], ["objectsid"])

    assert "objectSid" in message.keys()
    assert list(message["objectSid"]) == [
        fake_samba.sid_bytes(fake_samba.DOMAIN_SID)
    ]


# ---- the error codes of the bindings (measured on the lab DC) ---------------


# The error codes of the ldb, and the status and the error code of the
# document that each one has.  Measured on the lab DC (Samba 4.22.11):
# ERR_TIME_LIMIT_EXCEEDED=3, ERR_SIZE_LIMIT_EXCEEDED=4,
# ERR_NO_SUCH_OBJECT=32, ERR_INVALID_CREDENTIALS=49,
# ERR_INSUFFICIENT_ACCESS_RIGHTS=50, ERR_BUSY=51, ERR_UNAVAILABLE=52,
# ERR_UNWILLING_TO_PERFORM=53 and ERR_OTHER=80.
ERROR_CODES = (
    (32, "unavailable", "no_such_object"),
    (50, "denied", "access_denied"),
    (3, "truncated", "time_limit"),
    (4, "truncated", "size_limit"),
    (51, "unavailable", "server_down"),
    (52, "unavailable", "server_down"),
    (49, "error", "other"),
    (53, "error", "other"),
    (80, "error", "other"),
)


@pytest.mark.parametrize("code,status,error_code", ERROR_CODES)
def test_the_status_of_an_ldb_error_is_the_one_of_the_table(
    collector,
    install,
    sysvol,
    fake,
    capsys,
    monkeypatch,
    code,
    status,
    error_code,
) -> None:
    """Every ldb error code maps to the status and the code of the table.

    Measured on the lab DC: there is no ERR_ACCESS_DENIED, no
    ERR_INSUFFICIENT_ACCESS and no ERR_AUTH_ERROR, so the codes that
    mean something are the ones of the table.
    """
    fake.FAILURES["(objectClass=group)"] = (code, "the error of the lab DC")

    _, out, _ = run(collector, capsys, monkeypatch)

    result = document_of(out).queries["groups"]
    assert result.status == status
    assert result.error_code == error_code


def test_the_error_codes_of_the_fake_are_the_measured_ones(fake) -> None:
    """The fake offers the error codes the lab DC has, and no other.

    Measured on Samba 4.22.11: there is no ERR_ACCESS_DENIED, no
    ERR_INSUFFICIENT_ACCESS and no ERR_AUTH_ERROR.
    """
    import ldb

    assert ldb.ERR_TIME_LIMIT_EXCEEDED == 3
    assert ldb.ERR_SIZE_LIMIT_EXCEEDED == 4
    assert ldb.ERR_NO_SUCH_OBJECT == 32
    assert ldb.ERR_INVALID_CREDENTIALS == 49
    assert ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS == 50
    assert ldb.ERR_BUSY == 51
    assert ldb.ERR_UNAVAILABLE == 52
    assert ldb.ERR_UNWILLING_TO_PERFORM == 53
    assert ldb.ERR_OTHER == 80
    assert not hasattr(ldb, "ERR_ACCESS_DENIED")
    assert not hasattr(ldb, "ERR_INSUFFICIENT_ACCESS")
    assert not hasattr(ldb, "ERR_AUTH_ERROR")


def test_the_collector_never_names_an_error_code_that_does_not_exist(
    collector,
) -> None:
    """The collector asks for the error codes with getattr.

    A binding that does not carry one of the names must not break the
    collector, so no name is used as an attribute of the module.
    """
    text = COLLECTOR_PATH.read_text(encoding="utf-8")

    assert "getattr(ldb, name, None)" in text
    for name in ("ERR_ACCESS_DENIED", "ERR_INSUFFICIENT_ACCESS", "ERR_AUTH_ERROR"):
        assert "ldb." + name not in text


# ---- the loadparm (measured on the lab DC) ---------------------------------


def test_the_fake_takes_the_second_argument_as_a_share_name(fake) -> None:
    """The second argument of ``get`` is a share name, not a default.

    Measured on the lab DC (Samba 4.22.11): ``lp.get("realm")`` is the
    realm, ``lp.get("realm", "")`` is None and ``lp.get("path",
    "sysvol")`` is the path of the sysvol share.
    """
    lp = fake_samba.FakeLoadParm()

    assert lp.get("realm") == "LAB.NEWTON.TEST"
    assert lp.get("realm", "") is None
    assert lp.get("path", "sysvol") == "/var/lib/samba/sysvol"


def test_the_collector_asks_the_realm_without_a_default(collector) -> None:
    """The realm is asked with one argument only.

    The second argument of ``get`` is the name of a share, so a realm
    with a default would ask for a share that does not exist.
    """
    text = COLLECTOR_PATH.read_text(encoding="utf-8")

    assert 'lp.get("realm")' in text
    assert 'lp.get("realm", "")' not in text


def test_the_sysvol_of_the_realm_of_the_loadparm_is_read(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """The SYSVOL path is built with the realm of the loadparm.

    The realm of the lab DC is LAB.NEWTON.TEST and the tree of the
    fake is sysvol/lab.newton.test/Policies.
    """
    assert fake.PARM["realm"] == "LAB.NEWTON.TEST"

    _, out, _ = run(collector, capsys, monkeypatch)

    section = document_of(out).files["gpp"]
    assert section.status == "ok"
    assert section.error_code == ""


def test_a_realm_that_the_loadparm_does_not_hold_falls_back_to_the_dns_name(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """Without a realm in the loadparm the DNS name of the DC is used."""
    del fake.PARM["realm"]

    _, out, _ = run(collector, capsys, monkeypatch)

    section = document_of(out).files["gpp"]
    assert section.status == "ok"
    assert section.error_code == ""


def test_a_sysvol_path_that_is_not_absolute_is_unavailable(
    collector, install, sysvol, fake, capsys, monkeypatch, tmp_path: Path
) -> None:
    """A path that is not absolute is refused, and nothing is read.

    The tree that sits relative to the working directory must not be
    read, so the files are unavailable and not empty.
    """
    work = tmp_path / "work"
    (work / "sysvol" / "lab.newton.test" / "Policies").mkdir(parents=True)
    monkeypatch.chdir(work)
    fake.PARM["path"] = "relative/sysvol"

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    document = document_of(out)
    assert document.files["gpp"].status == "unavailable"
    assert document.files["gpp"].error_code == "no_such_object"
    assert document.files["gpttmpl"].status == "unavailable"


# ---- the walk of the SYSVOL ------------------------------------------------


def _xml_with_a_cpassword(secret: str = "P@ssw0rd-that-must-never-be-seen") -> str:
    """A Groups.xml that holds one cpassword."""
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        "<GroupPolicyContainer>\n"
        "  <Machine><Group><GroupSettings>"
        f'<Setting name="cpassword" cpassword="{secret}"/>'
        "</GroupSettings></Group></Machine>\n"
        "</GroupPolicyContainer>\n"
    )


@contextlib.contextmanager
def _time_limit(seconds: float):
    """Fail the test when the body takes longer than that."""
    def _handler(_signum, _frame):
        raise AssertionError("the collector did not finish in time")

    old = signal.signal(signal.SIGALRM, _handler)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def test_a_symlinked_gpo_folder_is_skipped_and_counted(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A symlinked folder of a GPO is never walked into.

    The collector runs as root, so a link is a way out of the SYSVOL.
    """
    outside = sysvol.parent / "outside"
    outside.mkdir()
    (outside / "Groups.xml").write_text(_xml_with_a_cpassword(), encoding="utf-8")
    (sysvol / "{4A06E176-48DD-4B65-B2B0-214B24EB0F59}").symlink_to(outside)

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    raw = json.loads(out)["files"]["gpp"]
    assert raw["skipped_special"] == 1
    assert raw["items"] == []
    assert "P@ssw0rd-that-must-never-be-seen" not in out


def test_a_symlinked_file_that_points_outside_is_skipped(
    collector, install, sysvol, fake, capsys, monkeypatch, tmp_path: Path
) -> None:
    """A symlink to a file outside the SYSVOL is never read."""
    secret = "P@ssw0rd-that-must-never-be-seen"
    outside = tmp_path / "outside.xml"
    outside.write_text(_xml_with_a_cpassword(secret), encoding="utf-8")
    directory = _write_gpo(
        sysvol,
        "{4A06E176-48DD-4B65-B2B0-214B24EB0F59}",
        {},
    )
    preferences = directory / "Machine" / "Preferences" / "Groups"
    preferences.mkdir(parents=True, exist_ok=True)
    (preferences / "x.xml").symlink_to(outside)

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    raw = json.loads(out)["files"]["gpp"]
    assert raw["skipped_special"] == 1
    assert raw["items"] == []
    assert secret not in out


def test_a_fifo_named_like_an_xml_file_does_not_hang(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A named pipe is never opened in a way that waits for a writer."""
    directory = _write_gpo(
        sysvol,
        "{4A06E176-48DD-4B65-B2B0-214B24EB0F59}",
        {},
    )
    preferences = directory / "Machine" / "Preferences" / "Groups"
    preferences.mkdir(parents=True, exist_ok=True)
    os.mkfifo(preferences / "x.xml")

    with _time_limit(5.0):
        code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    raw = json.loads(out)["files"]["gpp"]
    assert raw["items"] == []
    assert raw["skipped_special"] == 1


def test_a_file_that_is_too_big_is_refused(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A file of more than four mebibytes is refused and never parsed."""
    directory = _write_gpo(
        sysvol,
        "{4A06E176-48DD-4B65-B2B0-214B24EB0F59}",
        {},
    )
    preferences = directory / "Machine" / "Preferences" / "Groups"
    preferences.mkdir(parents=True, exist_ok=True)
    (preferences / "Groups.xml").write_text(
        _xml_with_a_cpassword() + "<!--" + "x" * (5 * 1024 * 1024) + "-->",
        encoding="utf-8",
    )

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    raw = json.loads(out)["files"]["gpp"]
    assert raw["parse_refused"] == 1
    assert raw["items"] == []
    assert "P@ssw0rd-that-must-never-be-seen" not in out


def test_the_deadline_that_passes_during_the_walk_truncates_the_files(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """When the deadline passes in the middle of the walk, it is cut.

    The clock of the test is moved while the first file is read, so
    the deadline of the run passes before the second one.
    """
    _write_gpo(
        sysvol,
        "{4A06E176-48DD-4B65-B2B0-214B24EB0F59}",
        {
            "Machine/Preferences/Groups/Groups.xml": _xml_with_a_cpassword(),
        },
    )
    _write_gpo(
        sysvol,
        "{5A06E176-48DD-4B65-B2B0-214B24EB0F59}",
        {
            "Machine/Preferences/Services/Services.xml": _xml_with_a_cpassword(),
        },
    )

    class _Clock:
        """A clock that the test moves by hand."""

        def __init__(self) -> None:
            self.now = 1000.0

        def monotonic(self) -> float:
            return self.now

        def time(self) -> float:
            return self.now

        def strftime(self, fmt, when):
            return time.strftime(fmt, when)

        def gmtime(self, when):
            return time.gmtime(when)

    clock = _Clock()
    monkeypatch.setattr(collector, "time", clock)
    original = collector._read_child_file

    def advancing(parent_fd, name):
        clock.now += 400.0
        return original(parent_fd, name)

    monkeypatch.setattr(collector, "_read_child_file", advancing)

    _, out, _ = run(collector, capsys, monkeypatch)

    document = document_of(out)
    assert document.files["gpp"].status == "truncated"
    assert document.files["gpp"].error_code == "time_limit"
    assert document.files["gpttmpl"].status == "truncated"
    assert document.files["gpttmpl"].error_code == "time_limit"


# ---- the decoding of the files ---------------------------------------------


def test_a_groups_xml_in_utf16_is_read_and_its_cpassword_is_counted(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A file with a byte order mark of UTF-16 is read as UTF-16."""
    directory = _write_gpo(
        sysvol,
        "{4A06E176-48DD-4B65-B2B0-214B24EB0F59}",
        {},
    )
    preferences = directory / "Machine" / "Preferences" / "Groups"
    preferences.mkdir(parents=True, exist_ok=True)
    (preferences / "Groups.xml").write_bytes(_xml_with_a_cpassword().encode("utf-16"))

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    items = document_of(out).files["gpp"].items
    assert len(items) == 1
    assert items[0].kind == "cpassword"
    assert items[0].count == 1


def test_a_groups_xml_that_is_not_utf8_is_read_and_counted(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A file without a byte order mark is read as UTF-8, leniently.

    Measured on the lab DC: a Latin-1 file is read with the
    replacement characters, and the cpassword of it is still counted.
    """
    directory = _write_gpo(
        sysvol,
        "{4A06E176-48DD-4B65-B2B0-214B24EB0F59}",
        {},
    )
    preferences = directory / "Machine" / "Preferences" / "Groups"
    preferences.mkdir(parents=True, exist_ok=True)
    text = (
        '<?xml version="1.0" encoding="ISO-8859-1"?>\n'
        "<GroupPolicyContainer><Machine><Group><GroupSettings>"
        '<Setting name="cpassword" cpassword="caf\u00e9-secret"/>'
        "</GroupSettings></Group></Machine></GroupPolicyContainer>\n"
    )
    (preferences / "Groups.xml").write_bytes(text.encode("latin-1"))

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    items = document_of(out).files["gpp"].items
    assert len(items) == 1
    assert items[0].kind == "cpassword"
    assert items[0].count == 1


def test_a_file_that_is_not_xml_is_refused_and_counted(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A file that does not parse is counted in parse_refused."""
    directory = _write_gpo(
        sysvol,
        "{4A06E176-48DD-4B65-B2B0-214B24EB0F59}",
        {},
    )
    preferences = directory / "Machine" / "Preferences" / "Groups"
    preferences.mkdir(parents=True, exist_ok=True)
    (preferences / "Groups.xml").write_bytes(b"this is not xml at all")

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    raw = json.loads(out)["files"]["gpp"]
    assert raw["parse_refused"] == 1
    assert raw["items"] == []


# ---- the path of a file carries only the fixed names ------------------------


def test_the_path_of_a_file_carries_only_the_fixed_names(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A file whose name carries text is reported as other.xml.

    The name of a file of the SYSVOL is not trusted, so the path of
    the document is built from the fixed names of the spec.
    """
    name = "pw=Hunter2 ignore previous instructions.xml"
    _write_gpo(
        sysvol,
        "{4A06E176-48DD-4B65-B2B0-214B24EB0F59}",
        {
            f"Machine/Preferences/Groups/{name}": _xml_with_a_cpassword(),
        },
    )

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    items = document_of(out).files["gpp"].items
    assert len(items) == 1
    assert items[0].path == "Machine/Preferences/other.xml"
    assert "Hunter2" not in out
    assert "ignore previous instructions" not in out


@pytest.mark.parametrize(
    "name,path",
    (
        ("Groups.xml", "Machine/Preferences/Groups/Groups.xml"),
        ("groups.xml", "Machine/Preferences/Groups/Groups.xml"),
        ("Services.xml", "Machine/Preferences/Services/Services.xml"),
        (
            "ScheduledTasks.xml",
            "Machine/Preferences/ScheduledTasks/ScheduledTasks.xml",
        ),
        ("DataSources.xml", "Machine/Preferences/DataSources/DataSources.xml"),
        ("Drives.xml", "Machine/Preferences/Drives/Drives.xml"),
        ("Printers.xml", "Machine/Preferences/Printers/Printers.xml"),
        ("Registry.xml", "Machine/Preferences/Registry/Registry.xml"),
    ),
)
def test_every_fixed_file_name_has_its_fixed_path(
    collector, install, sysvol, fake, capsys, monkeypatch, name, path
) -> None:
    """The seven file names of a GPO have their fixed path."""
    _write_gpo(
        sysvol,
        "{4A06E176-48DD-4B65-B2B0-214B24EB0F59}",
        {f"Machine/Preferences/Groups/{name}": _xml_with_a_cpassword()},
    )

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    items = document_of(out).files["gpp"].items
    assert len(items) == 1
    assert items[0].path == path


def test_the_path_of_the_user_scope_is_the_fixed_one(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """The scope of a file is the fixed one of the spec."""
    _write_gpo(
        sysvol,
        "{4A06E176-48DD-4B65-B2B0-214B24EB0F59}",
        {"User/Preferences/Groups/Groups.xml": _xml_with_a_cpassword()},
    )

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    items = document_of(out).files["gpp"].items
    assert len(items) == 1
    assert items[0].path == "User/Preferences/Groups/Groups.xml"


# ---- the install ------------------------------------------------------------


def test_the_collector_starts_with_the_isolated_interpreter() -> None:
    """The shebang of the collector asks for an isolated interpreter."""
    first = COLLECTOR_PATH.read_text(encoding="utf-8").splitlines()[0]

    assert first == "#!/usr/bin/python3 -I"


def test_the_install_is_checked_with_the_two_directories_and_their_parents(
    collector, install
) -> None:
    """Every parent of the install, up to the root, is checked."""
    directories = collector._install_directories()

    assert str(install) in directories
    assert str(install.parent) in directories
    assert str(install.parent.parent) in directories


def test_a_parent_directory_that_may_be_written_is_refused(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A parent of the install that others may write is not safe."""
    install.parent.chmod(0o777)

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 2
    assert out == ""
    assert "the install is not safe" in err


def test_the_install_check_runs_before_the_bindings_are_imported(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """The samba bindings are not imported when the install is unsafe."""
    for name in MODULE_NAMES:
        monkeypatch.delitem(sys.modules, name, raising=False)
    (install / "queries.json").chmod(0o664)

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 2
    assert "samba" not in sys.modules
    assert "ldb" not in sys.modules


def test_a_file_of_the_install_that_is_a_link_is_refused(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A file of the install that is a link is not a safe install."""
    target = install / "queries.json"
    target.unlink()
    target.symlink_to(install / "forbidden.json")

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 2
    assert out == ""
    assert "the install is not safe" in err


def test_the_json_files_are_read_without_following_a_link(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """The files of the query set are opened without following a link.

    The file is opened with O_NOFOLLOW and the check of the install
    runs on the descriptor of the open file.
    """
    text = COLLECTOR_PATH.read_text(encoding="utf-8")

    assert "O_NOFOLLOW" in text
    assert "os.fstat" in text


def test_a_symlinked_folder_inside_a_gpo_is_skipped_and_counted(
    collector, install, sysvol, fake, capsys, monkeypatch, tmp_path: Path
) -> None:
    """A symlinked folder of a GPO is never walked into.

    The link is a way out of the SYSVOL, so it is skipped at every
    level of the walk.
    """
    secret = "P@ssw0rd-that-must-never-be-seen"
    outside = tmp_path / "outside"
    (outside / "Preferences" / "Groups").mkdir(parents=True)
    (outside / "Preferences" / "Groups" / "Groups.xml").write_text(
        _xml_with_a_cpassword(secret), encoding="utf-8"
    )
    directory = _write_gpo(
        sysvol,
        "{4A06E176-48DD-4B65-B2B0-214B24EB0F59}",
        {},
    )
    (directory / "Machine").symlink_to(outside)

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    raw = json.loads(out)["files"]["gpp"]
    assert raw["items"] == []
    assert raw["skipped_special"] == 1
    assert secret not in out


def test_a_symlinked_preferences_folder_is_skipped_and_counted(
    collector, install, sysvol, fake, capsys, monkeypatch, tmp_path: Path
) -> None:
    """A symlinked Preferences folder of a scope is never walked into."""
    secret = "P@ssw0rd-that-must-never-be-seen"
    outside = tmp_path / "outside"
    (outside / "Groups").mkdir(parents=True)
    (outside / "Groups" / "Groups.xml").write_text(
        _xml_with_a_cpassword(secret), encoding="utf-8"
    )
    directory = _write_gpo(
        sysvol,
        "{4A06E176-48DD-4B65-B2B0-214B24EB0F59}",
        {},
    )
    (directory / "Machine").mkdir(parents=True, exist_ok=True)
    (directory / "Machine" / "Preferences").symlink_to(outside)

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    raw = json.loads(out)["files"]["gpp"]
    assert raw["items"] == []
    assert raw["skipped_special"] == 1
    assert secret not in out


# ---- the walk of the SYSVOL by descriptor -----------------------------------


def _open_directory(path: Path) -> int:
    """The descriptor of a directory, for a test that calls the collector."""
    return os.open(str(path), os.O_RDONLY | os.O_DIRECTORY)


def test_the_file_opener_never_reads_a_named_pipe(collector, tmp_path: Path) -> None:
    """A named pipe is never opened in a way that waits for a writer.

    The opener opens the file with ``O_NONBLOCK`` and then checks that
    it is a regular file: a named pipe is never read and never makes
    the collector wait.
    """
    os.mkfifo(tmp_path / "pipe")
    handle = _open_directory(tmp_path)
    try:
        with _time_limit(5.0):
            state, raw = collector._read_child_file(handle, "pipe")
    finally:
        os.close(handle)

    assert state == collector.FILE_SPECIAL
    assert raw is None


def test_the_file_opener_never_follows_a_link(collector, tmp_path: Path) -> None:
    """A symlink is never read: the file it points at is not the file.

    The opener opens the file with ``O_NOFOLLOW``: a link is refused
    and the file it points at is never read.
    """
    outside = tmp_path / "outside.xml"
    outside.write_text("the secret of a file outside", encoding="utf-8")
    (tmp_path / "link.xml").symlink_to(outside)
    handle = _open_directory(tmp_path)
    try:
        state, raw = collector._read_child_file(handle, "link.xml")
    finally:
        os.close(handle)

    assert state == collector.FILE_SPECIAL
    assert raw is None


def test_the_file_opener_never_reads_a_directory(collector, tmp_path: Path) -> None:
    """A directory is not a file of the SYSVOL.

    The opener checks that the file it opened is a regular file: a
    directory is refused and never read.
    """
    (tmp_path / "folder").mkdir()
    handle = _open_directory(tmp_path)
    try:
        state, raw = collector._read_child_file(handle, "folder")
    finally:
        os.close(handle)

    assert state == collector.FILE_SPECIAL
    assert raw is None


def test_a_link_swapped_in_after_the_listing_is_never_followed(
    collector, install, sysvol, fake, capsys, monkeypatch, tmp_path: Path
) -> None:
    """A folder that is swapped for a link after the listing is not walked.

    The collector lists a directory and opens every folder of it by
    descriptor.  A folder that is swapped for a link between the two
    is refused by the open, so the link is never followed and the file
    it points at is never read.
    """
    secret = "P@ssw0rd-that-must-never-be-seen"
    outside = tmp_path / "outside"
    (outside / "Preferences" / "Groups").mkdir(parents=True)
    (outside / "Preferences" / "Groups" / "Groups.xml").write_text(
        _xml_with_a_cpassword(secret), encoding="utf-8"
    )
    guid = "{4A06E176-48DD-4B65-B2B0-214B24EB0F59}"
    folder = sysvol / guid
    folder.mkdir()
    real_scandir = collector._scandir
    swapped = []

    def scandir(dir_fd):
        entries = real_scandir(dir_fd)
        if not swapped and any(name == guid for name, _kind in entries):
            # The folder is swapped for a link between the listing of
            # the parent and the open of the folder.
            swapped.append(True)
            folder.rmdir()
            folder.symlink_to(outside)
        return entries

    monkeypatch.setattr(collector, "_scandir", scandir)

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    raw = json.loads(out)["files"]["gpp"]
    assert raw["items"] == []
    assert raw["skipped_special"] == 1
    assert secret not in out


def test_every_case_variant_of_the_folder_of_a_scope_is_walked(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """Machine and MACHINE are two folders, and both are walked.

    Samba provisions the folders of a GPO in upper case and Windows in
    mixed case, and a host may hold both: every one of them is walked
    and every credential of them is counted.
    """
    secret = "P@ssw0rd-that-must-never-be-seen"
    guid = "{4A06E176-48DD-4B65-B2B0-214B24EB0F59}"
    _write_gpo(
        sysvol,
        guid,
        {"Machine/Preferences/Groups/Groups.xml": _xml_with_a_cpassword(secret)},
    )
    _write_gpo(
        sysvol,
        guid,
        {"MACHINE/Preferences/Groups/Groups.xml": _xml_with_a_cpassword(secret)},
    )

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    items = document_of(out).files["gpp"].items
    assert len(items) == 2
    assert all(item.kind == "cpassword" for item in items)
    assert all(item.count == 1 for item in items)
    assert all(item.path == "Machine/Preferences/Groups/Groups.xml" for item in items)
    assert secret not in out


def test_a_deadline_that_passes_after_the_first_directory_truncates_the_files(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """The deadline is checked before every directory of the walk.

    The clock of the test is moved while the first directory is listed,
    so the deadline of the run passes before the second one is read.
    """
    _write_gpo(
        sysvol,
        "{4A06E176-48DD-4B65-B2B0-214B24EB0F59}",
        {"Machine/Preferences/Groups/Groups.xml": _xml_with_a_cpassword()},
    )
    _write_gpo(
        sysvol,
        "{5A06E176-48DD-4B65-B2B0-214B24EB0F59}",
        {"Machine/Preferences/Services/Services.xml": _xml_with_a_cpassword()},
    )

    class _Clock:
        """A clock that the test moves by hand."""

        def __init__(self) -> None:
            self.now = 1000.0

        def monotonic(self) -> float:
            return self.now

        def time(self) -> float:
            return self.now

        def strftime(self, fmt, when):
            return time.strftime(fmt, when)

        def gmtime(self, when):
            return time.gmtime(when)

    clock = _Clock()
    monkeypatch.setattr(collector, "time", clock)
    real_scandir = collector._scandir
    listed = []

    def scandir(dir_fd):
        entries = real_scandir(dir_fd)
        listed.append(dir_fd)
        if len(listed) == 1:
            # The deadline passes while the first directory is listed.
            clock.now += 400.0
        return entries

    monkeypatch.setattr(collector, "_scandir", scandir)

    _, out, _ = run(collector, capsys, monkeypatch)

    document = document_of(out)
    assert document.files["gpp"].status == "truncated"
    assert document.files["gpp"].error_code == "time_limit"
    assert document.files["gpttmpl"].status == "truncated"
    assert document.files["gpttmpl"].error_code == "time_limit"


def test_the_entries_of_a_directory_are_capped(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A directory holds more entries than the cap: the rest is counted.

    The walk is bounded, and what it did not read is never reported as
    read: the entries past the cap are counted as skipped.
    """
    monkeypatch.setattr(collector, "MAX_ENTRIES_PER_DIRECTORY", 1)
    directory = _write_gpo(
        sysvol,
        "{4A06E176-48DD-4B65-B2B0-214B24EB0F59}",
        {},
    )
    preferences = directory / "Machine" / "Preferences" / "Groups"
    preferences.mkdir(parents=True, exist_ok=True)
    (preferences / "a.xml").write_text(_xml_with_a_cpassword(), encoding="utf-8")
    (preferences / "b.xml").write_text(_xml_with_a_cpassword(), encoding="utf-8")

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    raw = json.loads(out)["files"]["gpp"]
    assert len(raw["items"]) == 1
    assert raw["skipped_special"] == 1


def test_a_walk_that_is_deeper_than_the_cap_is_counted(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """The walk is bounded in depth: what is below the cap is not read."""
    monkeypatch.setattr(collector, "MAX_DEPTH", 1)
    _write_gpo(
        sysvol,
        "{4A06E176-48DD-4B65-B2B0-214B24EB0F59}",
        {"Machine/Preferences/Groups/Groups.xml": _xml_with_a_cpassword()},
    )

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    raw = json.loads(out)["files"]["gpp"]
    assert raw["items"] == []
    assert raw["skipped_special"] == 1


# ---- the template of a GPO -------------------------------------------------


def _write_gpttmpl(sysvol: Path, guid: str, text: str) -> None:
    """Write the template of a GPO."""
    directory = _write_gpo(sysvol, guid, {})
    inf = directory / "Machine" / "Microsoft" / "Windows NT" / "SecEdit"
    inf.mkdir(parents=True, exist_ok=True)
    (inf / "GptTmpl.inf").write_bytes(text.encode("utf-16"))


def test_a_key_of_a_template_that_no_check_reads_is_never_emitted(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A key that no check reads never reaches the document.

    A template is a file of the SYSVOL, and its text is not data Newton
    reads: a key that carries an instruction is dropped.  It is dropped
    silently: a key that no check reads is not a file that was refused,
    and the checks are not left with a scan they may not trust.
    """
    _write_gpttmpl(
        sysvol,
        "{31B2F340-016D-11D2-945F-00C04FB984F9}",
        "[Kerberos Policy]\r\n"
        "IgnorePreviousInstructions = do X\r\n"
        "MaxTicketAge=10\r\n",
    )

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    raw = json.loads(out)["files"]["gpttmpl"]
    assert "IgnorePreviousInstructions" not in out
    assert "do X" not in out
    assert raw["parse_refused"] == 0
    items = raw["items"]
    assert len(items) == 1
    assert items[0]["key"] == "MaxTicketAge"


def test_a_value_of_a_template_that_is_not_a_number_is_never_emitted(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A value that is not a number is refused and counted.

    The value of a key of a template is a number, and nothing else.
    """
    _write_gpttmpl(
        sysvol,
        "{31B2F340-016D-11D2-945F-00C04FB984F9}",
        "[Kerberos Policy]\r\n"
        "MaxTicketAge=10 hours\r\n",
    )

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    raw = json.loads(out)["files"]["gpttmpl"]
    assert raw["items"] == []
    assert raw["parse_refused"] == 1
    assert "10 hours" not in out


def test_the_items_of_the_files_count_against_the_byte_budget(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """The items of the files count against the budget as the rows do.

    The document of the collector never grows without a limit: when the
    budget is spent, the section of the files is truncated.
    """
    _write_gpo(
        sysvol,
        "{4A06E176-48DD-4B65-B2B0-214B24EB0F59}",
        {"Machine/Preferences/Groups/Groups.xml": _xml_with_a_cpassword()},
    )
    _, out, _ = run(collector, capsys, monkeypatch)
    rows = json.loads(out)["queries"]
    budget = sum(
        len(json.dumps(row, separators=(",", ":")).encode("utf-8"))
        for block in rows.values()
        for row in block["rows"]
    )
    monkeypatch.setattr(collector, "BYTE_LIMIT", budget + 8)

    _, out, _ = run(collector, capsys, monkeypatch)

    document = document_of(out)
    assert document.files["gpp"].status == "truncated"
    assert document.files["gpp"].error_code == "byte_limit"


# ---- the template of a GPO in a folder of any case -------------------------


def check_of(check_id: str) -> catalogue.Check:
    """The check of the catalogue with that id."""
    for check in catalogue.CHECKS:
        if check.id == check_id:
            return check
    raise KeyError(f"the catalogue holds no {check_id}")


def _write_gpttmpl_in(policies: Path, guid: str, scope: str, text: str) -> None:
    """Write the template of a GPO under a folder of a case of its name."""
    directory = policies / guid / scope / "Microsoft" / "Windows NT" / "SecEdit"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "GptTmpl.inf").write_bytes(text.encode("utf-16"))


def test_the_stock_template_of_a_samba_dc_gives_only_the_keys_that_are_read(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """The template of a stock Samba DC is not a refusal.

    The template of the Default Domain Policy holds ten keys of the
    [System Access] section and one of the [Kerberos Policy] section
    that no check of Newton reads.  A key that is not read is dropped
    silently: it is not a file that was refused, and the checks are not
    left with a scan they may not trust.
    """
    _write_gpttmpl(sysvol, fake_samba.GPO_GUID, measured.STOCK_GPTTMPL)

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    raw = json.loads(out)["files"]["gpttmpl"]
    assert raw["parse_refused"] == 0
    assert raw["skipped_special"] == 0
    assert [(item["key"], item["value"]) for item in raw["items"]] == [
        ("MaxTicketAge", "10"),
        ("MaxRenewAge", "7"),
        ("MaxServiceAge", "600"),
        ("MaxClockSkew", "5"),
    ]
    for key in ("MinimumPasswordLength", "LSAAnonymousNameLookup"):
        assert key not in out


def test_the_stock_template_of_a_samba_dc_lets_ad_a_34_pass(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """AD-A-34 passes on a stock Samba domain controller.

    The check is evaluated on its own and not through the runner: the
    identity guard of the runner needs a krbtgt, and the fake of these
    tests does not hold one.
    """
    _write_gpttmpl(sysvol, fake_samba.GPO_GUID, measured.STOCK_GPTTMPL)

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    document = document_of(out)
    result = check_of("AD-A-34").evaluate(document)

    assert result.status == model.Status.PASS
    assert "MaxTicketAge 10" in result.note
    assert "MaxClockSkew 5" in result.note


def test_a_key_of_a_template_that_is_not_a_number_is_counted(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A key that is read and whose value is not a number is refused.

    The value of a key of a template is a number and nothing else: the
    key is counted as refused and its value never reaches the document,
    and AD-A-34 cannot prove anything about a policy it did not read.
    """
    _write_gpttmpl(
        sysvol,
        fake_samba.GPO_GUID,
        "[Kerberos Policy]\nMaxTicketAge = 10 hours\n",
    )

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    raw = json.loads(out)["files"]["gpttmpl"]
    assert raw["items"] == []
    assert raw["parse_refused"] == 1
    assert "10 hours" not in out
    document = document_of(out)
    result = check_of("AD-A-34").evaluate(document)

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.PARSE_REFUSED


def test_every_case_variant_of_the_template_of_a_gpo_is_read(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """Machine and MACHINE are two folders, and both are read.

    Samba provisions the folders of a GPO in upper case and Windows in
    mixed case, and a host may hold both of them.  The template of the
    two of them is read: a key they hold with the same value is emitted
    once, and a key that only one of them holds is emitted as well.
    """
    guid = fake_samba.GPO_GUID
    _write_gpttmpl_in(
        sysvol,
        guid,
        "MACHINE",
        "[Kerberos Policy]\nMaxTicketAge = 10\n",
    )
    _write_gpttmpl_in(
        sysvol,
        guid,
        "Machine",
        "[Kerberos Policy]\nMaxTicketAge = 10\nMaxRenewAge = 7\n",
    )

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    raw = json.loads(out)["files"]["gpttmpl"]
    assert raw["parse_refused"] == 0
    assert [(item["key"], item["value"]) for item in raw["items"]] == [
        ("MaxTicketAge", "10"),
        ("MaxRenewAge", "7"),
    ]


def test_two_variants_of_a_template_that_disagree_are_refused(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """Two variants of a template that disagree are a refusal.

    The value of the GPO is not known when the two of its folders do not
    agree on it: neither value is emitted and the disagreement is
    counted once.
    """
    guid = fake_samba.GPO_GUID
    _write_gpttmpl_in(
        sysvol,
        guid,
        "MACHINE",
        "[Kerberos Policy]\nMaxTicketAge = 10\n",
    )
    _write_gpttmpl_in(
        sysvol,
        guid,
        "Machine",
        "[Kerberos Policy]\nMaxTicketAge = 11\n",
    )

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    raw = json.loads(out)["files"]["gpttmpl"]
    assert raw["items"] == []
    assert raw["parse_refused"] == 1


# ---- the protections of the walk --------------------------------------------


def test_a_symlinked_base_of_the_sysvol_is_refused(
    collector, install, sysvol, fake, capsys, monkeypatch, tmp_path: Path
) -> None:
    """The base of the walk is opened without following a link.

    The collector runs as root, so a link at the base of the SYSVOL is
    a way out of it: the base is refused and the files are reported as
    unavailable.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "{4A06E176-48DD-4B65-B2B0-214B24EB0F59}").mkdir()
    sysvol.rmdir()
    sysvol.symlink_to(outside)

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    document = document_of(out)
    assert document.files["gpp"].status == "unavailable"
    assert document.files["gpp"].error_code == "no_such_object"
    assert document.files["gpttmpl"].status == "unavailable"
    assert document.files["gpttmpl"].error_code == "no_such_object"


def test_the_items_of_a_template_count_against_the_byte_budget(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """The items of the templates count against the budget as the rows do.

    The document of the collector never grows without a limit: when the
    budget is spent, the section of the templates is truncated.
    """
    _write_gpttmpl(sysvol, fake_samba.GPO_GUID, measured.STOCK_GPTTMPL)
    _, out, _ = run(collector, capsys, monkeypatch)
    rows = json.loads(out)["queries"]
    budget = sum(
        len(json.dumps(row, separators=(",", ":")).encode("utf-8"))
        for block in rows.values()
        for row in block["rows"]
    )
    monkeypatch.setattr(collector, "BYTE_LIMIT", budget + 8)

    _, out, _ = run(collector, capsys, monkeypatch)

    document = document_of(out)
    assert document.files["gpttmpl"].status == "truncated"
    assert document.files["gpttmpl"].error_code == "byte_limit"
    assert document.files["gpttmpl"].items == ()


# ---- the loadparm ----------------------------------------------------------


def test_the_fake_raises_for_an_option_the_loadparm_does_not_hold(fake) -> None:
    """The loadparm raises a KeyError for an option it does not hold.

    The real binding does, and the collector has to live with it.
    """
    lp = fake_samba.FakeLoadParm()

    with pytest.raises(KeyError):
        lp.get("no such option")


def test_a_setting_that_the_loadparm_does_not_hold_is_unavailable(
    collector, install, sysvol, fake, capsys, monkeypatch
) -> None:
    """A parameter the loadparm does not hold is reported as unavailable.

    The collector catches the KeyError of the binding and reports the
    setting as unavailable, so the run still produces a document.
    """
    del fake.PARM["server signing"]

    code, out, err = run(collector, capsys, monkeypatch)

    assert code == 0, err
    section = document_of(out).settings
    assert section.status == "ok"
    values = {item.key: item for item in section.items}
    assert values["server signing"].status == "unavailable"
    assert values["server signing"].value == ""
    assert values["ntlm auth"].status == "ok"
