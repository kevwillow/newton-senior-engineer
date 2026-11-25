"""The baseline and stages 5 and 6 of the build helper (PLAN-1.5 task 6).

THE BASELINE.  ``baseline-2026.11.toml`` holds one table per setting:
its value or its options, why, its source (a ``learn.microsoft.com``
page, or a CIS Benchmark item by its number only, never its text) and
its compatibility risk.  ``load_baseline`` checks it, and the helper
holds the same values compiled in: a test keeps the two equal.

STAGE 5 is reversible and runs under the plan token: one op,
``s5-structure``, in the password task, writes the OU tree, the groups,
the owner's admin account, Protected Users, the password policy, the
fine-grained policy for admins and the built-in Administrator per its
option, then reads every object and value back in the same output.
STAGE 6 is irreversible (a checkpoint and a stage token): one op per
baseline GPO (``s6-gpo-domain``, ``s6-gpo-dc``), then ``s6-read``, the
refresh, the registry, the secedit export and the GPO versions.

THE FIXTURES ARE MEASURED (MEASURED-1.5 "Stages 5 and 6 on BUILD1,
2026-11-14"): ``fixtures/stages_5_6/<op>.txt`` is the output file of the
op as this helper renders it, run on BUILD1 in the password task as
newton-build, the BOM and the CR dropped, the domain SID and the GPO
GUIDs as measured but the SID masked.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest

from newton_mcp.ad.build import baseline as baseline_mod
from newton_mcp.ad.build import plan
from newton_mcp.approve import approval_token
from test_build_bootstrap import (
    HOSTILE_VALUES,
    _command_names,
    _run_pwsh,
    _every_occurrence_is_in_a_literal,
    _parse_errors,
    _single_quoted_spans,
)
from test_build_stages_0_4 import (  # noqa: F401  (server is a fixture)
    BOOT_0,
    BOOT_1,
    EXP,
    HELPER,
    KEY_HEX,
    NBF,
    PLAN_INPUTS,
    RUN,
    Server,
    _call,
    _fixture,
    _kinds,
    _ok,
    _ops_called,
    _plan,
    _render,
    _restarts,
    _s4_output,
    _seed_before,
    _stage_values,
    _states,
    _stopped,
    _values,
    server,
)

BASELINE_FILE = (
    Path(__file__).resolve().parents[3] / "newton_mcp" / "ad" / "build" / "baseline-2026.11.toml"
)
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "stages_5_6"
GOLDEN = FIXTURES / "golden"

#: The ops of stages 5 and 6, and the read of a resumed stage 4.
NEW_OPS = ["s3-state", "s4-state", "s5-structure", "s6-gpo-domain", "s6-gpo-dc", "s6-read"]

#: The domain SID of the fixtures, masked.
DOMAIN_SID = "S-1-5-21-1000000001-1000000002-1000000003"

CP6 = "pve:731:nb-stage6-20261114"


def _measured(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="ascii")


def _plan5(inputs: dict[str, Any] | None = None) -> dict[str, Any]:
    """The plan of the measured run: the OU tree and the groups of it."""
    the_inputs = copy.deepcopy(PLAN_INPUTS if inputs is None else inputs)
    the_inputs["domain"]["ou_tree"] = ["IT/Servers", "Staff"]
    the_inputs["domain"]["groups"] = ["IT Admins", "Staff Users"]
    return plan.plan_build(the_inputs)


def _with_option(option: str) -> dict[str, Any]:
    inputs = copy.deepcopy(PLAN_INPUTS)
    inputs["baseline"]["options"] = {"administrator": option}
    return _plan5(inputs)


def _seed_through(server: Server, the_plan: dict[str, Any], last: str, checkpoint: str = "") -> None:
    """Stages 0 to ``last`` done; the next stage checkpointed when given."""
    digest = plan.digest(the_plan)
    records: list[dict[str, Any]] = []
    for stage in [str(n) for n in range(int(last) + 1)]:
        records.append({"stage": stage, "state": "started", "digest": digest})
        records.append({"stage": stage, "state": "done", "digest": digest})
    if checkpoint:
        records.append({"stage": str(int(last) + 1), "state": "checkpointed", "digest": digest,
                        "checkpoint": checkpoint})
    server.seed(records)


# ---------------------------------------------------------------------------
# the baseline file
# ---------------------------------------------------------------------------


def test_every_entry_has_a_learn_source_or_a_cis_number() -> None:
    loaded = baseline_mod.load_baseline("2026.11")
    assert loaded.settings
    for setting in loaded.settings:
        learn = re.fullmatch(r"https://learn\.microsoft\.com/en-us/\S+", setting.source) is not None
        cis = re.fullmatch(r"[0-9]+(\.[0-9]+)+", setting.cis) is not None
        assert learn or cis, setting.id
        # A source is a learn.microsoft.com URL or nothing; never another site.
        assert setting.source == "" or learn, setting.id


def test_the_file_copies_no_cis_text() -> None:
    """CIS items are cited by number only: no title, no profile tag, no
    'Ensure ... is set to' sentence, no long pasted paragraph."""
    text = BASELINE_FILE.read_text(encoding="utf-8")
    for pattern in ["Ensure '", "(L1)", "(L2)", "is set to '", "(DC only)", "(MS only)", "Rationale", "Audit:", "Remediation"]:
        assert pattern not in text, pattern
    for setting in baseline_mod.load_baseline("2026.11").settings:
        assert len(setting.why) <= 200 and len(setting.risk) <= 200, setting.id
    for line in text.splitlines():
        if line.startswith(("why", "risk")):
            assert len(line) < 230, line


def _swap(old: str, new: str) -> str:
    text = BASELINE_FILE.read_text(encoding="utf-8")
    assert old in text
    return text.replace(old, new, 1)


@pytest.mark.parametrize(
    ("old", "new", "code"),
    [
        pytest.param('cis = "1.1.4"\n', 'cis = "Minimum password length"\n', "no_source", id="cis-text"),
        pytest.param(
            'source = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/minimum-password-length"',
            'source = "https://example.com/minimum-password-length"',
            "no_source",
            id="not-learn",
        ),
        pytest.param(
            'source = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/account-lockout-threshold"\n',
            "",
            "no_source",
            id="no-source",
        ),
        pytest.param(
            'why = "Stops a user cycling back to an old password."',
            "why = \"Ensure 'Enforce password history' is set to '24 or more password(s)'\"",
            "copied_text",
            id="cis-title",
        ),
        pytest.param('risk = "None known."\n', 'risk = "None known."\nnote = "x"\n', "bad_entry", id="unknown-field"),
        pytest.param('options = ["random-password", "disabled"]', 'options = ["random-password"]', "bad_entry", id="one-option"),
        pytest.param('value = "537395200"', 'value = "4294967295"', "bad_entry", id="not-a-dword"),
        pytest.param('target = "gpo:dc"', 'target = "gpo:member"', "bad_entry", id="unknown-gpo"),
    ],
)
def test_a_bad_entry_is_refused(old: str, new: str, code: str) -> None:
    with pytest.raises(baseline_mod.BaselineRefused) as caught:
        baseline_mod.parse_baseline(_swap(old, new), "2026.11")
    assert caught.value.code == code


def test_an_unknown_version_is_refused() -> None:
    with pytest.raises(baseline_mod.BaselineRefused) as caught:
        baseline_mod.load_baseline("2026.12")
    assert caught.value.code == "unknown_version"


def test_the_options_of_the_plan_are_the_options_of_the_baseline() -> None:
    assert plan.BASELINE_OPTIONS == baseline_mod.load_baseline("2026.11").options()
    assert plan.BASELINE_OPTIONS == {"administrator": ("random-password", "disabled")}


@pytest.mark.parametrize(
    "options",
    [
        {"administrator": "renamed"},
        {"administrator": "random-password", "ntlm-restrict": "deny-all"},
        {"lm-compatibility": "3", "administrator": "disabled"},
    ],
)
def test_an_unknown_option_is_refused(options: dict[str, str]) -> None:
    inputs = copy.deepcopy(PLAN_INPUTS)
    inputs["baseline"]["options"] = options
    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)
    assert caught.value.code == "unknown_baseline_option"


def test_the_helper_holds_the_baseline_of_the_file(server: Server) -> None:
    """The values stage 5 and 6 render with: the plan's own, then the
    baseline's, exactly as the file says."""
    the_plan = _plan5()
    values = _stage_values(server, the_plan)
    expected = baseline_mod.load_baseline("2026.11").helper_values()
    for key, value in expected.items():
        assert values[key] == value, key
    assert values["OuTree"] == ["IT/Servers", "Staff"]
    assert values["Groups"] == ["IT Admins", "Staff Users"]
    assert values["OwnerAdmin"] == "owner-admin"
    assert values["AdministratorOption"] == "random-password"
    assert values["AdminSecretFile"] == "C:\\NewtonBuild\\admin.bin"
    assert "BuiltinSecretFile" not in values


def test_the_helper_refuses_a_baseline_version_it_does_not_hold(server: Server) -> None:
    text = plan.canonical_bytes(_plan5()).decode("ascii").replace("baseline.version=2026.11", "baseline.version=2026.12")
    raw = base64.b64encode(text.encode("ascii")).decode("ascii")
    out = server.drive({"mode": "values", "plan": raw, "role": "dc1"})
    assert out.get("error") == "schema", out


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("domain.ou_tree", "IT/Servers,Staff'; Remove-Item C:\\ #"),
        ("domain.ou_tree", "IT//Servers"),
        ("domain.groups", "IT Admins,$(whoami)"),
        ("domain.owner_admin", "owner`admin"),
        ("domain.owner_admin", "admin"),
        ("baseline.options", "administrator=renamed"),
    ],
)
def test_the_helper_refuses_a_stage_5_value_outside_its_grammar(server: Server, key: str, value: str) -> None:
    text = plan.canonical_bytes(_plan5()).decode("ascii")
    changed = re.sub(rf"(?m)^{re.escape(key)}=.*$", lambda _: f"{key}={value}", text)
    assert changed != text
    raw = base64.b64encode(changed.encode("ascii")).decode("ascii")
    out = server.drive({"mode": "values", "plan": raw, "role": "dc1"})
    assert out.get("error") == "schema", out


# ---------------------------------------------------------------------------
# the renders
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("op", NEW_OPS)
def test_the_golden_render_of_each_new_op(server: Server, op: str) -> None:
    scripts = _render(server, _stage_values(server, _plan5()), [op])
    golden = (GOLDEN / f"{op}.ps1").read_text(encoding="utf-8")
    assert scripts[op] == golden


def test_each_gpo_renders_with_its_own_name_link_and_settings(server: Server) -> None:
    loaded = baseline_mod.load_baseline("2026.11")
    scripts = _render(server, _stage_values(server, _plan5()), ["s6-gpo-domain", "s6-gpo-dc"])
    for op, gpo in [("s6-gpo-domain", "domain"), ("s6-gpo-dc", "dc")]:
        name = next(g.name for g in loaded.gpos if g.id == gpo)
        assert f"$GpoName = '{name}'" in scripts[op]
        assert f"$GpoLink = '{gpo}'" in scripts[op]
        listed = ", ".join(f"'{s}'" for s in loaded.gpo_settings(gpo))
        assert f"$Settings = @({listed})" in scripts[op]


def test_every_new_op_parses_and_never_restarts(server: Server) -> None:
    scripts = _render(server, _stage_values(server, _plan5()), NEW_OPS)
    for op, script in scripts.items():
        assert _parse_errors(script) == [], op
        assert f"$OutFile = 'C:\\NewtonBuild\\out\\{op}.txt'" in script, op
        names = {name.lower() for name in _command_names(script)}
        assert "restart-computer" not in names and "shutdown.exe" not in names, op


@pytest.mark.parametrize("hostile", HOSTILE_VALUES)
def test_hostile_ou_group_and_account_names_reach_powershell_only_as_data(server: Server, hostile: str) -> None:
    golden = _render(server, _stage_values(server, _plan5()), NEW_OPS)
    values = _stage_values(server, _plan5())
    values["OuTree"] = [hostile, "IT/" + hostile]
    values["Groups"] = [hostile, "Staff Users"]
    values["OwnerAdmin"] = hostile
    values["PsoName"] = hostile
    values["DomainGpoName"] = hostile
    values["DcGpoName"] = hostile
    values["GpoNames"] = [hostile, hostile]
    scripts = _render(server, values, NEW_OPS)
    escaped = "'" + re.sub("['\u2018\u2019\u201a\u201b]", lambda m: m.group(0) * 2, hostile) + "'"
    for op, script in scripts.items():
        assert _parse_errors(script) == [], op
        assert _command_names(script) == _command_names(golden[op]), op
        assert _every_occurrence_is_in_a_literal(script, hostile, _single_quoted_spans(script)), op
    assert f"$OwnerAdmin = {escaped}" in scripts["s5-structure"]
    assert f"$Groups = @({escaped}, 'Staff Users')" in scripts["s5-structure"]
    assert f"$GpoName = {escaped}" in scripts["s6-gpo-dc"]


def test_the_body_builds_no_filter_or_command_out_of_a_name(server: Server) -> None:
    """A name is an -Identity, a -Name or an escaped DN part: never inside
    a -Filter or an LDAP filter, never run."""
    scripts = _render(server, _stage_values(server, _plan5()), ["s5-structure", "s6-gpo-domain"])
    for op, script in scripts.items():
        body = script.split("& {", 1)[1]
        for name in ["$OwnerAdmin", "$group", "$name", "$PsoName", "$GpoName"]:
            assert not re.search(r"-(LDAP)?Filter[^\n]*" + re.escape(name), body), (op, name)
            assert not re.search(r"Invoke-Expression|iex |\[scriptblock\]::Create", body), op


# ---------------------------------------------------------------------------
# stage 5
# ---------------------------------------------------------------------------


def _run5(server: Server, the_plan: dict[str, Any], output: str, result: int = 0) -> dict[str, Any]:
    _seed_through(server, the_plan, "4")
    return _call(server, the_plan, "5", ops={"s5-structure": {"result": result, "output": output}})


def test_stage_5_runs_in_the_password_task_and_is_done_on_the_measured_read_back(server: Server) -> None:
    the_plan = _plan5()
    result = _run5(server, the_plan, _measured("s5-structure.txt"))
    assert result["answer"]["status"] == "done", result
    ops = [c for c in result["calls"] if c["kind"] == "op"]
    assert [(c["op"], c["task"]) for c in ops] == [("s5-structure", True)]
    assert _restarts(result) == 0
    assert _states(server, "5") == ["started", "done"]
    names = [c["name"] for c in result["answer"]["checks"]]
    for name in ["secret_files", "ous", "groups", "owner_admin", "owner_admin_groups",
                 "password_policy", "admin_pso", "builtin_administrator"]:
        assert name in names, name


def test_stage_5_runs_under_the_plan_token_with_no_checkpoint(server: Server) -> None:
    the_plan = _plan5()
    result = _run5(server, the_plan, _measured("s5-structure.txt"))
    assert result["answer"]["status"] == "done"
    assert [e["checkpoint"] for e in server.journal() if e["stage"] == "5"] == ["", ""]


# ---------------------------------------------------------------------------
# The audit findings of stage 10 that the build fixes (the maintainer's
# ruling of 2026-11-24): AD-A-44 (the machine account quota of the
# domain), AD-A-46 (Windows LAPS on the domain controllers) and AD-A-09
# for the owner admin (an account that may be delegated).
# ---------------------------------------------------------------------------

#: The key of the Windows LAPS policy of a computer.
LAPS_KEY = r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS"


def test_stage_5_sets_the_machine_account_quota_of_the_domain_to_zero(server: Server) -> None:
    """AD-A-44: the domain head's ms-DS-MachineAccountQuota is 0 after
    stage 5, and the check names the quota before the write and the one
    after it."""
    result = _run5(server, _plan5(), _measured("s5-structure.txt"))
    assert result["answer"]["status"] == "done", result
    checks = {c["name"]: c for c in result["answer"]["checks"]}
    assert "machine_account_quota" in checks, checks
    assert checks["machine_account_quota"]["ok"] is True, checks
    assert "before 10" in checks["machine_account_quota"]["detail"], checks
    assert "after 0" in checks["machine_account_quota"]["detail"], checks
    script = next(c["script"] for c in result["calls"] if c["kind"] == "op")
    assert "Set-ADObject" in script
    assert "ms-DS-MachineAccountQuota" in script


@pytest.mark.parametrize(
    ("old", "new"),
    [
        # The write did not take: the quota is still 10.
        ("machine account quota after: 0", "machine account quota after: 10"),
        # The read-back of the quota is missing.
        ("machine account quota after: 0\n", ""),
        # The quota was never read before the write.
        ("machine account quota before: 10\n", ""),
    ],
)
def test_stage_5_stops_when_the_machine_account_quota_is_not_zero(server: Server, old: str, new: str) -> None:
    text = _measured("s5-structure.txt")
    assert old in text, old
    out = _run5(server, _plan5(), text.replace(old, new, 1))
    _stopped(server, out, "5", "readback_failed")
    assert {c["name"]: c for c in out["answer"]["checks"]}["machine_account_quota"]["ok"] is False


def test_stage_5_makes_the_owner_admin_not_delegatable(server: Server) -> None:
    """AD-A-09 for the owner admin: the account carries the NOT_DELEGATED
    bit (0x100000) of userAccountControl, and the read-back proves it."""
    result = _run5(server, _plan5(), _measured("s5-structure.txt"))
    assert result["answer"]["status"] == "done", result
    checks = {c["name"]: c for c in result["answer"]["checks"]}
    assert "owner_admin_not_delegated" in checks, checks
    assert checks["owner_admin_not_delegated"]["ok"] is True, checks
    script = next(c["script"] for c in result["calls"] if c["kind"] == "op")
    assert "Set-ADAccountControl" in script
    assert "AccountNotDelegated" in script


@pytest.mark.parametrize(
    ("old", "new"),
    [
        # The bit is not on the account.
        ("owner admin UAC 1048592", "owner admin UAC 512"),
        # The op says the account is not delegable, but the value says else.
        ("NOT_DELEGATED True", "NOT_DELEGATED False"),
        # The read-back of the bit is missing.
        ("  owner admin UAC 1048592 | NOT_DELEGATED True\n", ""),
    ],
)
def test_stage_5_stops_when_the_owner_admin_may_be_delegated(server: Server, old: str, new: str) -> None:
    text = _measured("s5-structure.txt")
    assert old in text, old
    out = _run5(server, _plan5(), text.replace(old, new, 1))
    _stopped(server, out, "5", "readback_failed")
    assert {c["name"]: c for c in out["answer"]["checks"]}["owner_admin_not_delegated"]["ok"] is False


def test_the_secrets_reach_the_task_only_through_the_dpapi_files(server: Server) -> None:
    """The owner's admin secret is written to its DPAPI file and removed
    after the op; it is in no rendered script, the journal or the
    answer.  The built-in Administrator's password is made inside the op
    (random-password) and so is no file and no value of the helper."""
    the_plan = _plan5()
    digest = plan.digest(the_plan)
    admin = plan.derive_secret(KEY_HEX, digest, plan.ADMIN_INFO)
    result = _run5(server, the_plan, _measured("s5-structure.txt"))
    secrets = [(c["path"], c["secret"]) for c in result["calls"] if c["kind"] == "secret"]
    assert secrets == [("C:\\NewtonBuild\\admin.bin", admin)]
    removed = [c["path"] for c in result["calls"] if c["kind"] == "secret-removed"]
    assert removed == ["C:\\NewtonBuild\\admin.bin"]
    for call in result["calls"]:
        if call["kind"] == "op":
            assert admin not in call["script"]
            assert "$AdminSecretFile = 'C:\\NewtonBuild\\admin.bin'" in call["script"]
    journal = json.dumps(server.journal())
    assert admin not in journal
    assert admin not in json.dumps(result["answer"])
    # The secret file is written before the task starts and removed after it.
    kinds = [c["kind"] for c in result["calls"] if c["kind"] in ("secret", "op", "secret-removed")]
    assert kinds == ["secret", "op", "secret-removed"]


def test_a_resume_plans_stage_5_gives_the_owner_the_first_plans_admin_password(server: Server) -> None:
    """DESIGN-1.5 open point 71 (review finding 4 of task 8 part E): stage 5
    run by a resume plan derives the owner's admin secret from the signed
    secrets_from, the first plan's digest, which every approval of the
    build shows; never from the resume plan's own digest."""
    first = _plan5()
    _seed_through(server, first, "4")
    inputs = copy.deepcopy(PLAN_INPUTS)
    inputs["domain"]["ou_tree"] = ["IT/Servers", "Staff"]
    inputs["domain"]["groups"] = ["IT Admins", "Staff Users"]
    inputs["resume_from"] = plan.digest(first)
    inputs["start_stage"] = "5"
    inputs["secrets_from"] = plan.digest(first)
    resumed = plan.plan_build(inputs)
    assert plan.digest(resumed) != plan.digest(first)
    result = _call(server, resumed, "5", ops={"s5-structure": {"result": 0, "output": _measured("s5-structure.txt")}})
    assert result["answer"]["status"] == "done", result
    secrets = [c["secret"] for c in result["calls"] if c["kind"] == "secret"]
    assert secrets == [plan.derive_secret(KEY_HEX, plan.digest(first), plan.ADMIN_INFO)]


def test_no_secret_in_any_rendered_command_line(server: Server) -> None:
    """Grep every render: the header of an op names the secret files,
    never a secret, and no op passes a password on a command line."""
    the_plan = _plan5()
    digest = plan.digest(the_plan)
    secrets = [plan.derive_secret(KEY_HEX, digest, info) for info in [plan.ADMIN_INFO, plan.DSRM_INFO]]
    scripts = _render(server, _stage_values(server, the_plan), NEW_OPS)
    for op, script in scripts.items():
        for secret in secrets:
            assert secret not in script, op
        assert not re.search(r"-AsPlainText[^\n]*'[^']{8,}'", script), op
        assert not re.search(r"(?i)password\s*=\s*'", script), op


@pytest.mark.parametrize("option", ["random-password", "disabled"])
def test_the_built_in_administrator_option_reaches_the_op(server: Server, option: str) -> None:
    the_plan = _with_option(option)
    fixture = "s5-structure.txt" if option == "random-password" else "s5-structure-disabled.txt"
    result = _run5(server, the_plan, _measured(fixture))
    assert result["answer"]["status"] == "done", result
    assert [c["path"] for c in result["calls"] if c["kind"] == "secret"] == ["C:\\NewtonBuild\\admin.bin"]
    script = next(c["script"] for c in result["calls"] if c["kind"] == "op")
    assert f"$AdministratorOption = '{option}'" in script


def test_the_built_in_administrator_is_read_back_per_its_option(server: Server) -> None:
    """random-password: enabled, its password set after the task started.
    disabled: the account disabled.  The other output is a deviation."""
    out = _run5(server, _with_option("disabled"), _measured("s5-structure.txt"))
    _stopped(server, out, "5", "readback_failed")
    assert {c["name"]: c for c in out["answer"]["checks"]}["builtin_administrator"]["ok"] is False
    other = Server(server.root.parent / "install-2")
    out = _run5(other, _with_option("random-password"), _measured("s5-structure-disabled.txt"))
    _stopped(other, out, "5", "readback_failed")
    assert {c["name"]: c for c in out["answer"]["checks"]}["builtin_administrator"]["ok"] is False


def test_random_password_with_an_old_password_last_set_stops(server: Server) -> None:
    output = re.sub(r"(built-in Administrator \S+ \(\S+\) \| Enabled True \| PasswordLastSet )\S+",
                    lambda m: m.group(1) + "2026-11-13T00:00:00.0000000Z", _measured("s5-structure.txt"))
    assert output != _measured("s5-structure.txt")
    out = _run5(server, _plan5(), output)
    _stopped(server, out, "5", "readback_failed")
    assert {c["name"]: c for c in out["answer"]["checks"]}["builtin_administrator"]["ok"] is False


# ---------------------------------------------------------------------------
# The disabled built-in Administrator in Protected Users (the maintainer's
# ruling of 2026-11-24): with the baseline option administrator =
# "disabled" alone, AD-A-06 and AD-A-09 still find the account of RID
# 500, because both skip a member of Protected Users and nothing else.
# Stage 5 therefore adds the account to that group (RID 525) and reads
# the membership back.  With the option random-password nothing changes.
# ---------------------------------------------------------------------------

#: The read-back line of the membership of the built-in Administrator in
#: Protected Users: the account, its SID and the word of a member.
PROTECTED_USERS_LINE = (
    "  protected users: Administrator (S-1-5-21-1000000001-1000000002-1000000003-500) | member"
)


def test_stage_5_adds_the_built_in_administrator_to_protected_users(server: Server) -> None:
    """The option administrator = disabled: stage 5 adds the account of
    RID 500 to Protected Users (RID 525) and the read-back proves the
    membership, so the new check names it."""
    result = _run5(server, _with_option("disabled"), _measured("s5-structure-disabled.txt"))
    assert result["answer"]["status"] == "done", result
    checks = {c["name"]: c for c in result["answer"]["checks"]}
    assert "builtin_administrator_protected_users" in checks, checks
    assert checks["builtin_administrator_protected_users"]["ok"] is True, checks
    script = next(c["script"] for c in result["calls"] if c["kind"] == "op")
    assert "Add-ADGroupMember" in script
    assert "Get-ADGroupMember" in script


@pytest.mark.parametrize(
    ("old", "new"),
    [
        # The read-back of the membership is missing.
        (PROTECTED_USERS_LINE + "\n", ""),
        # The account is not a member of Protected Users.
        (PROTECTED_USERS_LINE, PROTECTED_USERS_LINE.replace("| member", "| not a member")),
        # Another account is in Protected Users, not the one of RID 500.
        (PROTECTED_USERS_LINE, PROTECTED_USERS_LINE.replace("-500)", "-501)")),
    ],
)
def test_stage_5_stops_when_the_built_in_administrator_is_not_in_protected_users(
    server: Server, old: str, new: str
) -> None:
    text = _measured("s5-structure-disabled.txt")
    assert old in text, old
    out = _run5(server, _with_option("disabled"), text.replace(old, new, 1))
    _stopped(server, out, "5", "readback_failed")
    assert {c["name"]: c for c in out["answer"]["checks"]}["builtin_administrator_protected_users"]["ok"] is False


def test_the_random_password_option_changes_nothing_of_protected_users(server: Server) -> None:
    """With random-password the built-in Administrator is not put in
    Protected Users: the op says nothing of it and the read-back holds
    no line of it."""
    text = _measured("s5-structure.txt")
    assert "protected users" not in text
    result = _run5(server, _with_option("random-password"), text)
    assert result["answer"]["status"] == "done", result
    checks = {c["name"]: c for c in result["answer"]["checks"]}
    assert "builtin_administrator_protected_users" not in checks, checks


def _drop_line(prefix: str) -> str:
    lines = _measured("s5-structure.txt").splitlines(keepends=True)
    kept = [l for l in lines if not l.startswith(prefix)]
    assert len(kept) < len(lines), prefix
    return "".join(kept)


@pytest.mark.parametrize(
    ("change", "check"),
    [
        (lambda t: _drop_line("  OU OU=Servers"), "ous"),
        (lambda t: t.replace("| Protected True", "| Protected False", 1), "ous"),
        (lambda t: _drop_line("  group Staff Users"), "groups"),
        (lambda t: t.replace("| Global | Security", "| DomainLocal | Security", 1), "groups"),
        (lambda t: t.replace("owner-admin | Enabled True", "owner-admin | Enabled False"), "owner_admin"),
        (lambda t: re.sub(r"Protected Users \([^)]*\)", "Remote Desktop Users (S-1-5-32-555)", t), "owner_admin_groups"),
        (lambda t: t.replace("MinPasswordLength 14", "MinPasswordLength 7"), "password_policy"),
        (lambda t: t.replace("LockoutThreshold 10 | LockoutDuration", "LockoutThreshold 0 | LockoutDuration", 1), "password_policy"),
        (lambda t: t.replace("Precedence 10", "Precedence 20"), "admin_pso"),
        (lambda t: _drop_line("  PSO applies to: "), "admin_pso"),
        # The owner admin must change its password at first logon (review 3.1).
        (lambda t: t.replace("| pwdLastSet 0 |", "| pwdLastSet 134079099919391214 |"), "owner_admin"),
        # The owner admin in Domain Admins, Domain Users and Protected Users only (review 3.2).
        (lambda t: t.replace("  owner admin groups: ", "  owner admin groups: Account Operators (S-1-5-32-548), "), "owner_admin_groups"),
        # The PSO applies to Domain Admins only (review 3.2).
        (lambda t: t.replace("  PSO applies to: CN=Domain Admins,", "  PSO applies to: CN=Domain Admins,CN=Users,DC=build,DC=newton,DC=test; CN=Staff Users,"), "admin_pso"),
        (lambda t: t.replace("admin secret file deleted: True", "admin secret file deleted: False"), "secret_files"),
        (lambda t: _drop_line("built-in Administrator: "), "builtin_administrator"),
        (lambda t: _drop_line("domain: "), "domain"),
    ],
)
def test_stage_5_stops_readback_failed_on_each_deviation(server: Server, change: Any, check: str) -> None:
    output = change(_measured("s5-structure.txt"))
    assert output != _measured("s5-structure.txt")
    out = _run5(server, _plan5(), output)
    _stopped(server, out, "5", "readback_failed")
    assert {c["name"]: c for c in out["answer"]["checks"]}[check]["ok"] is False


def test_a_failed_stage_5_op_stops_and_removes_the_secret_files(server: Server) -> None:
    out = _run5(server, _plan5(), "task identity: x\nFAIL: System.Exception: boom\n", result=1)
    _stopped(server, out, "5", "op_failed")
    removed = [c["path"] for c in out["calls"] if c["kind"] == "secret-removed"]
    assert removed == ["C:\\NewtonBuild\\admin.bin"]


def test_an_empty_stage_5_output_stops_readback_failed(server: Server) -> None:
    out = _run5(server, _plan5(), "")
    _stopped(server, out, "5", "readback_failed")


def test_a_rerun_of_stage_5_over_present_objects_reads_back_the_same(server: Server) -> None:
    """Documents the measured fixture only (no helper runs here): the
    second run (the disabled option) found every object there already
    and left it as it is.  The op body runs only on Windows, so the
    present branch is proven by the lab run; the verdict over this
    output is driven by test_the_built_in_administrator_option_reaches_the_op."""
    text = _measured("s5-structure-disabled.txt")
    assert "OU present: " in text and "group present: " in text and "owner admin present: " in text


# ---------------------------------------------------------------------------
# stage 6
# ---------------------------------------------------------------------------


def _ops6(**over: Any) -> dict[str, dict[str, Any]]:
    ops = {
        "s6-gpo-domain": _ok(_measured("s6-gpo-domain.txt")),
        "s6-gpo-dc": _ok(_measured("s6-gpo-dc.txt")),
        "s6-read": _ok(_measured("s6-read.txt")),
    }
    ops.update(over)
    return ops


def _run6(server: Server, the_plan: dict[str, Any], **over: Any) -> dict[str, Any]:
    _seed_through(server, the_plan, "5", CP6)
    return _call(server, the_plan, "6", ops=_ops6(**over), checkpoint=CP6)


def test_stage_6_writes_each_gpo_then_reads_the_policy_back(server: Server) -> None:
    the_plan = _plan5()
    result = _run6(server, the_plan)
    assert result["answer"]["status"] == "done", result
    ops = [(c["op"], c["task"]) for c in result["calls"] if c["kind"] == "op"]
    assert ops == [("s6-gpo-domain", True), ("s6-gpo-dc", True), ("s6-read", True)]
    assert _restarts(result) == 0
    assert _states(server, "6") == ["checkpointed", "started", "done"]
    assert all(e["checkpoint"] == CP6 for e in server.journal() if e["stage"] == "6")
    names = [c["name"] for c in result["answer"]["checks"]]
    for name in ["gpo_domain", "gpo_dc", "gpupdate", "registry", "secedit_password_policy", "secedit_registry_values",
                 "password_policy_after_refresh", "gpo_versions"]:
        assert name in names, name


def test_stage_6_without_a_checkpoint_is_refused(server: Server) -> None:
    the_plan = _plan5()
    _seed_through(server, the_plan, "5")
    result = _call(server, the_plan, "6", ops=_ops6())
    assert result["answer"]["code"] == "schema"
    assert _ops_called(result) == []


def test_stage_6_under_the_plan_token_is_bad_token(server: Server) -> None:
    the_plan = _plan5()
    _seed_through(server, the_plan, "5", CP6)
    result = _call(server, the_plan, "6", ops=_ops6())
    assert result["answer"]["code"] == "bad_token"
    assert _ops_called(result) == []


def test_a_failed_gpo_op_stops_before_the_next_gpo(server: Server) -> None:
    result = _run6(server, _plan5(), **{"s6-gpo-domain": {"result": 1, "output": "FAIL: System.Exception: x\n"}})
    _stopped(server, result, "6", "op_failed")
    assert _ops_called(result) == ["s6-gpo-domain"]


def test_a_gpo_of_the_name_already_there_stops(server: Server) -> None:
    output = _measured("s6-gpo-dc.txt").replace("before: GPOs of the name: 0", "before: GPOs of the name: 1")
    result = _run6(server, _plan5(), **{"s6-gpo-dc": _ok(output)})
    _stopped(server, result, "6", "readback_failed")
    assert _ops_called(result) == ["s6-gpo-domain", "s6-gpo-dc"]


@pytest.mark.parametrize(
    ("op", "old", "new", "check"),
    [
        ("s6-gpo-domain", "LmCompatibilityLevel = 5 | DWord", "LmCompatibilityLevel = 3 | DWord", "gpo_domain"),
        ("s6-gpo-dc", "LDAPServerIntegrity = 2 | DWord", "LDAPServerIntegrity = 1 | DWord", "gpo_dc"),
        ("s6-gpo-dc", "ADPasswordEncryptionEnabled = 1 | DWord", "ADPasswordEncryptionEnabled = 0 | DWord", "gpo_dc"),
        ("s6-gpo-dc", "ADBackupDSRMPassword = 1 | DWord", "ADBackupDSRMPassword = 0 | DWord", "gpo_dc"),
        ("s6-gpo-dc", "| Enabled True |", "| Enabled False |", "gpo_dc"),
        ("s6-read", "LmCompatibilityLevel = 5", "LmCompatibilityLevel = 3", "registry"),
        ("s6-read", "LDAPServerIntegrity = 2", "LDAPServerIntegrity : absent", "registry"),
        ("s6-read", "ADPasswordEncryptionEnabled = 1", "ADPasswordEncryptionEnabled = 0", "registry"),
        ("s6-read", "ADBackupDSRMPassword = 1", "ADBackupDSRMPassword : absent", "registry"),
        ("s6-read", "secedit MinimumPasswordLength = 14", "secedit MinimumPasswordLength = 7", "secedit_password_policy"),
        ("s6-read", "secedit LockoutBadCount = 10", "secedit LockoutBadCount = 0", "secedit_password_policy"),
        ("s6-read", "password policy: MinPasswordLength 14", "password policy: MinPasswordLength 7", "password_policy_after_refresh"),
    ],
)
def test_stage_6_stops_readback_failed_on_each_deviation(server: Server, op: str, old: str, new: str, check: str) -> None:
    text = _measured(f"{op}.txt")
    assert old in text, old
    result = _run6(server, _plan5(), **{op: _ok(text.replace(old, new, 1))})
    _stopped(server, result, "6", "readback_failed")
    assert {c["name"]: c for c in result["answer"]["checks"]}[check]["ok"] is False


# ---------------------------------------------------------------------------
# stage 6: Windows LAPS on the domain controllers (AD-A-46)
# ---------------------------------------------------------------------------


def test_the_dc_gpo_sets_the_windows_laps_policy(server: Server) -> None:
    """The DC baseline GPO sets the Windows LAPS policy value
    BackupDirectory = 2 (Active Directory), and the file of the baseline
    says so."""
    loaded = baseline_mod.load_baseline("2026.11")
    assert LAPS_KEY + "|BackupDirectory|2" in loaded.gpo_settings("dc")
    scripts = _render(server, _stage_values(server, _plan5()), ["s6-gpo-dc"])
    assert "'" + LAPS_KEY + "|BackupDirectory|2'" in scripts["s6-gpo-dc"]
    values = _stage_values(server, _plan5())
    assert LAPS_KEY + "|BackupDirectory|2" in values["DcGpoSettings"]


#: The three values of the Windows LAPS policy of the DCs (Microsoft
#: Learn, "LAPS management policy settings", read 2026-11-24): the
#: directory the password goes to (2, Active Directory only), the
#: encryption of that password in the directory (1) and the backup of the
#: DSRM password of the domain controller (1).  Without the two last
#: ones a domain controller backs up nothing: on a DC Windows LAPS
#: manages the DSRM password only.
LAPS_SETTINGS = (
    "BackupDirectory|2",
    "ADPasswordEncryptionEnabled|1",
    "ADBackupDSRMPassword|1",
)

#: The page that names the three values and the requirement of the
#: encryption (the domain functional level 2016 or later).
LAPS_SOURCE = "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-policy-settings"


def test_the_dc_gpo_sets_the_three_windows_laps_values(server: Server) -> None:
    """The DC baseline GPO sets the three values of the Windows LAPS
    policy: the directory to back up to (2), the encryption of the
    password in the directory (1) and the backup of the DSRM password
    (1).  The file of the baseline, the compiled list of the helper and
    the rendered op hold the three."""
    loaded = baseline_mod.load_baseline("2026.11")
    settings = loaded.gpo_settings("dc")
    for one in LAPS_SETTINGS:
        assert LAPS_KEY + "|" + one in settings, one
    scripts = _render(server, _stage_values(server, _plan5()), ["s6-gpo-dc"])
    for one in LAPS_SETTINGS:
        assert "'" + LAPS_KEY + "|" + one + "'" in scripts["s6-gpo-dc"], one
    values = _stage_values(server, _plan5())
    for one in LAPS_SETTINGS:
        assert LAPS_KEY + "|" + one in values["DcGpoSettings"], one


def test_every_laps_value_cites_the_page_that_names_it() -> None:
    """Every value of the Windows LAPS policy cites the page that names
    it, and none of them is a value of the security template (the export
    of secedit never holds the LAPS policy)."""
    loaded = baseline_mod.load_baseline("2026.11")
    laps = [s for s in loaded.settings if s.key == LAPS_KEY]
    assert len(laps) == 3, [s.id for s in laps]
    for setting in laps:
        assert setting.source == LAPS_SOURCE, setting.id
        assert setting.security_template is False, setting.id
    for one in LAPS_SETTINGS:
        assert LAPS_KEY + "|" + one not in loaded.security_gpo_settings(), one


def test_stage_6_reads_the_three_laps_values_back(server: Server) -> None:
    """The read of stage 6 proves the three values of the Windows LAPS
    policy: the GPO holds them as DWords and the registry of DC1 holds
    them after the refresh."""
    result = _run6(server, _plan5())
    assert result["answer"]["status"] == "done", result
    checks = {c["name"]: c for c in result["answer"]["checks"]}
    assert checks["registry"]["ok"] is True, checks
    assert checks["gpo_dc"]["ok"] is True, checks
    read = _measured("s6-read.txt").splitlines()
    gpo = _measured("s6-gpo-dc.txt").splitlines()
    for one in LAPS_SETTINGS:
        name, value = one.split("|")
        assert "registry " + LAPS_KEY + "\\" + name + " = " + value in read, one
        assert "  GPO value " + LAPS_KEY + "\\" + name + " = " + value + " | DWord | Set" in gpo, one


def test_the_security_template_holds_the_baseline_values_but_the_laps_policy(server: Server) -> None:
    """The export of the security policy (the area secedit exports) holds
    the values of the security template; the LAPS policy is not one of
    them, so the secedit check asks for the template's values only and
    the registry read proves the LAPS value."""
    loaded = baseline_mod.load_baseline("2026.11")
    security = loaded.security_gpo_settings()
    assert LAPS_KEY + "|BackupDirectory|2" not in security
    lines = [l.lower() for l in _measured("s6-read.txt").splitlines()]
    for setting in security:
        key, name, value = setting.split("|")
        path = "MACHINE" + key[4:] + "\\" + name
        assert any(l.startswith("secedit " + path.lower() + "=4," + value) for l in lines), setting
    assert not [l for l in lines if l.startswith("secedit machine\\software\\microsoft\\windows\\currentversion\\policies\\laps")]


def test_stage_6_reads_the_laps_password_of_the_computer_object_back(server: Server) -> None:
    """AD-A-46: after the refresh the op runs the LAPS policy processing
    and the read-back proves that the computer object of DC1 carries the
    LAPS password (its expiration time)."""
    result = _run6(server, _plan5())
    assert result["answer"]["status"] == "done", result
    checks = {c["name"]: c for c in result["answer"]["checks"]}
    assert "laps" in checks, checks
    assert checks["laps"]["ok"] is True, checks
    script = next(c["script"] for c in result["calls"] if c["kind"] == "op" and c["op"] == "s6-read")
    assert "Invoke-LapsPolicyProcessing" in script


@pytest.mark.parametrize(
    ("old", "new"),
    [
        # The policy processing wrote no password for the computer object.
        ("msLAPS-PasswordExpirationTime 133800000000000000", "msLAPS-PasswordExpirationTime 0"),
        # The read-back of the computer object is missing.
        ("  computer object BDC1 | msLAPS-PasswordExpirationTime 133800000000000000 | msLAPS-EncryptedDSRMPassword absent\n", ""),
    ],
)
def test_stage_6_stops_when_the_computer_object_carries_no_laps_password(server: Server, old: str, new: str) -> None:
    text = _measured("s6-read.txt")
    assert old in text, old
    result = _run6(server, _plan5(), **{"s6-read": _ok(text.replace(old, new, 1))})
    _stopped(server, result, "6", "readback_failed")
    assert {c["name"]: c for c in result["answer"]["checks"]}["laps"]["ok"] is False


@pytest.mark.parametrize("expiry", ["", "0"])
def test_stage_6_accepts_an_encrypted_dsrm_backup_with_no_expiration_time(server: Server, expiry: str) -> None:
    """Codex review 2026-11-24: on a DC Windows LAPS may write only the encrypted DSRM password; the producer then
    prints an empty expiration time, and the parser must still accept the present DSRM backup."""
    text = _measured("s6-read.txt")
    old = "msLAPS-PasswordExpirationTime 133800000000000000 | msLAPS-EncryptedDSRMPassword absent"
    assert old in text, old
    new = "msLAPS-PasswordExpirationTime " + expiry + " | msLAPS-EncryptedDSRMPassword present"
    result = _run6(server, _plan5(), **{"s6-read": _ok(text.replace(old, new, 1))})
    assert result["answer"]["status"] == "done", result
    assert {c["name"]: c for c in result["answer"]["checks"]}["laps"]["ok"] is True


def test_stage_6_stops_when_neither_laps_attribute_is_present(server: Server) -> None:
    text = _measured("s6-read.txt")
    old = "msLAPS-PasswordExpirationTime 133800000000000000 | msLAPS-EncryptedDSRMPassword absent"
    result = _run6(server, _plan5(), **{"s6-read": _ok(text.replace(old, "msLAPS-PasswordExpirationTime  | msLAPS-EncryptedDSRMPassword absent", 1))})
    _stopped(server, result, "6", "readback_failed")


# ---------------------------------------------------------------------------
# The domain functional level the Windows LAPS policy needs (2016 or later)
# ---------------------------------------------------------------------------

#: A domain that runs below the domain functional level 2016 (the
#: msDS-Behavior-Version of Windows Server 2012 R2 is 6).  The design
#: builds the forest at 2025 only, so the bytes of such a plan are made
#: by hand.
LEVEL_BELOW_2016 = "Win2012R2"


def _plan_bytes_at_level(level: str) -> bytes:
    text = plan.canonical_bytes(_plan5()).decode("ascii")
    changed = re.sub(r"(?m)^domain\.functional_level=.*$", f"domain.functional_level={level}", text)
    assert changed != text
    return changed.encode("ascii")


def test_the_plan_refuses_a_domain_level_below_2016_clearly() -> None:
    """The Windows LAPS policy of the DCs needs the domain functional
    level 2016 or later (ADPasswordEncryptionEnabled), so a plan that
    asks for an older level is refused, and the refusal says why."""
    inputs = copy.deepcopy(PLAN_INPUTS)
    inputs["domain"]["functional_level"] = LEVEL_BELOW_2016
    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)
    assert caught.value.code == "free_text"
    assert "2016" in str(caught.value)
    assert "LAPS" in str(caught.value)


def test_the_helper_refuses_a_domain_level_below_2016_clearly(server: Server) -> None:
    """The helper refuses a plan whose domain runs below the domain
    functional level 2016 before anything runs, and the refusal names
    the Windows LAPS policy and the level it needs."""
    raw = _plan_bytes_at_level(LEVEL_BELOW_2016)
    digest = hashlib.sha256(raw).hexdigest()
    request = json.dumps({
        "run": RUN,
        "plan": base64.b64encode(raw).decode("ascii"),
        "stage": "5",
        "action": "run",
        "token": approval_token(KEY_HEX, digest, NBF, EXP),
        "nbf": NBF,
        "exp": EXP,
    })
    result = server.drive({"mode": "request", "request": request, "fake": {
        "ops": {}, "groups": [], "directory": True, "restart": True, "results": {}, "running": []}})
    assert result["answer"]["code"] == "schema", result
    assert "2016" in result["error"], result
    assert "LAPS" in result["error"], result
    assert server.journal() == []
    assert result["calls"] == []


def test_the_helper_holds_the_domain_levels_of_the_plan_model() -> None:
    """The levels of build.ps1 are the ones of plan.py, and the level the
    Windows LAPS policy needs is the one of the plan model."""
    text = HELPER.read_text(encoding="utf-8")
    block = re.search(r"\$script:DomainLevels = @\{(.*?)\n\}", text, re.S)
    assert block is not None
    found = dict(re.findall(r"'([^']+)'\s*=\s*([0-9]+)", block.group(1)))
    assert found == {name: str(number) for name, number in plan.DOMAIN_LEVELS.items()}
    minimum = re.search(r"\$script:LapsMinimumDomainLevel = ([0-9]+)", text)
    assert minimum is not None
    assert int(minimum.group(1)) == plan.LAPS_MINIMUM_DOMAIN_LEVEL


def _system_access(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    inside = False
    for line in text.splitlines():
        if line == "secedit [System Access]":
            inside = True
            continue
        if inside and line.startswith("secedit ["):
            break
        if inside and line.startswith("secedit "):
            key, _, value = line[len("secedit "):].partition(" = ")
            values[key] = value
    return values


def test_the_secedit_read_back_parses_the_measured_export() -> None:
    """Documents the measured fixtures (the verdict over them is driven by
    test_stage_6_writes_each_gpo_then_reads_the_policy_back and
    test_the_default_policy_export_is_refused).  The [System Access] of
    the measured export after stage 6 holds the
    baseline's account policy.  The measured export of the fresh forest
    before stage 5 does not: its domain password policy is length 0,
    history 0 and no lockout (the Default Domain Policy's GptTmpl.inf
    says 7 and 24, and the domain does not hold them)."""
    after = _system_access(_measured("s6-read.txt"))
    assert (after["MinimumPasswordLength"], after["PasswordHistorySize"], after["LockoutBadCount"],
            after["ResetLockoutCount"], after["LockoutDuration"], after["ClearTextPassword"]) == (
        "14", "24", "10", "15", "15", "0")
    default = _system_access(_measured("secedit-default.txt"))
    assert (default["MinimumPasswordLength"], default["PasswordHistorySize"], default["LockoutBadCount"],
            default["MaximumPasswordAge"]) == ("0", "0", "0", "42")


def test_the_default_policy_export_is_refused(server: Server) -> None:
    """s6-read with the [System Access] of the measured default export:
    the stage stops readback_failed, naming the secedit check."""
    default = _measured("secedit-default.txt").splitlines()
    start = default.index("secedit [System Access]")
    end = next(i for i in range(start + 1, len(default)) if default[i].startswith("secedit ["))
    lines = _measured("s6-read.txt").splitlines()
    a = lines.index("secedit [System Access]")
    b = next(i for i in range(a + 1, len(lines)) if lines[i].startswith("secedit ["))
    changed = "\n".join(lines[:a] + default[start:end] + lines[b:]) + "\n"
    result = _run6(server, _plan5(), **{"s6-read": _ok(changed)})
    _stopped(server, result, "6", "readback_failed")
    assert {c["name"]: c for c in result["answer"]["checks"]}["secedit_password_policy"]["ok"] is False


@pytest.mark.parametrize(
    "line",
    [
        "secedit MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity=4,2",
        "secedit MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel=4,5",
        "secedit MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\RequireSecuritySignature=4,1",
    ],
)
def test_the_secedit_registry_values_hold_each_baseline_value(server: Server, line: str) -> None:
    """The export's [Registry Values] lists the security options the DC
    applies (measured: each baseline value, LanManServer in secedit's own
    case); one missing or changed stops readback_failed."""
    text = _measured("s6-read.txt")
    assert line in text.splitlines(), line
    for changed in [text.replace(line + "\n", ""), text.replace(line, line[:-1] + "0")]:
        other = Server(server.root.parent / f"install-{abs(hash(changed)) % 10**8}")
        result = _run6(other, _plan5(), **{"s6-read": _ok(changed)})
        _stopped(other, result, "6", "readback_failed")
        assert {c["name"]: c for c in result["answer"]["checks"]}["secedit_registry_values"]["ok"] is False


def test_the_secedit_check_needs_the_system_access_section(server: Server) -> None:
    text = _measured("s6-read.txt").replace("secedit [System Access]", "secedit [Nothing]")
    result = _run6(server, _plan5(), **{"s6-read": _ok(text)})
    _stopped(server, result, "6", "readback_failed")


def test_a_gpo_whose_ds_and_sysvol_versions_differ_stops(server: Server) -> None:
    text = _measured("s6-read.txt")
    changed = re.sub(r"(GPO Newton Baseline 2026\.11 Domain \| GpoStatus \S+ \| Computer DSVersion )(\d+)",
                     lambda m: m.group(1) + str(int(m.group(2)) + 1), text, count=1)
    assert changed != text
    result = _run6(server, _plan5(), **{"s6-read": _ok(changed)})
    _stopped(server, result, "6", "readback_failed")
    assert {c["name"]: c for c in result["answer"]["checks"]}["gpo_versions"]["ok"] is False


def test_a_stage_after_6_still_has_no_template(server: Server) -> None:
    """A server with none of stage 8's bootstrap files refuses stage 8
    before anything, for the write helper the bootstrap installs (the maintainer's
    decision of 2026-11-19; before it, the run refused ``schema`` for the
    write helper its request no longer carries).  The template refusals
    are test_build_stage8_helper.py's."""
    the_plan = _plan5()
    _seed_through(server, the_plan, "6")
    before = server.journal()
    result = _call(server, the_plan, "8")
    assert result["answer"]["code"] == "write_helper_missing", result
    assert server.journal() == before


# ---------------------------------------------------------------------------
# A stage 4 stopped after s4-laps succeeded, resumed
# ---------------------------------------------------------------------------

CP4 = "cp-4"
CP4R = "cp-4-resume"


def _stopped_after_laps(server: Server, how: str) -> dict[str, Any]:
    the_plan = _plan()
    _seed_before(server, the_plan, "4", CP4)
    if how == "restart_refused":
        _call(server, the_plan, "4", ops={"s4-laps": _ok(_s4_output())}, checkpoint=CP4, restart=False)
    else:
        _call(server, the_plan, "4", ops={"s4-laps": _ok(_s4_output())}, checkpoint=CP4)
        _call(server, the_plan, "4", "status", checkpoint=CP4, boot=BOOT_1, now=EXP + 901)
    last = server.journal()[-1]
    assert (last["stage"], last["state"]) == ("4", "stopped"), last
    inputs = copy.deepcopy(PLAN_INPUTS)
    inputs["resume_from"] = plan.digest(the_plan)
    inputs["secrets_from"] = plan.digest(the_plan)
    inputs["start_stage"] = "4"
    resumed = _plan(inputs)
    server.append({"stage": "4", "state": "checkpointed", "digest": plan.digest(resumed), "checkpoint": CP4R})
    return resumed


@pytest.mark.parametrize("how", ["restart_refused", "grace_passed"])
def test_a_resumed_stage_4_in_the_after_state_goes_on_to_the_reboot(server: Server, how: str) -> None:
    resumed = _stopped_after_laps(server, how)
    result = _call(server, resumed, "4", ops={"s4-state": _ok(_measured("s4-state-after.txt"))}, checkpoint=CP4R)
    assert result["answer"]["status"] == "rebooting", result
    assert _ops_called(result) == ["s4-state"]
    assert _restarts(result) == 1
    # Then the boot and the group read, as an unresumed stage 4.
    done = _call(server, resumed, "4", "status", checkpoint=CP4R, boot="2026-11-13T15:00:05.5000000Z",
                 ops={"s4-groups": _ok(_fixture("s4-groups.txt"))},
                 groups=[l for l in _fixture("s4-s4u-groups-after-boot.txt").splitlines() if l])
    assert done["answer"]["status"] == "done", done


def test_a_resumed_stage_4_in_the_before_state_runs_s4_laps(server: Server) -> None:
    the_plan = _plan()
    _seed_before(server, the_plan, "4", CP4)
    bad = _s4_output().replace("  ms-Mcs-AdmPwd : absent", "  ms-Mcs-AdmPwd : present")
    _call(server, the_plan, "4", ops={"s4-laps": _ok(bad)}, checkpoint=CP4)
    inputs = copy.deepcopy(PLAN_INPUTS)
    inputs["resume_from"] = plan.digest(the_plan)
    inputs["secrets_from"] = plan.digest(the_plan)
    inputs["start_stage"] = "4"
    resumed = _plan(inputs)
    server.append({"stage": "4", "state": "checkpointed", "digest": plan.digest(resumed), "checkpoint": CP4R})
    result = _call(server, resumed, "4", checkpoint=CP4R,
                   ops={"s4-state": _ok(_measured("s4-state-before.txt")), "s4-laps": _ok(_s4_output())})
    assert result["answer"]["status"] == "rebooting", result
    assert _ops_called(result) == ["s4-state", "s4-laps"]


@pytest.mark.parametrize(
    ("old", "new"),
    [
        # The schema there, but one ACE missing: s4-laps stopped half way.
        ("ReadProperty, WriteProperty, ExtendedRight", "ReadProperty"),
        # The ACEs there, but the build account still in Schema Admins.
        ("  Schema Admins members: Administrator", "  Schema Admins members: Administrator, newton-build"),
        # One LAPS attribute absent.
        ("  ms-LAPS-EncryptedDSRMPassword : present", "  ms-LAPS-EncryptedDSRMPassword : absent"),
    ],
)
def test_a_resumed_stage_4_in_any_other_state_stops_with_no_write(server: Server, old: str, new: str) -> None:
    resumed = _stopped_after_laps(server, "restart_refused")
    text = _measured("s4-state-after.txt")
    assert old in text, old
    result = _call(server, resumed, "4", ops={"s4-state": _ok(text.replace(old, new, 1))}, checkpoint=CP4R)
    _stopped(server, result, "4", "readback_failed")
    assert _ops_called(result) == ["s4-state"]
    assert _restarts(result) == 0


@pytest.mark.parametrize(
    ("old", "new"),
    [
        # The schema absent, but the build account already out of Enterprise Admins.
        ("  Enterprise Admins members: Administrator, newton-build", "  Enterprise Admins members: Administrator"),
        ("Domain Users, Enterprise Admins, Schema Admins", "Domain Users, Schema Admins"),
        # The schema absent, but the build account in a group more than measured.
        ("Domain Users, Enterprise Admins, Schema Admins", "Backup Operators, Domain Users, Enterprise Admins, Schema Admins"),
        # The schema absent, but the build account out of Domain Users.
        ("Domain Admins, Domain Users, Enterprise Admins", "Domain Admins, Enterprise Admins"),
        # The schema absent, but an explicit SELF ACE on the Domain Controllers OU already there.
        ("IsInherited True\nGet-ADPrincipalGroupMembership",
         "IsInherited True\n  NT AUTHORITY\\SELF | WriteProperty | Allow | ObjectType ec25cc5c-46a7-42ab-90a1-fb73b06146b9 () | "
         "InheritanceType Descendents | InheritedObjectType bf967a86-0de6-11d0-a285-00aa003049e2 | IsInherited False\n"
         "Get-ADPrincipalGroupMembership"),
    ],
)
def test_a_resumed_stage_4_not_in_the_measured_before_state_stops(server: Server, old: str, new: str) -> None:
    """Review 3.3: 'before' is the whole measured before-state (no LAPS
    schema, no explicit SELF ACE, the build account in Enterprise and
    Schema Admins); a state with the schema absent and anything else
    changed stops before s4-laps."""
    resumed = _stopped_after_laps(server, "restart_refused")
    text = _measured("s4-state-before.txt")
    assert old in text, old
    result = _call(server, resumed, "4", ops={"s4-state": _ok(text.replace(old, new, 1))}, checkpoint=CP4R)
    _stopped(server, result, "4", "readback_failed")
    assert _ops_called(result) == ["s4-state"]
    assert _restarts(result) == 0


def test_a_failed_s4_state_read_stops_readback_failed(server: Server) -> None:
    resumed = _stopped_after_laps(server, "restart_refused")
    result = _call(server, resumed, "4", ops={"s4-state": {"result": 1, "output": "FAIL: x\n"}}, checkpoint=CP4R)
    _stopped(server, result, "4", "readback_failed")
    assert _ops_called(result) == ["s4-state"]


def test_an_unresumed_stage_4_reads_no_state_first(server: Server) -> None:
    the_plan = _plan()
    _seed_before(server, the_plan, "4", CP4)
    result = _call(server, the_plan, "4", ops={"s4-laps": _ok(_s4_output())}, checkpoint=CP4)
    assert _ops_called(result) == ["s4-laps"]


def test_the_measured_states_are_the_lines_s4_laps_prints() -> None:
    """Documents the measured fixtures (the verdict over them is driven by
    the resumed stage 4 tests above).  s4-state prints the schema and ACE
    lines s4-laps prints after its
    writes: the measured after-state read holds the same attribute and
    ACE lines, GUIDs of its own forest."""
    after = _measured("s4-state-after.txt")
    before = _measured("s4-state-before.txt")
    assert after.count(" : present, lDAPDisplayName msLAPS-") == 6
    assert before.count(" : absent") == 7
    assert "NT AUTHORITY\\SELF | ReadProperty, WriteProperty, ExtendedRight | Allow" in after


# ---------------------------------------------------------------------------
# The directory_groups check of a failed s4-groups read
# ---------------------------------------------------------------------------


def test_a_failed_s4_groups_read_names_the_directory_groups_check(server: Server) -> None:
    the_plan = _plan()
    _seed_before(server, the_plan, "4", CP4)
    _call(server, the_plan, "4", ops={"s4-laps": _ok(_s4_output())}, checkpoint=CP4)
    result = _call(server, the_plan, "4", "status", checkpoint=CP4, boot=BOOT_1,
                   ops={"s4-groups": {"result": 1, "output": _fixture("s4-groups-directory-unready.txt")}},
                   groups=[l for l in _fixture("s4-s4u-groups-after-boot.txt").splitlines() if l])
    _stopped(server, result, "4", "readback_failed")
    checks = [c for c in result["answer"]["checks"] if c["name"] == "directory_groups"]
    assert len(checks) == 1 and checks[0]["ok"] is False, result["answer"]["checks"]


# ---------------------------------------------------------------------------
# the task 6 triage: IC1a, IC1b, IC2, IC3, IC4, X-F1
# ---------------------------------------------------------------------------


def test_a_failed_gpupdate_stops_stage_6_naming_it(server: Server) -> None:
    """IC1a: s6-read whose policy refresh did not exit 0 stops
    readback_failed, and the check that fails is the gpupdate one."""
    text = _measured("s6-read.txt")
    line = "gpupdate /target:computer /force exit 0"
    assert line in text.splitlines(), line
    result = _run6(server, _plan5(), **{"s6-read": _ok(text.replace(line, "gpupdate /target:computer /force exit 1", 1))})
    _stopped(server, result, "6", "readback_failed")
    checks = {c["name"]: c for c in result["answer"]["checks"]}
    assert checks["gpupdate"]["ok"] is False
    assert [c["name"] for c in result["answer"]["checks"] if not c["ok"]] == ["gpupdate"]


def test_a_failed_s6_read_stops_readback_failed(server: Server) -> None:
    """IC2: the read of stage 6 that fails stops readback_failed, as the
    reads of stage 4 do, never op_failed."""
    result = _run6(server, _plan5(), **{"s6-read": {"result": 1, "output": "task identity: x\nFAIL: System.Exception: boom\n"}})
    _stopped(server, result, "6", "readback_failed")
    assert _ops_called(result) == ["s6-gpo-domain", "s6-gpo-dc", "s6-read"]


def test_a_resumed_stage_4_with_the_legacy_laps_attribute_stops_before_the_reboot(server: Server) -> None:
    """IC1b: the after-state with ms-Mcs-AdmPwd present is not the state
    s4-laps leaves: readback_failed, no reboot, no write."""
    resumed = _stopped_after_laps(server, "restart_refused")
    text = _measured("s4-state-after.txt")
    old = "  ms-Mcs-AdmPwd : absent"
    assert old in text.splitlines()
    changed = text.replace(old, "  ms-Mcs-AdmPwd : present, lDAPDisplayName ms-Mcs-AdmPwd, "
                                "schemaIDGUID 1b8b8a2e-3b8f-4a1c-9d3e-6f0a2b4c5d6e", 1)
    result = _call(server, resumed, "4", ops={"s4-state": _ok(changed)}, checkpoint=CP4R)
    _stopped(server, result, "4", "readback_failed")
    assert _ops_called(result) == ["s4-state"]
    assert _restarts(result) == 0
    assert "rebooting" not in _states(server, "4")[-2:]


EXTRA_SELF_ACE = (
    "  NT AUTHORITY\\SELF | GenericAll | Allow | ObjectType 00000000-0000-0000-0000-000000000000 () | "
    "InheritanceType Descendents | InheritedObjectType bf967a86-0de6-11d0-a285-00aa003049e2 | IsInherited False"
)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        # A fourth explicit SELF ACE next to the three of the self-permission.
        ("IsInherited True\nGet-ADPrincipalGroupMembership", "IsInherited True\n" + EXTRA_SELF_ACE + "\nGet-ADPrincipalGroupMembership"),
        # The build account in one group more than the measured after-state.
        ("Get-ADPrincipalGroupMembership now: Administrators, Domain Admins, Domain Users",
         "Get-ADPrincipalGroupMembership now: Administrators, Domain Admins, Domain Users, Group Policy Creator Owners"),
        # The build account in one group fewer.
        ("Get-ADPrincipalGroupMembership now: Administrators, Domain Admins, Domain Users",
         "Get-ADPrincipalGroupMembership now: Domain Admins, Domain Users"),
    ],
)
def test_a_resumed_stage_4_after_state_must_be_exactly_the_measured_one(server: Server, old: str, new: str) -> None:
    """IC3: the after-state is exactly three explicit SELF ACEs and the
    measured group set of the build account (Administrators, Domain Admins,
    Domain Users); a superset stops readback_failed with no write."""
    resumed = _stopped_after_laps(server, "restart_refused")
    text = _measured("s4-state-after.txt")
    assert old in text, old
    result = _call(server, resumed, "4", ops={"s4-state": _ok(text.replace(old, new, 1))}, checkpoint=CP4R)
    _stopped(server, result, "4", "readback_failed")
    assert _ops_called(result) == ["s4-state"]
    assert _restarts(result) == 0


def test_a_resumed_stage_4_whose_state_read_still_runs_is_refused_out_of_order(server: Server) -> None:
    """X-F1: the s4-state task of an earlier request still runs: the
    resume is refused out_of_order before any started entry."""
    resumed = _stopped_after_laps(server, "restart_refused")
    before = server.journal()
    result = _call(server, resumed, "4", ops={"s4-state": _ok(_measured("s4-state-after.txt"))},
                   checkpoint=CP4R, running=["s4-state"])
    assert (result["answer"]["status"], result["answer"]["code"]) == ("refused", "out_of_order"), result
    assert server.journal() == before
    assert _ops_called(result) == []


#: IC4: the line s5-structure prints, and the exception it throws, when
#: the owner admin account is there and Newton did not make it.
FOREIGN_OWNER = (
    "task identity: nbuild\\newton-build | auth Kerberos\n"
    "owner admin present, not made by this build: owner-admin\n"
    "FAIL: System.Management.Automation.RuntimeException: the owner admin account is there and was not made by this build\n"
)


def test_a_stage_5_owner_admin_newton_did_not_make_stops_readback_failed(server: Server) -> None:
    """IC4: s5-structure found an account of the owner admin's name that
    does not carry Newton's marker: the stage stops readback_failed,
    naming the owner_admin check."""
    out = _run5(server, _plan5(), FOREIGN_OWNER, result=1)
    _stopped(server, out, "5", "readback_failed")
    checks = {c["name"]: c for c in out["answer"]["checks"]}
    assert checks["owner_admin"]["ok"] is False


def _owner_branch(script: str) -> str:
    """The part of the rendered s5-structure that finds or creates the
    owner admin and adds it to 512 and 525."""
    start = script.index("$found = $null\ntry { $found = Get-ADUser")
    # The marker is assigned just before, and is part of the branch.
    start = script.rindex("\n", 0, start - 1) + 1
    assert script[start:].startswith("$marker = "), script[start:start + 40]
    end = script.index("\n", script.index("foreach ($rid in '512', '525')"))
    return script[start:end + 1]


OWNER_STUBS = r"""
Add-Type -TypeDefinition 'namespace Microsoft.ActiveDirectory.Management { public class ADIdentityNotFoundException : System.Exception { } }'
$script:Calls = New-Object System.Collections.ArrayList
function Get-ADUser {
    param($Identity, $Properties)
    [void]$script:Calls.Add('Get-ADUser ' + $Identity + ' ' + ($Properties -join ','))
    if ($null -eq $script:FakeUser) { throw (New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException) }
    return $script:FakeUser
}
function New-ADUser {
    param($Name, $SamAccountName, $UserPrincipalName, $AccountPassword, $Enabled, $ChangePasswordAtLogon, $Path, $Description)
    [void]$script:Calls.Add('New-ADUser ' + $SamAccountName + ' | Description ' + $Description)
}
function Get-ADGroup { param($Identity) return [pscustomobject]@{ SID = $Identity } }
function Add-ADGroupMember { param($Identity, $Members) [void]$script:Calls.Add('Add-ADGroupMember ' + $Identity.SID + ' ' + $Members) }
$OwnerAdmin = 'owner-admin'
$users = 'CN=Users,DC=build,DC=newton,DC=test'
$dom = [pscustomobject]@{ DNSRoot = 'build.newton.test' }
$sid = 'S-1-5-21-1000000001-1000000002-1000000003'
$adminSecret = 'not-a-secret'
"""


def _run_owner_branch(server: Server, fake_user: str) -> list[str]:
    script = _render(server, _stage_values(server, _plan5()), ["s5-structure"])["s5-structure"]
    branch = _owner_branch(script)
    program = (
        OWNER_STUBS
        + f"$script:FakeUser = {fake_user}\n"
        + "$ErrorActionPreference = 'Stop'\n"
        + "try {\n" + branch + "} catch { 'THREW: ' + $_.Exception.Message }\n"
        + "foreach ($call in $script:Calls) { 'CALL: ' + $call }\n"
    )
    return _run_pwsh(program).splitlines()


MARKER = "Newton AD build: the owner's admin account"


def test_stage_5_creates_the_owner_admin_with_newtons_marker(server: Server) -> None:
    """IC4: the account stage 5 makes carries Newton's marker in its
    description, the only account a later run of stage 5 adds to Domain
    Admins and Protected Users."""
    out = _run_owner_branch(server, "$null")
    calls = [l for l in out if l.startswith("CALL: ")]
    assert f"CALL: New-ADUser owner-admin | Description {MARKER}" in calls, out
    assert [c for c in calls if c.startswith("CALL: Add-ADGroupMember")] == [
        "CALL: Add-ADGroupMember S-1-5-21-1000000001-1000000002-1000000003-512 owner-admin",
        "CALL: Add-ADGroupMember S-1-5-21-1000000001-1000000002-1000000003-525 owner-admin",
    ], out


@pytest.mark.parametrize(
    "fake_user",
    [
        # DefaultAccount of a fresh forest: no description of Newton's.
        "[pscustomobject]@{ SamAccountName = 'owner-admin'; Description = 'A user account managed by the system.' }",
        "[pscustomobject]@{ SamAccountName = 'owner-admin'; Description = $null }",
        # The marker in another case, or with more text: not the marker.
        "[pscustomobject]@{ SamAccountName = 'owner-admin'; Description = 'newton ad build: the owner''s admin account' }",
        "[pscustomobject]@{ SamAccountName = 'owner-admin'; Description = 'Newton AD build: the owner''s admin account (copy)' }",
    ],
)
def test_stage_5_never_adds_an_account_newton_did_not_make_to_the_admin_groups(server: Server, fake_user: str) -> None:
    """IC4: an account of the owner admin's name that Newton did not make
    stops the op before any Add-ADGroupMember, and the line the verdict
    reads is printed first."""
    out = _run_owner_branch(server, fake_user)
    assert "owner admin present, not made by this build: owner-admin" in out, out
    assert any(l.startswith("THREW: ") for l in out), out
    assert not [l for l in out if l.startswith("CALL: Add-ADGroupMember") or l.startswith("CALL: New-ADUser")], out


def test_stage_5_goes_on_over_the_owner_admin_it_made_before(server: Server) -> None:
    """A resumed stage 5 over the account an earlier run made (the
    marker): no new account, and the memberships are added."""
    out = _run_owner_branch(server, "[pscustomobject]@{ SamAccountName = 'owner-admin'; Description = 'Newton AD build: the owner''s admin account' }")
    assert "owner admin present: owner-admin" in out, out
    assert not any(l.startswith("THREW: ") for l in out), out
    calls = [l for l in out if l.startswith("CALL: ")]
    assert "CALL: Get-ADUser owner-admin Description" in calls, out
    assert not [c for c in calls if c.startswith("CALL: New-ADUser")]
    assert len([c for c in calls if c.startswith("CALL: Add-ADGroupMember")]) == 2, out


# ---------------------------------------------------------------------------
# A stage 3 or 4 stopped after its irreversible write, resumed
# ---------------------------------------------------------------------------
#
# The s3-state read prints the lines s3-recyclebin prints, with 'now' for
# 'before' and 'after'.  Its fixtures are built from the measured
# s3-recyclebin output (MEASURED-1.5, stage 3 on BUILD1): the before line
# of the fresh forest, and the after scopes and msDS-EnabledFeature line
# of the enabled feature.  s3-state itself was not run on BUILD1.

CP3 = "cp-3"
CP3R = "cp-3-resume"


def _s3_state(phase: str) -> str:
    lines = _fixture("s3-recyclebin.txt").splitlines()
    head = [l for l in lines if l.startswith("task identity: ") or l.startswith("task start ")]
    tail = [l for l in lines if l.startswith("task end ")]
    before = next(l for l in lines if l.startswith("before: EnabledScopes count "))
    i = lines.index("after: EnabledScopes:")
    scopes = []
    for line in lines[i + 1:]:
        if not line.startswith("  "):
            break
        scopes.append(line)
    feature = next(l for l in lines if l.startswith("msDS-EnabledFeature on Partitions: "))
    if phase == "before":
        body = [before.replace("before: ", "now: ", 1), "now: EnabledScopes:", "msDS-EnabledFeature on Partitions: "]
    else:
        count = before.replace("before: EnabledScopes count 0 |", f"now: EnabledScopes count {len(scopes)} |", 1)
        body = [count, "now: EnabledScopes:", *scopes, feature]
    return "\n".join(head + body + tail) + "\n"


def _resume_3(server: Server, the_plan: dict[str, Any]) -> dict[str, Any]:
    inputs = copy.deepcopy(PLAN_INPUTS)
    inputs["resume_from"] = plan.digest(the_plan)
    inputs["secrets_from"] = plan.digest(the_plan)
    inputs["start_stage"] = "3"
    resumed = _plan(inputs)
    server.append({"stage": "3", "state": "checkpointed", "digest": plan.digest(resumed), "checkpoint": CP3R})
    return resumed


def _append_stop(server: Server, record: dict[str, Any], reason: str) -> None:
    server.append(record)
    seq = len(server.journal()) - 1
    path = server.root / "journal" / f"{server.journal()[-1]['run']}.{seq}.json"
    entry = json.loads(path.read_text(encoding="utf-8"))
    entry["reason"] = reason
    path.write_text(json.dumps(entry), encoding="utf-8")


def _stopped_after_recycle(server: Server, how: str) -> dict[str, Any]:
    """A stage 3 stopped after Enable-ADOptionalFeature ran, three ways."""
    the_plan = _plan()
    digest = plan.digest(the_plan)
    _seed_before(server, the_plan, "3", CP3)
    if how == "grace_passed":
        # The session dropped while the op ran; past EXP and the grace no
        # result file is there: grace_passed, the feature may be on.
        ops = {"s3-recyclebin": {"drop": True, "result": 0, "output": ""}}
        assert _call(server, the_plan, "3", ops=ops, checkpoint=CP3).get("dropped") is True
        _call(server, the_plan, "3", "status", checkpoint=CP3, now=EXP + 900 + 60)
    elif how == "readback_failed":
        # The op enabled the feature, and its output lost the last line.
        output = "".join(l for l in _fixture("s3-recyclebin.txt").splitlines(keepends=True)
                         if not l.startswith("msDS-EnabledFeature on Partitions: "))
        _call(server, the_plan, "3", ops={"s3-recyclebin": _ok(output)}, checkpoint=CP3)
    else:
        # An error after the op succeeded, as the journal records it.
        server.append({"stage": "3", "state": "started", "digest": digest, "checkpoint": CP3})
        _append_stop(server, {"stage": "3", "state": "stopped", "digest": digest, "checkpoint": CP3}, "error")
    last = server.journal()[-1]
    assert (last["stage"], last["state"], last["reason"]) == ("3", "stopped", how), last
    return _resume_3(server, the_plan)


def _scripts_run(result: dict[str, Any]) -> str:
    return "\n".join(c["script"] for c in result["calls"] if c["kind"] == "op")


@pytest.mark.parametrize("how", ["grace_passed", "error", "readback_failed"])
def test_a_resumed_stage_3_in_the_after_state_is_done_with_no_second_enable(server: Server, how: str) -> None:
    resumed = _stopped_after_recycle(server, how)
    result = _call(server, resumed, "3", ops={"s3-state": _ok(_s3_state("after"))}, checkpoint=CP3R)
    assert result["answer"]["status"] == "done", result
    assert _ops_called(result) == ["s3-state"]
    assert "Enable-ADOptionalFeature" not in _scripts_run(result)
    assert all(c["ok"] for c in result["answer"]["checks"]), result
    names = [c["name"] for c in result["answer"]["checks"]]
    assert "recycle_bin_scope" in names and "recycle_bin_feature" in names
    assert _states(server, "3")[-3:] == ["checkpointed", "started", "done"]


def test_a_resumed_stage_3_in_the_before_state_enables_the_recycle_bin(server: Server) -> None:
    the_plan = _plan()
    digest = plan.digest(the_plan)
    _seed_before(server, the_plan, "3", CP3)
    # Stopped before the op wrote anything (the task never started).
    server.append({"stage": "3", "state": "started", "digest": digest, "checkpoint": CP3})
    _append_stop(server, {"stage": "3", "state": "stopped", "digest": digest, "checkpoint": CP3}, "op_failed")
    resumed = _resume_3(server, the_plan)
    result = _call(server, resumed, "3", checkpoint=CP3R,
                   ops={"s3-state": _ok(_s3_state("before")), "s3-recyclebin": _ok(_fixture("s3-recyclebin.txt"))})
    assert result["answer"]["status"] == "done", result
    assert _ops_called(result) == ["s3-state", "s3-recyclebin"]


@pytest.mark.parametrize(
    ("phase", "old", "new"),
    [
        # Enabled, but on another scope than the plan's Partitions container.
        ("after", "  CN=Partitions,CN=Configuration,DC=build,DC=newton,DC=test",
         "  CN=Partitions,CN=Configuration,DC=other,DC=test"),
        # Enabled on one scope more than measured.
        ("after", "  CN=Partitions,CN=Configuration,DC=build,DC=newton,DC=test\n",
         "  CN=Partitions,CN=Configuration,DC=build,DC=newton,DC=test\n  CN=NTDS Settings,CN=BDC1,CN=Servers,"
         "CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=build,DC=newton,DC=test\n"),
        # The scope there, the feature not on the Partitions container.
        ("after", "msDS-EnabledFeature on Partitions: CN=Recycle Bin Feature", "msDS-EnabledFeature on Partitions: CN=Other Feature"),
        # The count says one scope, none listed.
        ("after", "  CN=Partitions,CN=Configuration,DC=build,DC=newton,DC=test\n", ""),
        # Not enabled, and the feature named on the Partitions container.
        ("before", "msDS-EnabledFeature on Partitions: ",
         "msDS-EnabledFeature on Partitions: CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,"
         "CN=Windows NT,CN=Services,CN=Configuration,DC=build,DC=newton,DC=test"),
        # Not enabled, but another forest mode than measured.
        ("before", "RequiredForestMode Windows2008R2Forest", "RequiredForestMode Windows2016Forest"),
        # A line missing.
        ("before", "now: EnabledScopes:\n", ""),
    ],
)
def test_a_resumed_stage_3_in_any_other_state_stops_with_no_write(server: Server, phase: str, old: str, new: str) -> None:
    resumed = _stopped_after_recycle(server, "error")
    text = _s3_state(phase)
    assert old in text, old
    result = _call(server, resumed, "3", checkpoint=CP3R,
                   ops={"s3-state": _ok(text.replace(old, new, 1)), "s3-recyclebin": _ok(_fixture("s3-recyclebin.txt"))})
    _stopped(server, result, "3", "readback_failed")
    assert _ops_called(result) == ["s3-state"]


def test_a_failed_s3_state_read_stops_readback_failed(server: Server) -> None:
    resumed = _stopped_after_recycle(server, "error")
    result = _call(server, resumed, "3", ops={"s3-state": {"result": 1, "output": "FAIL: x\n"}}, checkpoint=CP3R)
    _stopped(server, result, "3", "readback_failed")
    assert _ops_called(result) == ["s3-state"]


def test_an_s3_state_read_still_running_at_its_limit_stops_with_no_write(server: Server) -> None:
    resumed = _stopped_after_recycle(server, "error")
    result = _call(server, resumed, "3", checkpoint=CP3R,
                   ops={"s3-state": {"outcome": "running", "result": -1, "output": ""}})
    _stopped(server, result, "3", "readback_failed")
    assert _ops_called(result) == ["s3-state"]


def test_a_resumed_stage_3_whose_state_read_still_runs_is_refused_out_of_order(server: Server) -> None:
    resumed = _stopped_after_recycle(server, "error")
    before = server.journal()
    result = _call(server, resumed, "3", ops={"s3-state": _ok(_s3_state("after"))},
                   checkpoint=CP3R, running=["s3-state"])
    assert (result["answer"]["status"], result["answer"]["code"]) == ("refused", "out_of_order"), result
    assert server.journal() == before


def test_an_unresumed_stage_3_reads_no_state_first(server: Server) -> None:
    the_plan = _plan()
    _seed_before(server, the_plan, "3", CP3)
    result = _call(server, the_plan, "3", ops={"s3-recyclebin": _ok(_fixture("s3-recyclebin.txt"))}, checkpoint=CP3)
    assert result["answer"]["status"] == "done", result
    assert _ops_called(result) == ["s3-recyclebin"]


def test_the_s3_state_read_writes_nothing(server: Server) -> None:
    script = _render(server, _stage_values(server, _plan5()), ["s3-state"])["s3-state"]
    names = {name.lower() for name in _command_names(script)}
    assert "enable-adoptionalfeature" not in names
    assert not [n for n in names if n.split("-")[0] in {"set", "new", "remove", "add", "enable", "disable"}
                and n not in {"new-object"}], names


def test_a_stage_4_dropped_and_recorded_grace_passed_resumes_to_done_with_no_second_schema_update(server: Server) -> None:
    """The stage 4 case: the session dropped while s4-laps ran, and
    the status past EXP and the grace recorded its successful result file
    as grace_passed (no restart).  The resume reads the state, finds the
    after-state, reboots and ends done; Update-LapsADSchema never runs
    again."""
    the_plan = _plan()
    _seed_before(server, the_plan, "4", CP4)
    dropped = _call(server, the_plan, "4", ops={"s4-laps": {"drop": True, "result": 0, "output": ""}}, checkpoint=CP4)
    assert dropped.get("dropped") is True
    stop = _call(server, the_plan, "4", "status", checkpoint=CP4, now=EXP + 900 + 60,
                 results={"s4-laps": _ok(_s4_output())})
    _stopped(server, stop, "4", "grace_passed")
    assert _restarts(stop) == 0
    inputs = copy.deepcopy(PLAN_INPUTS)
    inputs["resume_from"] = plan.digest(the_plan)
    inputs["secrets_from"] = plan.digest(the_plan)
    inputs["start_stage"] = "4"
    resumed = _plan(inputs)
    server.append({"stage": "4", "state": "checkpointed", "digest": plan.digest(resumed), "checkpoint": CP4R})
    result = _call(server, resumed, "4", ops={"s4-state": _ok(_measured("s4-state-after.txt"))}, checkpoint=CP4R)
    assert result["answer"]["status"] == "rebooting", result
    assert _ops_called(result) == ["s4-state"]
    assert "Update-LapsADSchema" not in _scripts_run(result)
    done = _call(server, resumed, "4", "status", checkpoint=CP4R, boot="2026-11-13T15:00:05.5000000Z",
                 ops={"s4-groups": _ok(_fixture("s4-groups.txt"))},
                 groups=[l for l in _fixture("s4-s4u-groups-after-boot.txt").splitlines() if l])
    assert done["answer"]["status"] == "done", done
    assert "Update-LapsADSchema" not in _scripts_run(done)


@pytest.mark.parametrize("op", ["s5-structure"])
def test_the_domain_head_is_named_by_its_dn_never_by_the_bare_domain_sid(server: Server, op: str) -> None:
    # Measured on Server 2025 (lab run 6, 2026-11-24): Get-ADObject/Set-ADObject -Identity <domain SID> answers
    # ADIdentityNotFoundException under the domain head, so stage 5 stopped op_failed. A SID names an account or a
    # group ($sid + '-<rid>'); the domain head is named by its DN ($root).
    script = _render(server, _stage_values(server, _plan5()), [op])[op]
    bad = [line for line in script.splitlines() if re.search(r"-Identity \$sid(?!\s*\+)", line)]
    assert bad == [], bad
