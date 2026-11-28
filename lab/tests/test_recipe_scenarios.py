"""The lab runner plans a recipe: a scenario may name a recipe instead of
carrying a batch.

A recipe scenario names the recipe (its id) and the values it takes.  The
runner loads the recipe file with the MCP server's own loader and resolves
it against those values; a value may reference a lab [vars] placeholder,
the way tier_values do.  The resolved batch and the resolved probes are
what the plan uses, so the rules, the client checks and the hold work
unchanged.

The rules of the new scenario kind:

* a recipe scenario carries no batch, no probes and no tier: the recipe
  brings its own, and each clash is refused by the name of the field;
* a recipe the loader refuses is the scenario's error, and nothing is
  staged on the router.

Nothing here touches a router: the plan, the apply and the var cmds are
answered by a fake subprocess.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import newton_lab_test as nl


SID = "0123456789abcdef0123456789abcdef"
BASE_HASH = "b" * 64
PLANDIGEST = "d" * 64

#: A synthetic recipe: one dhcp host section and one probe.
RECIPE = '''\
id = "test-recipe"
title = "Test recipe"
summary = "A synthetic recipe for the lab runner's loader tests."
platform = "openwrt"
version = 1
risk = "LOW: one synthetic dhcp host section, nothing else."

[params.name]
kind = "name"
help = "The UCI section name of the host."

[params.addr]
kind = "ipv4"
help = "The address the host gets."

[[steps]]
kind = "uci"
text = """
set dhcp.{name}=host
set dhcp.{name}.ip='{addr}'
"""

[[checks]]
probe = ["uci-equals", "dhcp.{name}.ip", "{addr}"]
'''

#: The scenario body of a recipe scenario, with the values it takes.
SCENARIO = '''
name = "01-recipe"
description = "a recipe scenario"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
recipe = "test-recipe"
recipe_values = { name = "rc_host", addr = "10.109.0.61" }
'''


def _cp(stdout: str = "", stderr: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(args=[], returncode=returncode,
                                       stdout=stdout, stderr=stderr)


def _plan_output(sid: str = SID) -> str:
    """A staged plan the fake subprocess answers with."""
    return (
        f"BACKUP /tmp/fake.tar.gz (2 config files)\n"
        f"STAGED session={sid}\n"
        f"BASEHASH {BASE_HASH}\n"
        f"PLANDIGEST {PLANDIGEST}\n"
        "APPROVAL not-required\n"
        "----- diff -----\n"
        "----------------\n"
    )


def _apply_output(sid: str = SID) -> str:
    return f"APPLYBASE {BASE_HASH}\nCONFIRMED session={sid}\n"


def _lab(tmp_path: Path, *, with_vars: bool = False) -> tuple[Path, Path]:
    """A self-contained lab.toml + scenarios dir."""
    lab_toml = tmp_path / "lab.toml"
    vars_block = (
        "[vars]\n"
        'lab_ip = { device = "lab-r1", cmd = "echo 10.109.0.61" }\n'
    ) if with_vars else "[vars]\n"
    lab_toml.write_text(
        f"""
[pve]
host = "pve.test"
node = "lab"
token_file = "~/.config/pve/token"
pin_file = "~/.config/pve/pin"

[ssh]
proxy = "ssh -W %h:%p root@pve.test"
password_file = "~/.config/newton/lab-root.pw"
key = "~/.ssh/key"

[devices.lab-r1]
vmid = 9102
vm_name = "lab-r1"
host = "10.109.0.11"
user = "root"
snapshot = "baseline"

{vars_block}
"""
    )
    scen_dir = tmp_path / "scenarios"
    scen_dir.mkdir()
    return lab_toml, scen_dir


def _write_scenario(scen_dir: Path, name: str, body: str) -> Path:
    path = scen_dir / f"{name}.toml"
    path.write_text(body)
    return path


@pytest.fixture
def recipes_dir(tmp_path, monkeypatch):
    """A temp manifest and the temp recipes dir beside it.

    The recipes dir sits next to the manifest, so pointing the manifest at
    a temp file gives the loader a temp recipes dir with one synthetic
    recipe in it.
    """
    manifest = tmp_path / "manifest.toml"
    manifest.write_text("")
    recipes = tmp_path / "recipes"
    recipes.mkdir()
    (recipes / "test-recipe.toml").write_text(RECIPE)
    monkeypatch.setenv("NEWTON_MANIFEST", str(manifest))
    return recipes


def _fake_run(plan_calls: list[tuple[str, object]], var_value: str = "10.109.0.61"):
    """The fake subprocess: the var cmd answers, the plan and the apply
    answer, and every plan call is recorded."""
    def fake_run(args, **_kw):
        if args[0] == "ssh":
            return _cp(stdout=f"{var_value}\n")
        if args[0] == str(nl.OWRT_CHANGE) and args[1] == "plan":
            plan_calls.append(("plan", args[3]))
            return _cp(stdout=_plan_output())
        if args[0] == str(nl.OWRT_CHANGE) and args[1] == "apply":
            return _cp(stdout=_apply_output())
        return _cp()
    return fake_run


# ---------- the loader ----------


def test_a_recipe_scenario_loads(tmp_path, recipes_dir):
    """A scenario that names a recipe loads with the recipe and its values.

    The scenario carries no batch and no probes: the recipe brings both.
    """
    lab_toml, scen_dir = _lab(tmp_path)
    _write_scenario(scen_dir, "01-recipe", SCENARIO)

    scen = nl.load_scenarios(scen_dir)[0]

    assert scen.recipe == "test-recipe"
    assert scen.recipe_values == {"name": "rc_host", "addr": "10.109.0.61"}
    assert scen.batch == ""
    assert scen.probes == []
    assert scen.tier is None


def test_a_scenario_without_a_recipe_is_unchanged(tmp_path):
    """A scenario that names no recipe loads exactly as before."""
    lab_toml, scen_dir = _lab(tmp_path)
    _write_scenario(scen_dir, "01-plain", """
name = "01-plain"
description = "a plain scenario"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
batch = "set foo=bar"
""")

    scen = nl.load_scenarios(scen_dir)[0]

    assert scen.recipe is None
    assert scen.recipe_values is None


def test_the_recipe_values_must_be_a_table_of_strings(tmp_path):
    """A recipe_values that is not a table of strings is refused by the
    load, and the refusal names the field."""
    lab_toml, scen_dir = _lab(tmp_path)
    _write_scenario(scen_dir, "01-bad", """
name = "01-bad"
description = "a bad recipe scenario"
target = "lab-r1"
reset = []
expect = "confirmed"
timeout = 60
recipe = "test-recipe"
recipe_values = { name = 7 }
""")

    with pytest.raises(ValueError) as exc:
        nl.load_scenarios(scen_dir)

    assert "recipe_values" in str(exc.value)


# ---------- the load-time rules ----------


def test_a_recipe_scenario_with_a_batch_is_refused(tmp_path, recipes_dir):
    """A recipe scenario must not carry a batch: the recipe brings its own.

    The refusal names the field that clashes.
    """
    lab_toml, scen_dir = _lab(tmp_path)
    _write_scenario(scen_dir, "01-batch", SCENARIO + '\nbatch = "set foo=bar"\n')

    lab = nl.load_lab(lab_toml)
    scens = nl.load_scenarios(scen_dir)

    errors = nl.validate_scenarios(lab, scens)

    assert any("batch" in error for error in errors), errors


def test_a_recipe_scenario_with_probes_is_refused(tmp_path, recipes_dir):
    """A recipe scenario must not carry probes: the recipe brings its own."""
    lab_toml, scen_dir = _lab(tmp_path)
    _write_scenario(scen_dir, "01-probes", SCENARIO +
                    '\nprobes = [["uci-equals", "dhcp.x.ip", "1"]]\n')

    lab = nl.load_lab(lab_toml)
    scens = nl.load_scenarios(scen_dir)

    errors = nl.validate_scenarios(lab, scens)

    assert any("probes" in error for error in errors), errors


def test_a_recipe_scenario_with_a_tier_is_refused(tmp_path, recipes_dir):
    """A recipe scenario must not carry a tier: the recipe brings its own."""
    lab_toml, scen_dir = _lab(tmp_path)
    _write_scenario(scen_dir, "01-tier", SCENARIO + '\ntier = "standard"\n')

    lab = nl.load_lab(lab_toml)
    scens = nl.load_scenarios(scen_dir)

    errors = nl.validate_scenarios(lab, scens)

    assert any("tier" in error for error in errors), errors


def test_a_recipe_scenario_validates(tmp_path, recipes_dir):
    """A recipe scenario with nothing else is valid: the batch it does not
    carry comes from the recipe."""
    lab_toml, scen_dir = _lab(tmp_path)
    _write_scenario(scen_dir, "01-recipe", SCENARIO)

    lab = nl.load_lab(lab_toml)
    scens = nl.load_scenarios(scen_dir)

    assert nl.validate_scenarios(lab, scens) == []


# ---------- the run ----------


def test_the_recipe_batch_and_probes_reach_the_plan(tmp_path, recipes_dir,
                                                    monkeypatch):
    """The plan gets the recipe's resolved batch and the recipe's own
    probes, exactly as a scenario's own batch and probes would."""
    lab_toml, scen_dir = _lab(tmp_path)
    _write_scenario(scen_dir, "01-recipe", SCENARIO)
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(scen_dir)[0]

    planned: list[str] = []
    sealed: list[object] = []

    def fake_plan_batch(lab, target, batch, *, probes=None, timeout_s=90,
                        lane="password"):
        planned.append(batch)
        sealed.append(probes)
        return 0, _plan_output(), ""

    monkeypatch.setattr(nl, "plan_batch", fake_plan_batch)
    monkeypatch.setattr(nl, "apply_batch",
                        lambda *a, **k: (0, _apply_output(), ""))
    monkeypatch.setattr(nl, "_run", lambda *a, **k: _cp())

    rec = nl.run_scenario(lab, scen)

    assert rec["outcome"] == "confirmed", rec
    assert rec["passed"] is True, rec
    assert planned == [
        "set dhcp.rc_host=host\nset dhcp.rc_host.ip='10.109.0.61'\n"
    ]
    assert sealed == [[["uci-equals", "dhcp.rc_host.ip", "10.109.0.61"]]]
    assert rec["recipe"]["id"] == "test-recipe"


def test_an_unknown_recipe_id_fails_at_run_time_and_stages_nothing(
        tmp_path, recipes_dir, monkeypatch):
    """A recipe id no file carries is the scenario's error, and nothing is
    staged on the router."""
    lab_toml, scen_dir = _lab(tmp_path)
    _write_scenario(scen_dir, "01-bad", SCENARIO.replace(
        'recipe = "test-recipe"', 'recipe = "no-such-recipe"'))
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(scen_dir)[0]

    staged: list[str] = []

    def fake_plan_batch(*_a, **_k):
        staged.append("plan")
        return 0, _plan_output(), ""

    monkeypatch.setattr(nl, "plan_batch", fake_plan_batch)
    monkeypatch.setattr(nl, "_run", lambda *a, **k: _cp())

    rec = nl.run_scenario(lab, scen)

    assert rec["passed"] is False
    assert "no-such-recipe" in (rec.get("error") or ""), rec
    assert staged == []


def test_a_value_the_recipe_refuses_fails_at_run_time(tmp_path, recipes_dir,
                                                      monkeypatch):
    """A value the recipe's own kind refuses is the scenario's error, and
    nothing is staged."""
    lab_toml, scen_dir = _lab(tmp_path)
    _write_scenario(scen_dir, "01-bad-value", SCENARIO.replace(
        'addr = "10.109.0.61"', 'addr = "not-an-address"'))
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(scen_dir)[0]

    staged: list[str] = []

    def fake_plan_batch(*_a, **_k):
        staged.append("plan")
        return 0, _plan_output(), ""

    monkeypatch.setattr(nl, "plan_batch", fake_plan_batch)
    monkeypatch.setattr(nl, "_run", lambda *a, **k: _cp())

    rec = nl.run_scenario(lab, scen)

    assert rec["passed"] is False
    assert "addr" in (rec.get("error") or ""), rec
    assert staged == []


def test_the_recipe_values_resolve_a_var_placeholder(tmp_path, recipes_dir,
                                                      monkeypatch):
    """A recipe value may be a {var}: the lab resolves it through the same
    [vars] machinery tier_values use, and the recipe gets the resolved
    value."""
    lab_toml, scen_dir = _lab(tmp_path, with_vars=True)
    _write_scenario(scen_dir, "01-var", SCENARIO.replace(
        'addr = "10.109.0.61"', 'addr = "{lab_ip}"'))
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(scen_dir)[0]

    planned: list[str] = []

    def fake_plan_batch(lab, target, batch, *, probes=None, timeout_s=90,
                        lane="password"):
        planned.append(batch)
        return 0, _plan_output(), ""

    monkeypatch.setattr(nl, "plan_batch", fake_plan_batch)
    monkeypatch.setattr(nl, "apply_batch",
                        lambda *a, **k: (0, _apply_output(), ""))
    monkeypatch.setattr(nl, "_run", _fake_run([]))

    rec = nl.run_scenario(lab, scen)

    assert rec["outcome"] == "confirmed", rec
    assert planned == [
        "set dhcp.rc_host=host\nset dhcp.rc_host.ip='10.109.0.61'\n"
    ]
    assert rec["recipe"]["values"]["addr"] == "10.109.0.61"


def test_an_unknown_var_in_a_recipe_value_fails_before_the_plan(
        tmp_path, recipes_dir, monkeypatch):
    """A {var} the lab does not know is refused before anything is
    staged."""
    lab_toml, scen_dir = _lab(tmp_path)
    _write_scenario(scen_dir, "01-var", SCENARIO.replace(
        'addr = "10.109.0.61"', 'addr = "{no_such_var}"'))
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(scen_dir)[0]

    staged: list[str] = []

    def fake_plan_batch(*_a, **_k):
        staged.append("plan")
        return 0, _plan_output(), ""

    monkeypatch.setattr(nl, "plan_batch", fake_plan_batch)
    monkeypatch.setattr(nl, "_run", lambda *a, **k: _cp())

    rec = nl.run_scenario(lab, scen)

    assert rec["passed"] is False
    assert "no_such_var" in (rec.get("error") or ""), rec
    assert staged == []


# ---------- the shipped scenarios ----------


def test_the_recipe_scenarios_of_the_repo_load_and_validate():
    """The eight recipe scenarios of lab/scenarios/recipes/ load and are
    valid against the lab file."""
    from conftest import lab_toml_path

    lab_dir = Path(__file__).resolve().parent.parent
    scen_dir = lab_dir / "scenarios" / "recipes"
    lab = nl.load_lab(lab_toml_path())

    scens = nl.load_scenarios(scen_dir)

    assert [scen.name for scen in scens] == [
        "rc-01-guest-network",
        "rc-02-dhcp-reservation",
        "rc-03-port-forward",
        "rc-04-dns-host",
        "rc-05-dns-upstream",
        "rc-06-wireguard",
        "rc-07-bufferbloat",
        "rc-08-dns-upstream-fresh",
    ]
    assert nl.validate_scenarios(lab, scens) == []
    for scen in scens:
        assert scen.recipe, scen.name
        assert scen.batch == "", scen.name
        assert scen.probes == [], scen.name
        assert scen.expect == "confirmed", scen.name
        assert scen.target == "lab-r1", scen.name
        assert scen.reset == ["lab-r1"], scen.name
