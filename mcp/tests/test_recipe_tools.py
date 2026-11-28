"""The two recipe tools: ``newton_list_recipes`` and ``newton_plan_recipe``.

``newton_plan_recipe`` builds the batch and the probes from a reviewed
recipe file and hands them to the same ``plan()`` every other change uses,
so the seal, the touched checks on the RESOLVED lines, the network rules,
the approval gate, the hold and the undo all apply unchanged.  A package
the router lacks refuses the plan with the ``apk add`` line for the owner
(Newton installs nothing), and a UCI path the recipe needs but the router
does not hold refuses the plan with the owner's own command.

The recipe file is a fixture here: no real recipe file is in the tree yet.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from exhelp import explained, record_fields

import newton_mcp.approve as approve
import newton_mcp.server as server
from newton_mcp import explanation
from newton_mcp import recipes as recipes_mod
from newton_mcp.plan import compute_plan_hash
from test_recipe_files import RECIPE_IDS
from test_recipe_files import VALUES as SHIPPED_VALUES


SID = "fd595e20f2cd6c2b928fe3156f82d5db"
BASE_HASH = "8" * 64
ROUTER_DIGEST = "3" * 64
PROBES_SHA = "1" * 64

#: The manifest of the repo: the recipes it ships sit next to it.
REPO_MANIFEST = (
    Path(__file__).resolve().parents[2] / "profiles" / "openwrt" / "manifest.toml"
)

RECIPE_ID = "dhcp-reservation"

RECIPE = '''id = "dhcp-reservation"
title = "DHCP reservation"
summary = "One device always gets the same IPv4 address."
platform = "openwrt"
version = 1
risk = "LOW: adds one host entry; nothing else changes."
packages = ["dnsmasq"]
requires_set = ["dhcp.{name}.mac"]
owner_command = "uci set dhcp.{name}.mac='00:00:00:00:00:00'"

[params.name]
kind = "name"
help = "UCI section name for the reservation"

[params.mac]
kind = "mac"
help = "the device's MAC address"

[[steps]]
kind = "uci"
text = """
set dhcp.{name}=host
set dhcp.{name}.mac='{mac}'
"""

[[checks]]
probe = ["uci-equals", "dhcp.{name}.mac", "{mac}"]
'''

VALUES = {"name": "laptop", "mac": "aa:bb:cc:dd:ee:ff"}
BATCH = "set dhcp.laptop=host\nset dhcp.laptop.mac='aa:bb:cc:dd:ee:ff'\n"

#: A recipe with a step that waits for a param: the step is dropped when
#: nobody gives that param.
OPTIONAL_RECIPE = '''id = "optional-step"
title = "Optional step"
summary = "A recipe with a step that waits for a param."
platform = "openwrt"
version = 1
risk = "LOW: adds one line."

[params.name]
kind = "name"
help = "UCI section name"

[params.extra]
kind = "name"
default = ""
help = "the optional name"

[[steps]]
kind = "uci"
text = """
set dhcp.{name}=host
"""

[[steps]]
kind = "uci"
when = "extra"
text = """
set dhcp.{name}.extra='{extra}'
"""
'''


# ---- fixtures --------------------------------------------------------------


def _plan_output(diff="dhcp.laptop='host'"):
    return (
        "BACKUP /tmp/fake.tar.gz (2 config files)\n"
        f"STAGED session={SID}\n"
        f"BASEHASH {BASE_HASH}\n"
        f"PROBES 1 {PROBES_SHA}\n"
        "PROFILE lab\n"
        "SECTION dhcp cfg01 dnsmasq dnsmasq\n"
        "LEASH wan-rule firewall.wan_rule\n"
        "APPROVAL not-required\n"
        f"PLANDIGEST {ROUTER_DIGEST}\n"
        f"----- diff -----\n"
        f"{diff}\n"
        f"----------------\n"
    )


def _fake_script(calls, *, output, uci_text_holder, probes_holder):
    """Fake ``run_script``: records the call and keeps the staged files."""

    def fake_run(self, device, *args, **kwargs):
        for arg in args:
            if isinstance(arg, str) and arg.startswith("/tmp/newton-uci-"):
                uci_text_holder["text"] = Path(arg).read_text(encoding="utf-8")
            if isinstance(arg, str) and arg.startswith("/tmp/newton-probes-"):
                probes_holder["bytes"] = Path(arg).read_bytes()
        modes = tuple(
            stat.S_IMODE(os.stat(part).st_mode)
            for part in args
            if isinstance(part, str) and part.startswith("/tmp/newton-")
        )
        calls.append((args, kwargs, modes))
        return subprocess.CompletedProcess(list(args), 0, output, "")

    return fake_run


def _read_result(text: str, exit_code: int = 0) -> dict:
    return {
        "exit_code": exit_code,
        "stdout": {"kind": "untrusted-device-data", "source": "quasar:read", "text": text},
        "stderr": {"kind": "untrusted-device-data", "source": "quasar:read", "text": ""},
        "truncated": False,
    }


def _fake_read(installed=("dnsmasq",), set_paths=("dhcp.laptop.mac",), calls=None):
    """A read lane that answers the two commands the recipe path uses."""

    def fake_read(self, device_name, command):
        if calls is not None:
            calls.append(command)
        if command.startswith("apk list -I "):
            package = command[len("apk list -I "):]
            if package in installed:
                return _read_result(f"{package}-1.0-r1 x86_64 {{origin}} (GPL) [installed]\n")
            return _read_result("")
        if command.startswith("uci get "):
            path = command[len("uci get "):]
            if path in set_paths:
                return _read_result("aa:bb:cc:dd:ee:ff\n")
            return _read_result("", exit_code=1)
        return _read_result("", exit_code=1)

    return fake_read


@pytest.fixture
def configured(tmp_path, monkeypatch):
    """An inventory with one installed router and one no-install router."""
    # A synthetic pin (the sha256 of a fixed string): the shape matters,
    # the value does not, and no lab certificate belongs in git.
    pin = base64.b64encode(
        hashlib.sha256(b"newton-noinstall-test-pin").digest()
    ).decode()
    pw_file = tmp_path / "rpcd-password"
    pw_file.write_text("synthetic-password\n", encoding="utf-8")
    pw_file.chmod(0o600)
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.quasar]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n'
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "192.0.2.2"\nuser = "root"\n'
        'access = "no-install"\n'
        f'rpcd_password_file = "{pw_file}"\n'
        f'https_spki = "{pin}"\n'
    )
    inventory.chmod(0o644)
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    return tmp_path


@pytest.fixture
def recipe_file(configured, monkeypatch):
    """The recipe fixture, in a recipes dir the manifest points at."""
    profiles = configured / "profiles" / "openwrt"
    recipes = profiles / "recipes"
    recipes.mkdir(parents=True, exist_ok=True)
    manifest = profiles / "manifest.toml"
    manifest.write_text("", encoding="utf-8")
    monkeypatch.setenv("NEWTON_MANIFEST", str(manifest))
    (recipes / f"{RECIPE_ID}.toml").write_text(RECIPE, encoding="utf-8")
    return recipes


@pytest.fixture
def shipped_recipes(configured, monkeypatch):
    """The recipes the repo ships, in the inventory's own router."""
    monkeypatch.setenv("NEWTON_MANIFEST", str(REPO_MANIFEST))
    return configured


# ---- the tool surface ------------------------------------------------------


def test_both_recipe_tools_are_in_the_tool_names() -> None:
    assert "newton_list_recipes" in server.TOOL_NAMES
    assert "newton_plan_recipe" in server.TOOL_NAMES


def test_list_recipes_names_the_recipe_and_its_params(recipe_file) -> None:
    """The listing shows the owner what the recipe needs: its params, the
    packages it wants, its risk and the rule it suggests."""
    result = server.newton_list_recipes("quasar")

    assert result["result"] == "ok"
    entries = {entry["id"]: entry for entry in result["recipes"]}
    assert RECIPE_ID in entries, result
    entry = entries[RECIPE_ID]
    assert entry["title"] == "DHCP reservation"
    assert entry["version"] == 1
    assert entry["risk"].startswith("LOW:")
    assert entry["packages"] == ["dnsmasq"]
    assert entry["params"]["name"] == {
        "kind": "name",
        "help": "UCI section name for the reservation",
        "required": True,
    }
    assert entry["params"]["mac"]["kind"] == "mac"


def test_the_listing_answers_for_a_no_install_router(recipe_file) -> None:
    """The listing reads the host's own files, so it answers for a
    router Newton cannot install on too."""
    result = server.newton_list_recipes("lab-r1")

    assert result["result"] == "ok"
    assert [entry["id"] for entry in result["recipes"]] == [RECIPE_ID]


# ---- the listing shows the steps --------------------------------------------


def test_the_listing_carries_the_steps_of_the_recipe(recipe_file) -> None:
    """The listing shows the steps of the recipe: the file's own text, with
    the placeholders left in, and the param a step waits for.

    The agent has to explain every change line of the plan, and the plan
    is built from these steps: without their lines it cannot know what it
    has to explain.
    """
    result = server.newton_list_recipes("quasar")

    entry = {entry["id"]: entry for entry in result["recipes"]}[RECIPE_ID]
    steps = entry["steps"]
    assert len(steps) == 1, steps
    assert steps[0]["when"] == "", steps
    text = steps[0]["text"]
    assert "set dhcp.{name}=host" in text, text
    assert "set dhcp.{name}.mac='{mac}'" in text, text
    # the file's own text: no value is ever in it
    assert "laptop" not in text, text
    assert "aa:bb:cc:dd:ee:ff" not in text, text


def test_the_listing_names_the_param_a_step_waits_for(recipe_file) -> None:
    """A step with a ``when`` names the param it waits for: the listing
    says which, so the agent knows the step may be dropped."""
    (recipe_file / "optional-step.toml").write_text(
        OPTIONAL_RECIPE, encoding="utf-8"
    )

    result = server.newton_list_recipes("quasar")

    entry = {entry["id"]: entry for entry in result["recipes"]}["optional-step"]
    assert [step["when"] for step in entry["steps"]] == ["", "extra"], entry
    assert "set dhcp.{name}.extra='{extra}'" in entry["steps"][1]["text"], entry


@pytest.mark.parametrize("recipe_id", RECIPE_IDS)
def test_the_listed_steps_count_the_lines_of_the_resolved_batch(
    shipped_recipes, recipe_id: str
) -> None:
    """The listed steps are the plan's lines: the change lines of the
    steps that are used are the change lines of the resolved batch.

    The plan needs one ``explanation.steps`` entry per change line, so
    the agent must be able to count them from the listing alone.
    """
    result = server.newton_list_recipes("quasar")

    entry = {entry["id"]: entry for entry in result["recipes"]}[recipe_id]
    recipe = recipes_mod.load_recipe(recipe_id)
    resolved = recipes_mod.resolve(recipe, SHIPPED_VALUES[recipe_id])

    effective = {
        name: spec.get("default", "")
        for name, spec in recipe["params"].items()
    }
    effective.update(SHIPPED_VALUES[recipe_id])

    used = [
        step for step in entry["steps"]
        if step["when"] == "" or effective.get(step["when"], "") != ""
    ]
    listed_lines = sum(explanation.change_lines(step["text"]) for step in used)

    assert listed_lines == explanation.change_lines(resolved["uci_batch"]), (
        recipe_id, listed_lines, resolved["uci_batch"]
    )


# ---- plan_recipe reaches plan() --------------------------------------------


def test_plan_recipe_reaches_plan_with_the_resolved_batch_and_probes(
    recipe_file, monkeypatch
) -> None:
    """The batch and the probes that reach ``plan()`` are the resolved
    ones: no placeholder is left in them."""
    calls = []
    monkeypatch.setattr(server.NewtonService, "read", _fake_read(calls=calls))
    monkeypatch.setattr(
        server.NewtonService,
        "plan",
        lambda self, device_name, uci_batch, timeout_s=None, probes=None,
        manifest_checks=None, **kwargs: calls.append(
            ("plan", device_name, uci_batch, probes, kwargs)
        ) or {"session_id": SID, "plan_hash": "0" * 64},
    )

    result = server.newton_plan_recipe(
        "quasar", RECIPE_ID, values=VALUES, **explained(BATCH)
    )

    planned = [call for call in calls if isinstance(call, tuple) and call[0] == "plan"]
    assert len(planned) == 1, calls
    _, device_name, uci_batch, probes, kwargs = planned[0]
    assert device_name == "quasar"
    assert uci_batch == BATCH
    assert probes == [["uci-equals", "dhcp.laptop.mac", "aa:bb:cc:dd:ee:ff"]]
    assert kwargs["_tool"] == "newton_plan_recipe"
    assert kwargs["_recipe"] == {
        "id": RECIPE_ID,
        "version": 1,
        "title": "DHCP reservation",
        "risk": "LOW: adds one host entry; nothing else changes.",
        # the hash of the file the recipe was read from
        "sha256": hashlib.sha256(
            (recipe_file / f"{RECIPE_ID}.toml").read_bytes()
        ).hexdigest(),
    }
    assert result["recipe"] == RECIPE_ID
    assert result["recipe_version"] == 1


def test_plan_recipe_checks_the_packages_and_the_paths_before_planning(
    recipe_file, monkeypatch
) -> None:
    """The two reads of the precondition step happen, and nothing else."""
    reads: list[str] = []
    monkeypatch.setattr(server.NewtonService, "read", _fake_read(calls=reads))
    monkeypatch.setattr(
        server.NewtonService,
        "plan",
        lambda self, *a, **k: {"session_id": SID, "plan_hash": "0" * 64},
    )

    server.newton_plan_recipe("quasar", RECIPE_ID, values=VALUES, **explained(BATCH))

    assert reads == ["apk list -I dnsmasq", "uci get dhcp.laptop.mac"]


def test_a_missing_package_refuses_with_the_apk_add_line_and_stages_nothing(
    recipe_file, monkeypatch
) -> None:
    """Newton installs nothing: a package the router lacks refuses the
    plan with the ``apk add`` line for the owner, and nothing is staged."""
    staged = []

    def fail_if_staged(self, device, *args, **kwargs):
        staged.append(args)
        raise AssertionError("nothing may be staged when a package is missing")

    monkeypatch.setattr(server.NewtonService, "read", _fake_read(installed=()))
    monkeypatch.setattr(server.NewtonService, "run_script", fail_if_staged)

    result = server.newton_plan_recipe(
        "quasar", RECIPE_ID, values=VALUES, **explained(BATCH)
    )

    assert result["error"] == (
        f"recipe {RECIPE_ID}: the router needs package(s) dnsmasq; "
        "the owner runs: apk add dnsmasq; nothing planned"
    ), result
    assert staged == []


def test_an_unset_requires_set_path_refuses_with_the_owner_command(
    recipe_file, monkeypatch
) -> None:
    """A UCI path the recipe needs and the router does not hold refuses
    the plan with the owner's own command."""

    def fail_if_staged(self, device, *args, **kwargs):
        raise AssertionError("nothing may be staged when a path is unset")

    monkeypatch.setattr(
        server.NewtonService, "read", _fake_read(set_paths=())
    )
    monkeypatch.setattr(server.NewtonService, "run_script", fail_if_staged)

    result = server.newton_plan_recipe(
        "quasar", RECIPE_ID, values=VALUES, **explained(BATCH)
    )

    assert result["error"] == (
        f"recipe {RECIPE_ID}: dhcp.laptop.mac is not set; the owner runs on "
        "the router: uci set dhcp.laptop.mac='00:00:00:00:00:00'; nothing planned"
    ), result


def test_a_no_install_device_gets_preconditions_unchecked(recipe_file, monkeypatch) -> None:
    """A router Newton cannot install on gets the plan without the
    precondition reads, and the result says what was not checked."""
    from newton_mcp import noinstall_flow

    calls = []

    def fail_if_read(self, device_name, command):
        raise AssertionError("a no-install device is not read for the preconditions")

    def fake_noinstall_plan(svc, device_name, uci_batch, window_s=180, **kwargs):
        calls.append((device_name, uci_batch, kwargs))
        return {"session_id": SID, "plan_hash": "0" * 64, "mode": "auto"}

    monkeypatch.setattr(server.NewtonService, "read", fail_if_read)
    monkeypatch.setattr(noinstall_flow, "plan", fake_noinstall_plan)

    result = server.newton_plan_recipe(
        "lab-r1", RECIPE_ID, values=VALUES, **explained(BATCH)
    )

    assert result["preconditions_unchecked"] == ["dnsmasq", "dhcp.laptop.mac"]
    assert calls[0][0] == "lab-r1"
    assert calls[0][1] == BATCH
    # the no-install flow takes no probes and no _recipe
    assert "probes" not in calls[0][2]
    assert "_recipe" not in calls[0][2]


# ---- the stored record and the hash ----------------------------------------


def test_the_stored_record_carries_the_recipe_and_the_hash_covers_it(
    recipe_file, configured, monkeypatch
) -> None:
    """The record says which recipe was planned, and the plan hash binds
    it: an edited risk does not verify, so the apply refuses."""
    calls, uci_text, probes_holder = [], {}, {}
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        _fake_script(
            calls,
            output=_plan_output(),
            uci_text_holder=uci_text,
            probes_holder=probes_holder,
        ),
    )
    monkeypatch.setattr(server.NewtonService, "read", _fake_read())

    server.newton_plan_recipe("quasar", RECIPE_ID, values=VALUES, **explained(BATCH))

    record_path = configured / "state" / "plans" / f"{SID}.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    assert record["recipe"]["id"] == RECIPE_ID
    assert record["recipe"]["version"] == 1
    assert record["recipe"]["title"] == "DHCP reservation"
    assert record["recipe"]["risk"].startswith("LOW:")
    assert len(record["recipe"]["sha256"]) == 64

    # an edited risk does not verify any more
    record["recipe"]["risk"] = "HIGH: it takes the router down."
    record_path.write_text(json.dumps(record), encoding="utf-8")

    result = server.newton_apply_change("quasar", SID)
    assert result["error"] == "plan record was modified or is invalid; plan again"


def test_a_record_without_a_recipe_hashes_exactly_as_before() -> None:
    """A record that carries no recipe hashes as it always did: the
    canonical payload only grows when the record has the key."""
    record = {
        "device": "quasar",
        "host": "192.0.2.1",
        "session_id": "0123456789abcdef0123456789abcdef",
        "uci_batch": "set wireless.radio0.key='never-display-this'",
        "diff": "wireless.radio0.key='never-display-this'",
        "probes": [["log-has", "present", "made-up-marker"]],
        "timeout_s": 120,
        "base_hash": "a" * 64,
        "requires_approval": True,
        "router_digest": "d" * 64,
        **record_fields("set wireless.radio0.key='never-display-this'"),
        "router_profile": "prod",
        "router_leash": ["mgmt-if"],
        "router_sections": ["wireless.radio0"],
        "router_requires_approval": True,
        "staged_check": {
            "fw4": "skipped-untouched",
            "reason": "",
            "not_checked": ["firewall"],
        },
        "reasons": ["wireless configuration changes require approval"],
        "created_at": "2026-10-07T12:00:00+00:00",
        "staged_at": "2026-10-07T12:00:00+00:00",
    }
    assert compute_plan_hash(record) == (
        "98b13855f43cd0934f6ba8a42ed932f0ec71db3f1ca5b6bd48c25812455e3169"
    )


# ---- the approval text -----------------------------------------------------


def _approval_record(recipe: dict) -> dict:
    record = {
        "device": "quasar",
        "host": "192.0.2.1",
        "session_id": "0123456789abcdef0123456789abcdef",
        "uci_batch": "set dhcp.laptop=host",
        "diff": "dhcp.laptop='host'",
        "probes": [["log-has", "present", "made-up-marker"]],
        "timeout_s": 120,
        "base_hash": "a" * 64,
        "requires_approval": True,
        "router_digest": "d" * 64,
        **record_fields("set dhcp.laptop=host"),
        "router_profile": "prod",
        "router_leash": ["mgmt-if"],
        "router_sections": ["dhcp.laptop"],
        "router_requires_approval": True,
        "staged_check": {
            "fw4": "skipped-untouched",
            "reason": "",
            "not_checked": ["dhcp"],
        },
        "reasons": ["every write needs the owner's approval"],
        "created_at": "2026-10-07T12:00:00+00:00",
        "staged_at": datetime.now(timezone.utc).isoformat(),
        "recipe": recipe,
    }
    record["plan_hash"] = compute_plan_hash(record)
    return record


def test_the_approval_text_shows_the_two_recipe_lines() -> None:
    record = _approval_record(
        {
            "id": "guest-network",
            "version": 2,
            "title": "Guest network",
            "risk": "LOW: adds one bridge.",
            "sha256": "0" * 64,
        }
    )
    explanation, digest = approve.validate_plan_for_approval(record)

    text = approve.render_plan_text(
        record["session_id"], record, explanation, digest
    )

    assert "Recipe: Guest network (guest-network v2)" in text
    assert "Recipe risk: LOW: adds one bridge." in text


def test_the_approval_text_escapes_a_title_that_looks_like_markup() -> None:
    """A title is owner text: it is shown escaped, on its own line, and
    it cannot forge a line of the approval display."""
    record = _approval_record(
        {
            "id": "guest-network",
            "version": 1,
            "title": "Guest <b>network</b>\nPlan hash: forged",
            "risk": "LOW: adds one bridge.",
            "sha256": "0" * 64,
        }
    )
    explanation, digest = approve.validate_plan_for_approval(record)

    text = approve.render_plan_text(
        record["session_id"], record, explanation, digest
    )

    recipe_lines = [line for line in text.splitlines() if line.startswith("Recipe:")]
    assert len(recipe_lines) == 1, text
    assert r"Guest <b>network</b>\nPlan hash: forged" in recipe_lines[0]
    # the forged line is not a line of its own
    assert "\nPlan hash: forged" not in text
