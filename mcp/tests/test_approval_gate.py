"""The lab approval carve-out is off unless the lab turns it on.

The carve-out lets a device that is both ``lab = true`` and
``profile = "lab"`` skip newton-approve for a plan nothing else flags.
It is off by default.  It is on only when the server runs from a source
checkout (the lab's dev tree) AND ``NEWTON_LAB_APPROVAL_CARVEOUT=1`` is
set.  An installed (non-editable) build refuses it whatever the
environment says; ``test_installed_layout.py`` proves that against a
real installed venv.  A plan the carve-out frees says
"approval: lab carve-out" in its result.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from newton_mcp import approval_gate

LAB = SimpleNamespace(lab=True, profile="lab")
ENV = "NEWTON_LAB_APPROVAL_CARVEOUT"


def _requires(device) -> bool:
    return approval_gate.plan_requires_approval(
        device, router_requires=False, policy_requires=False
    )


def test_the_carve_out_is_off_without_the_lab_switch(monkeypatch):
    monkeypatch.delenv(ENV, raising=False)
    assert approval_gate.lab_carve_out_applies(LAB) is False
    assert _requires(LAB) is True


@pytest.mark.parametrize("value", ["", "0", "true", "yes", " 1", "1 ", "2"])
def test_only_the_exact_value_1_turns_the_carve_out_on(monkeypatch, value):
    monkeypatch.setenv(ENV, value)
    assert approval_gate.lab_carve_out_applies(LAB) is False
    assert _requires(LAB) is True


def test_the_lab_switch_turns_the_carve_out_on_in_a_source_checkout(monkeypatch):
    monkeypatch.setenv(ENV, "1")
    assert approval_gate.running_from_source_checkout() is True
    assert approval_gate.lab_carve_out_applies(LAB) is True
    assert _requires(LAB) is False


def test_an_installed_build_refuses_the_carve_out_even_with_the_lab_switch(
    monkeypatch,
):
    monkeypatch.setenv(ENV, "1")
    monkeypatch.setattr(approval_gate, "running_from_source_checkout", lambda: False)
    assert approval_gate.lab_carve_out_applies(LAB) is False
    assert _requires(LAB) is True


@pytest.mark.parametrize(
    "device",
    [
        SimpleNamespace(lab=False, profile="lab"),
        SimpleNamespace(lab=True, profile="prod"),
        SimpleNamespace(lab="true", profile="lab"),
        SimpleNamespace(profile="lab"),
    ],
)
def test_the_lab_switch_never_frees_a_device_outside_the_carve_out(monkeypatch, device):
    monkeypatch.setenv(ENV, "1")
    assert approval_gate.lab_carve_out_applies(device) is False
    assert _requires(device) is True


def test_the_source_checkout_check_wants_newtons_own_pyproject(tmp_path):
    pkg = tmp_path / "newton_mcp"
    pkg.mkdir()
    module = pkg / "approval_gate.py"
    module.write_text("", encoding="utf-8")
    assert approval_gate.running_from_source_checkout(module) is False
    # a stray pyproject.toml next to the package (site-packages can hold
    # one from a badly packaged wheel) is not Newton's source tree
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "something-else"\n', encoding="utf-8"
    )
    assert approval_gate.running_from_source_checkout(module) is False
    (tmp_path / "pyproject.toml").write_text("not toml [", encoding="utf-8")
    assert approval_gate.running_from_source_checkout(module) is False
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "newton-mcp"\n', encoding="utf-8"
    )
    assert approval_gate.running_from_source_checkout(module) is True
