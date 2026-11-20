"""The runner checks a VM's Proxmox name before it rolls the VM back.

A mistyped or copied vmid used to roll back whatever VM had that id and a
snapshot of the same name ("baseline" is common).  Every VM device now names
its Proxmox VM (`vm_name`, required), and pve_rollback reads the VM's name
from the API first and refuses, with no rollback, when it differs.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from conftest import LAB_DIR, lab_toml_path
import newton_lab_test as nl


def _cp(stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode,
                                       stdout=stdout, stderr="")


def _lab_text(extra: str = 'vm_name = "lab-r1"\n') -> str:
    return (
        '[pve]\nhost = "pve.test"\nnode = "lab"\n'
        'token_file = "~/.config/pve/token"\npin_file = "~/.config/pve/pin"\n'
        '[ssh]\nproxy = "ssh -W %h:%p root@pve.test"\n'
        'password_file = "~/.config/newton/lab-root.pw"\nkey = "~/.ssh/key"\n'
        '[devices.lab-r1]\nvmid = 9102\nhost = "10.109.0.11"\nuser = "root"\n'
        'snapshot = "baseline"\n' + extra
    )


def test_a_vm_device_without_vm_name_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "lab.toml"
    path.write_text(_lab_text(extra=""))
    with pytest.raises(nl.LabConfigError, match=r"devices\.lab-r1\.vm_name"):
        nl.load_lab(path)


def test_vm_name_is_loaded(tmp_path: Path) -> None:
    path = tmp_path / "lab.toml"
    path.write_text(_lab_text())
    assert nl.load_lab(path).devices["lab-r1"].vm_name == "lab-r1"


def test_every_vm_device_of_the_shipped_lab_files_names_its_vm(
        tmp_path: Path) -> None:
    example = tmp_path / "lab.example.toml"
    example.write_text((LAB_DIR / "lab.example.toml").read_text()
                       .replace("/home/user/", "~/"))
    for path in (Path(lab_toml_path()), example):
        lab = nl.load_lab(path)
        vms = [dev for dev in lab.devices.values() if not dev.is_physical]
        assert vms, path
        for dev in vms:
            assert dev.vm_name, (path, dev.name)


def _lab(tmp_path: Path) -> nl.Lab:
    path = tmp_path / "lab.toml"
    path.write_text(_lab_text())
    return nl.load_lab(path)


def test_rollback_reads_the_vm_name_first_and_rolls_back_on_a_match(
        tmp_path: Path) -> None:
    lab = _lab(tmp_path)
    dev = lab.devices["lab-r1"]
    replies = [_cp(json.dumps({"data": {"name": "lab-r1", "cores": 1}})),
               _cp(json.dumps({"data": "UPID:abc"}))]
    with mock.patch.object(nl, "_run", side_effect=replies) as m:
        assert nl.pve_rollback(lab, dev) == "UPID:abc"
    first, second = (c[0][0] for c in m.call_args_list)
    assert first[first.index("-X") + 1] == "GET"
    assert first[-1].endswith(f"/qemu/{dev.vmid}/config")
    assert second[second.index("-X") + 1] == "POST"
    assert second[-1].endswith(f"/qemu/{dev.vmid}/snapshot/{dev.snapshot}/rollback")


@pytest.mark.parametrize("data", [
    {"name": "someone-elses-vm"},
    {"cores": 1},
    "not a dict",
])
def test_rollback_refuses_a_vm_whose_name_differs(tmp_path: Path, data) -> None:
    lab = _lab(tmp_path)
    dev = lab.devices["lab-r1"]
    with mock.patch.object(nl, "_run",
                           return_value=_cp(json.dumps({"data": data}))) as m:
        with pytest.raises(nl.VmIdentityError) as exc:
            nl.pve_rollback(lab, dev)
    assert "refusing to roll back vmid 9102" in str(exc.value)
    assert "the lab file names lab-r1" in str(exc.value)
    # one GET, no POST: nothing was rolled back
    assert len(m.call_args_list) == 1
    assert "rollback" not in m.call_args_list[0][0][0][-1]


def test_the_run_start_reset_stops_on_a_vm_name_mismatch(
        tmp_path: Path, capsys) -> None:
    lab = _lab(tmp_path)
    with mock.patch.object(nl, "_run",
                           return_value=_cp(json.dumps({"data": {"name": "other"}}))):
        ok = nl._reset_lab_at_run_start(lab, tmp_path / "out" / "r-lab-reset.json")
    assert ok is False
    err = capsys.readouterr().err
    assert "lab-reset lab-r1 reset failed: VmIdentityError" in err
