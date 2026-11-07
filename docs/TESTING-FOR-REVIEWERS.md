# Testing Newton: what to try first

Newton changes routers, so a bug can lock you out. Start with the read-only things, use a router you can reset, and keep a way to reach it that does not go through Newton (a cable to the router, or a serial console).

## 1. No hardware (20 minutes)

1. Install the prerequisites ([README](../README.md)) and clone the release. You need Python 3.11 or newer and `uv`.
2. From the repository root, create the test environment and run the six suites that need no lab:

   ```sh
   cd mcp && uv sync --extra test && cd ..
   mcp/.venv/bin/python -m pytest tests/serial -q
   mcp/.venv/bin/python -m pytest tests/protocol -q
   mcp/.venv/bin/python -m pytest tests/profiles -q
   mcp/.venv/bin/python -m pytest device/openwrt/newton-guard/tests -q
   mcp/.venv/bin/python -m pytest device/openwrt/newton-router/tests -q
   mcp/.venv/bin/python -m pytest mcp/tests -q
   ```

   The first line creates `mcp/.venv`. None of these suites needs a router, a lab file or a network connection (only the first line downloads packages). Run them one after another.
   The protocol suite is the slowest: expect 20 minutes or more. The counts change between releases, so compare
   against your own first run. Report any failure with the suite name and the last 30 lines.
3. Read [docs/design/04-SECURITY-AND-SAFETY-MODEL.md](design/04-SECURITY-AND-SAFETY-MODEL.md), then try to find a path that violates one of its rules.

## What needs a lab

The live lab scenarios (`lab/newton-lab-test.py`, `lab/scenarios/`) run against a Proxmox lab with a virtual OpenWrt router. The runner reads a lab file: `lab/lab.toml` by default, or the file you name with `--lab`. The maintainer's own lab file is not published, so you write yours. The example lab file in `lab/` (`lab/*.example.toml`) is a complete lab file for a physical router.

`lab/tests` (the tests of the lab runner itself) also reads the lab file, so it fails in a clone that has none. Run it once you have a lab file: `mcp/.venv/bin/python -m pytest lab/tests -q`.

You do not need the lab to review the code. The method is in [docs/TESTING-METHOD.md](TESTING-METHOD.md).

The scenario runner resets router snapshots, so run it only against a lab router.

## 2. A real router (read-only first)

Use a router you can reset. Never test on the router your home depends on.

1. Follow [SETUP.md](../SETUP.md). Add the router. Ask your agent: "Check my router and tell me what to fix." Nothing changes.
2. Ask for a small change (a DHCP reservation). Check that you see the plan, that you must approve it yourself, in your client's approval dialog if it has one, otherwise with `newton-approve`, that the result says CONFIRMED, and that a receipt exists.
3. Ask for a change that breaks management access on purpose (on a router you can reach by cable). Check that the router undoes it by itself and that the result says ROLLED BACK.
4. Pull the power in the middle of a change. Check that the router comes back with the old config. Only do this on hardware you can recover. Skip it if you have no cable or serial console.

`newton-approve` is the terminal approval command. Use it when your client has no approval dialog.

## 3. What we most want broken

- Approval without you: any way for the AI, or text coming from a device, to approve its own plan.
- A write that reaches the router without the undo timer armed first.
- A secret (Wi-Fi key, password, token) showing up in anything the AI sees or in a log.
- Text from a router (hostname, SSID, log line) that changes what the AI does.
- A change kept even though a check failed, or a check that says "passed" when it did not run.
- The installer accepting a release it should not.

## 4. How to report

Open an issue (or, for a security problem, follow [SECURITY.md](../SECURITY.md)). Include: Newton version, router model and firmware, what you asked, the NEWTON RESULT line, and the receipt id. Remove addresses and keys.
