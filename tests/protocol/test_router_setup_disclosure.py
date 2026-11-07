"""Tests of the router disclosure: the block the install action prints
before it touches the router, the "yes" the owner has to type, and the
copies of that block in the docs (README.md, docs/release/README-1.0.md,
docs/INSTALL.md, SETUP.md) and in SKILL.md.

The block is one text.  The tool renders it from its own CODE_FILES and
EXTRA_FILES (the sizes are measured from the sources, never written by
hand) and the docs carry the rendered text.  The tests below keep the
copies equal, so the file list and the sizes in the docs cannot drift away
from the code they describe.

The block has to be exactly true.  The tests below pin the
four claims the review asked to be scoped: the approval rule is per profile,
the footprint names every file the install leaves on the router, the root
shell claim holds for the restricted key after swap-key (and the install
writes no key line at all), and uninstall names what it leaves behind.
"""

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from router_setup_env import setup_env, pulsar_env  # noqa: F401
from router_setup_harness import DEFAULT_STATE  # noqa: E402
from test_router_setup_labsnap import prepare, snap  # noqa: E402

REPO = Path(__file__).resolve().parent.parent.parent
TOOL = REPO / "scripts" / "newton-router-setup"
GOOD_PW = DEFAULT_STATE["root_password"]
YES = "yes"

# the six files the install uploads: the source path under the repo and the
# path on the router (CODE_FILES and EXTRA_FILES of the tool)
UPLOADED = (
	("device/openwrt/newton-router/newton-router",
	 "/usr/libexec/newton/newton-router"),
	("scripts/owrt-safe-apply.sh", "/usr/libexec/newton/newton-safe-apply"),
	("device/openwrt/newton-guard/newton-guard", "/usr/libexec/newton-guard"),
	("device/openwrt/newton-guard/newton-guard.init",
	 "/etc/init.d/newton-guard"),
	("scripts/newton-wan-health.sh", "/usr/libexec/newton/newton-wan-health"),
	("scripts/newton-wan-health.init", "/etc/init.d/newton-wan-health"),
)

# the docs that carry the block, and the skill that says it in its own words
DOCS = ("README.md", "docs/release/README-1.0.md", "docs/INSTALL.md",
        "SETUP.md")
SKILL = "SKILL.md"


def doc_path(name):
	"""The path of a doc.  Without docs/release/README-1.0.md,
	README.md is that file, renamed."""
	path = REPO / name
	if name == "docs/release/README-1.0.md" and not path.exists():
		return REPO / "README.md"
	return path


def seed_known_hosts(env):
	"""The router's host key in the device known_hosts file, as a previous
	check run would have left it."""
	env.known_hosts.write_text("10.1.2.3 %s\n" % env.router.state()["host_key"])


def human_size(nbytes):
	"""The plain size the tool prints: the exact byte count below 1024,
	else the size in KB rounded to the nearest whole number."""
	if nbytes < 1024:
		return "%d B" % nbytes
	return "%d KB" % ((nbytes + 512) // 1024)


def render_block(root):
	"""The block the tool prints, rendered with the sources under root."""
	proc = subprocess.run(
		["bash", "-c", 'source "$1"; router_disclosure_block "$2"',
		 "bash", str(TOOL), str(root)],
		capture_output=True, text=True, timeout=120)
	assert proc.returncode == 0, proc.stderr
	return proc.stdout


def block_paths(block):
	"""The router paths the block's file list names."""
	return [line.split()[0] for line in block.splitlines()
	        if line.startswith("  /")]


def block_line(block, path):
	"""The block's line about one router path."""
	for line in block.splitlines():
		if line.startswith("  %s" % path):
			return line
	raise AssertionError("no line about %s in:\n%s" % (path, block))


def doc_has_block(text, block):
	"""True when the text carries the block: the same lines in the same
	order, maybe indented (a fenced block inside a list item)."""
	doc_lines = [line.strip() for line in text.splitlines()]
	block_lines = [line.strip() for line in block.splitlines()]
	for index in range(len(doc_lines) - len(block_lines) + 1):
		if doc_lines[index:index + len(block_lines)] == block_lines:
			return True
	return False


def flat(text):
	"""The text with every run of whitespace collapsed to one space: the
	prose of the block is checked as words, not as a line wrapping."""
	return " ".join(text.split())


def router_leash_codes():
	"""The distinct leash codes the router program can fire, without the
	prod-only profile-prod (it fires on a prod router only, so a lab
	router never meets it)."""
	import re
	program = (REPO / "device" / "openwrt" / "newton-router"
	           / "newton-router").read_text()
	codes = set(re.findall(r'fire\("([a-z-]+)"', program))
	assert codes, "no leash codes found"
	assert "profile-prod" in codes, "profile-prod is not a leash code?"
	return codes - {"profile-prod"}


def tool_sysupgrade_line_count():
	"""The number of lines the tool puts in /etc/sysupgrade.conf, taken
	from the tool's own array (never a number written by hand)."""
	proc = subprocess.run(
		["bash", "-c", 'source "$1"; printf "%d\\n" "${#SYSUPGRADE_LINES[@]}"',
		 "bash", str(TOOL)],
		capture_output=True, text=True, timeout=120)
	assert proc.returncode == 0, proc.stderr
	return int(proc.stdout.strip())


# -- 1. the install prints the block and asks before it touches the router ----

def test_install_prints_the_block_and_asks_yes(setup_env):
	"""The install says what it puts on the router and asks the owner
	before it starts."""
	env = setup_env
	seed_known_hosts(env)
	r = env.run(env.device, "install", typed=(GOOD_PW, YES))
	assert r.rc == 0, r.out
	assert "What Newton puts on your router" in r.out
	assert 'Type "yes" to install Newton on r1: ' in r.err
	assert r.out.splitlines()[-1] == "DONE install r1"


def test_install_stops_with_nothing_changed_on_another_answer(setup_env):
	"""Anything but "yes" stops the run with the router untouched: not
	one ssh call was made."""
	env = setup_env
	seed_known_hosts(env)
	before = env.router.snapshot()
	r = env.run(env.device, "install", typed=(GOOD_PW, "no"))
	assert r.rc == 1
	assert r.out.splitlines()[-1] == "STOPPED install r1: nothing was changed"
	assert "nothing was changed" in r.out
	assert "NOTE state: router unchanged" in r.out.splitlines()
	assert r.calls == []
	assert env.router.snapshot() == before


def test_install_stops_with_nothing_changed_at_the_end_of_the_input(setup_env):
	"""No answer at all (the end of the typed input) stops the run with
	the router untouched."""
	env = setup_env
	seed_known_hosts(env)
	before = env.router.snapshot()
	r = env.run(env.device, "install", typed=(GOOD_PW,))
	assert r.rc == 1
	assert r.out.splitlines()[-1] == "STOPPED install r1: nothing was changed"
	assert r.calls == []
	assert env.router.snapshot() == before


def test_install_stops_with_nothing_changed_on_a_yes_in_the_wrong_case(setup_env):
	"""The answer is exactly "yes"; "Yes" and "YES" are not it."""
	env = setup_env
	seed_known_hosts(env)
	for answer in ("Yes", "YES", "yes please", ""):
		r = env.run(env.device, "install", typed=(GOOD_PW, answer))
		assert r.rc == 1, answer
		assert "nothing was changed" in r.out, answer
		assert r.calls == [], answer


def test_the_block_is_printed_before_the_first_router_call(setup_env):
	"""The block comes before the first ssh call: the refused run made no
	call at all, so nothing was touched before the answer."""
	env = setup_env
	seed_known_hosts(env)
	r = env.run(env.device, "install", typed=(GOOD_PW, "no"))
	assert "What Newton puts on your router" in r.out
	assert r.calls == []


# -- 2. the block names what the install puts on the router -------------------

def test_the_block_lists_exactly_the_files_the_install_uploads(setup_env):
	"""The block's file list is the install's own list: the four code
	files and the two WAN-health files."""
	env = setup_env
	seed_known_hosts(env)
	r = env.run(env.device, "install", typed=(GOOD_PW, YES))
	assert r.rc == 0, r.out
	block = r.out
	assert block_paths(block) == [path for _, path in UPLOADED]


def test_the_block_measures_the_sizes_of_the_files_it_installs(setup_env):
	"""Every size in the block is the measured size of the file the
	install uploads, and the total is the sum of them."""
	env = setup_env
	seed_known_hosts(env)
	r = env.run(env.device, "install", typed=(GOOD_PW, YES))
	assert r.rc == 0, r.out
	total = 0
	for source, path in UPLOADED:
		size = (env.src / source).stat().st_size
		total += size
		line = block_line(r.out, path)
		assert human_size(size) in line, (path, line)
	assert "about %s of shell" % human_size(total) in r.out
	assert "in %d files" % len(UPLOADED) in r.out


def test_the_block_says_no_packages_and_no_compiled_code(setup_env):
	"""The block is honest about what the install does not do."""
	env = setup_env
	seed_known_hosts(env)
	r = env.run(env.device, "install", typed=(GOOD_PW, YES))
	assert r.rc == 0, r.out
	assert "No package is installed and nothing is compiled" in r.out
	assert "shell scripts" in r.out


def test_the_block_names_the_config_files_the_key_and_the_sysupgrade_lines(setup_env):
	"""The block names the rest of the footprint: the config files, the
	WAN-health settings, the two boot links, the one authorized_keys line
	and the sysupgrade.conf lines."""
	env = setup_env
	seed_known_hosts(env)
	r = env.run(env.device, "install", typed=(GOOD_PW, YES))
	assert r.rc == 0, r.out
	assert "/etc/newton" in r.out
	assert "/etc/config/newton_wanhealth" in r.out
	assert "/etc/rc.d/S09newton-guard" in r.out
	assert "/etc/rc.d/S95newton-wan-health" in r.out
	# STOP=10 in the init makes `enable` write a stop link too
	assert "/etc/rc.d/K10newton-wan-health" in r.out
	assert "/etc/dropbear/authorized_keys" in r.out
	assert "/etc/sysupgrade.conf" in r.out


def test_the_block_says_why_and_what_protects_the_owner(setup_env):
	"""The block says why the program is there, what protects the owner
	and what the trade-off is."""
	env = setup_env
	seed_known_hosts(env)
	r = env.run(env.device, "install", typed=(GOOD_PW, YES))
	assert r.rc == 0, r.out
	assert "survive a reboot or a cut link" in r.out
	assert "last good settings" in r.out
	assert "restricted" in r.out
	assert "read" in r.out
	assert "upgrade" in r.out
	assert "uninstall" in r.out


def test_the_block_says_the_approval_rule_is_per_profile(setup_env):
	"""The approval rule is the policy's: every change needs the owner's
	approval on the default prod profile, a lab router applies changes
	without asking except the leash ones, and the leash list is the one
	policy.py and ADR-015 name."""
	env = setup_env
	seed_known_hosts(env)
	r = env.run(env.device, "install", typed=(GOOD_PW, YES))
	assert r.rc == 0, r.out
	text = flat(r.out)
	assert "on the default prod profile every change needs your approval" in text
	assert "a router you set to lab applies changes without asking" in text
	for item in ("SSH (dropbear)", "the web interface", "rpcd",
	             "the management interface or zone", "WAN"):
		assert item in text, item
	# the list is examples, not a promise of every case: the router
	# program fires 23 leash codes, one of which (profile-prod) only
	# fires on a prod router, so a lab router meets 22 of them
	assert "Among them:" in text
	assert "22 rules in all" in text
	# ADR-015 names users and keys among the leash operations; the
	# code fires unknown-package for them (a config no known package
	# owns), so the block has to name them too
	assert "users" in text
	assert "keys" in text
	assert "anything that changes what a WAN zone lets through" not in text
	# the host-side carve-out needs the inventory flag as well
	assert "lab = true" in text


def test_the_leash_count_in_the_block_is_the_router_programs():
	"""The "N rules in all" of the block is the number of distinct leash
	codes the router program can fire, so a new rule cannot leave the
	block behind.  The prod-only profile-prod code is left out: it fires
	on a prod router only, so a lab router never meets it."""
	lab_codes = router_leash_codes()
	block = flat(render_block(REPO))
	assert "%d rules in all" % len(lab_codes) in block, sorted(lab_codes)


def test_the_block_scopes_the_root_shell_claim_to_the_restricted_key(setup_env):
	"""The root shell claim holds for Newton's restricted key and only
	after swap-key or add-key wrote it; the setup tool's own root login
	is the owner's and never the agent's."""
	env = setup_env
	seed_known_hosts(env)
	r = env.run(env.device, "install", typed=(GOOD_PW, YES))
	assert r.rc == 0, r.out
	text = flat(r.out)
	assert "never gets a root shell through Newton's restricted key" in text
	assert "once swap-key or add-key has written it" in text
	assert ("Until you run swap-key, every key already on the router stays as it is"
	        in text)
	assert "logs in as root with your password or your admin key" in text
	assert "the agent never gets that login" in text


def test_the_block_says_what_uninstall_leaves_and_how_to_remove_it(setup_env):
	"""Uninstall names what it leaves on the router and the one line that
	removes it by hand."""
	env = setup_env
	seed_known_hosts(env)
	r = env.run(env.device, "install", typed=(GOOD_PW, YES))
	assert r.rc == 0, r.out
	text = flat(r.out)
	assert "/etc/newton/lkg and /etc/newton/quarantine" in text
	assert "/etc/config/newton_wanhealth" in text
	assert "rm -rf /etc/newton /usr/libexec/newton /etc/config/newton_wanhealth" in text
	# the key backup swap-key leaves is named and in the manual line
	assert ("/etc/config/newton_wanhealth /etc/dropbear/authorized_keys.newton-prev"
	        in text)
	# the run-time leftovers are named one by one: the transaction lock
	# is one of them (an abort keeps the <sid>.health snapshot in it)
	assert ("/tmp/newton and /tmp/owrt-safe-apply.lock are in memory" in text)
	# the WAN-health run-time state does NOT survive the uninstall: the
	# stop removes it, and the block has to say so
	assert ("restore removes the WAN-health run-time state in "
	        "/var/run/newton-wan-health" in text)
	assert "all_down.flag" in text
	# the /etc/sysupgrade.conf file the install created stays behind (the
	# Newton lines go out of it), so the block has to name it too
	assert "the /etc/sysupgrade.conf file" in text
	assert ("delete /etc/sysupgrade.conf once you have checked that none of "
	        "your own lines are left in it") in text
	# swap-key took the plain key out; the backup is the owner's copy of it
	assert "copy the line back first" in text


def test_the_block_says_uninstall_removes_and_restores_every_newton_key():
	text = flat(render_block(REPO))
	assert "EVERY Newton key line" in text
	assert "for every host and label" in text
	assert "including the key the Newton server itself uses" in text
	assert "prints each removed key with its restore command" in text
	assert (
		"after a reinstall, restore each one, on the Newton host that "
		"holds that key, with"
	) in text
	assert (
		"sudo -u newton /usr/local/bin/newton-router-setup <device> "
		"add-key <label> <role>"
	) in text


def test_the_docs_say_where_to_run_the_restore_command():
	"""The restore command says on which host to run it: the block and
	every doc that carries it name the Newton host that holds the key."""
	sentence = (
		"after a reinstall, restore each one, on the Newton host that "
		"holds that key, with"
	)
	assert sentence in flat(render_block(REPO))
	for name in DOCS:
		text = flat(doc_path(name).read_text())
		assert sentence in text, name


def test_the_install_writes_no_key_line(setup_env):
	"""The install writes no authorized_keys line: the key comes with
	swap-key or add-key, so a key that is already on the router stays as
	it is until the swap."""
	env = setup_env
	seed_known_hosts(env)
	before = env.router.authorized_keys()
	r = env.run(env.device, "install", typed=(GOOD_PW, YES))
	assert r.rc == 0, r.out
	assert env.router.authorized_keys() == before


# -- 3. the upgrade asks nothing ---------------------------------------------

def test_upgrade_does_not_ask(setup_env):
	"""The upgrade was agreed when the mode was chosen: it asks nothing
	and prints no block."""
	env = setup_env
	seed_known_hosts(env)
	env.run(env.device, "install", typed=(GOOD_PW, YES))
	r = env.run(env.device, "upgrade", typed=(GOOD_PW,))
	assert r.rc == 0, r.out
	assert "What Newton puts on your router" not in r.out
	assert 'Type "yes"' not in r.err


# -- 4. the lab-snapshot prints the block and asks nothing ---------------------

def test_lab_snapshot_prints_the_block_and_asks_nothing(setup_env):
	"""The lab-snapshot action installs on the lab router, so it prints the
	same block; it asks no question, because it only runs for a lab profile
	and the lab runner drives it with no owner at the terminal."""
	env = setup_env
	prepare(env, env.tmp)
	r = snap(env, "--new-key", "--skip-gates")
	assert r.rc == 0, r.out + r.err
	assert "What Newton puts on your router" in r.out
	assert "/etc/config/newton_wanhealth" in r.out
	assert 'Type "yes"' not in r.err
	assert "nothing was changed" not in r.out


# -- 5. the docs carry the same block ----------------------------------------

def test_the_docs_carry_the_same_block():
	"""README.md, docs/release/README-1.0.md, docs/INSTALL.md and SETUP.md
	carry the block the tool prints, line for line."""
	block = render_block(REPO)
	assert "What Newton puts on your router" in block
	for name in DOCS:
		text = doc_path(name).read_text()
		assert doc_has_block(text, block), name


def test_the_docs_say_the_same_facts_about_the_sizes():
	"""The sizes the docs state are the sizes of the files the install
	uploads, measured from this repo."""
	block = render_block(REPO)
	total = sum((REPO / source).stat().st_size for source, _ in UPLOADED)
	assert "about %s of shell" % human_size(total) in block
	assert block_paths(block) == [path for _, path in UPLOADED]
	for source, path in UPLOADED:
		size = (REPO / source).stat().st_size
		assert human_size(size) in block_line(block, path), path


def test_the_readme_says_where_the_disclosure_is():
	"""The README names the section, near the top, before the install.  The
	1.0 readme calls its install section Get started."""
	text = (REPO / "README.md").read_text()
	heading = "## What Newton puts on your router"
	assert heading in text
	install = "## Quickstart" if "## Quickstart" in text else "## Get started"
	assert text.index(heading) < text.index(install)


def test_the_release_readme_says_where_the_disclosure_is():
	"""The 1.0 readme names the section before the get-started steps."""
	text = doc_path("docs/release/README-1.0.md").read_text()
	heading = "## What Newton puts on your router"
	assert heading in text
	assert text.index(heading) < text.index("## Get started")


def test_the_install_guide_shows_the_block_at_the_router_step():
	"""docs/INSTALL.md shows the block at step 7e, where the router
	install is."""
	text = (REPO / "docs/INSTALL.md").read_text()
	step = text.index("**7e.**")
	assert text.index("What Newton puts on your router") > step
	assert text.index("What Newton puts on your router") < text.index("**7f.**")


def test_the_setup_guide_shows_the_block_at_the_router_step():
	"""SETUP.md shows the block where the router install is."""
	text = (REPO / "SETUP.md").read_text()
	step = text.index("e. Choose the access mode")
	assert text.index("What Newton puts on your router") > step


def test_the_skill_tells_the_owner_the_same_facts():
	"""SKILL.md says the same facts in its own words, before the agent
	suggests the router install."""
	block = render_block(REPO)
	skill = (REPO / SKILL).read_text()
	about = "about %s" % human_size(
		sum((REPO / source).stat().st_size for source, _ in UPLOADED))
	assert about in skill, about
	assert "%d files" % len(UPLOADED) in skill
	assert "no package" in skill.lower()
	assert "shell" in skill.lower()
	assert "guard" in skill.lower()
	assert "restricted" in skill.lower()
	assert "uninstall" in skill.lower()
	# the numbers the skill states come from the tool and the router
	# program, so they cannot drift away from the code
	assert ("%d lines in `/etc/sysupgrade.conf`"
	        % tool_sysupgrade_line_count()) in skill
	assert ("(%d rules" % len(router_leash_codes())) in skill
	# the paragraph comes before the line that tells the agent how the
	# router setup runs (and that names the install action)
	assert (skill.index("What Newton puts on your router")
	        < skill.index("Router setup (`install`"))


# -- 6. the uninstall leaves exactly what the block names --------------------

ROUTER_CONFTEST = (REPO / "device" / "openwrt" / "newton-router" / "tests"
                   / "conftest.py")

# the paths the block says uninstall leaves on the router, and the words
# the block has to use for each of them: the guard's saved copies of the
# settings and the rest of its directory, the empty program directory,
# the WAN-health settings, the copy of the keys from before swap-key, the
# sysupgrade.conf file the install created and the three run-time paths
# (all in memory, gone at the next reboot).
NAMED_LEFTOVERS = (
	("/etc/newton", "/etc/newton"),
	("/usr/libexec/newton", "/usr/libexec/newton"),
	("/etc/config/newton_wanhealth", "/etc/config/newton_wanhealth"),
	("/etc/dropbear/authorized_keys.newton-prev",
	 "/etc/dropbear/authorized_keys.newton-prev"),
	("/etc/sysupgrade.conf", "the /etc/sysupgrade.conf file"),
	("/tmp/newton", "/tmp/newton"),
	("/tmp/owrt-safe-apply.lock", "/tmp/owrt-safe-apply.lock"),
	("/var/run/newton-wan-health", "/var/run/newton-wan-health"),
)

# the trees the router program and the setup tool write in; the device
# harness's own control/, bin/ and proc/ trees are not Newton's
NEWTON_TREES = ("/etc", "/usr", "/tmp", "/var")

# the fixture init script records its start and stop calls in /tmp; the
# real init script (scripts/newton-wan-health.init) writes no such file,
# so these two are the test harness's, not Newton's
FIXTURE_MARKERS = ("/tmp/newton-wan-health.start",
                   "/tmp/newton-wan-health.stop")

# the stage helper the test puts on the fake router: it does what the
# real helper's stage does (write the session id and the live lock) and
# nothing else, so the router program can stage a transaction for real
STAGE_HELPER = """#!/bin/sh
root="$NEWTON_ROUTER_ROOT"
mkdir -p "$root/tmp/owrt-safe-apply.lock"
IFS= read -r sid < "$root/control/next-sid"
printf '%s\\n' "$sid" > "$root/tmp/owrt-safe-apply.lock/sid"
printf '%s\\n' "$sid" >> "$root/control/sessions"
printf '%s\\n' "$sid"
"""


def _load_router_conftest():
	"""Import the device harness's conftest by file path: it builds the
	fake router root the router program runs against."""
	spec = importlib.util.spec_from_file_location(
		"router_conftest_disclosure", ROUTER_CONFTEST)
	mod = importlib.util.module_from_spec(spec)
	assert spec.loader is not None
	spec.loader.exec_module(mod)
	return mod


def _router_paths(root):
	"""Every path under a router root, absolute, with a leading slash."""
	out = set()
	for dirpath, dirnames, filenames in os.walk(root):
		rel = os.path.relpath(dirpath, root)
		prefix = "/" if rel == "." else "/" + rel.replace(os.sep, "/")
		for name in list(dirnames) + list(filenames):
			out.add(prefix + "/" + name)
	return out


def _graft_router_harness(env, tmp_path):
	"""Put the device harness's fake router root inside the fake router
	of the setup tests, so the REAL router program can run against it:
	its tool fakes, its /proc and /control trees and the router's own
	config files."""
	mod = _load_router_conftest()
	dev = mod.Router(tmp_path / "devrouter")
	fs = env.router.root / "fs"
	# the program's fake tools and its /proc and /control trees
	for name in ("bin", "proc", "control"):
		shutil.copytree(dev.root / name, fs / name, symlinks=True)
	# the router's own config files (the program reads them)
	for name in ("system", "network", "firewall", "dhcp", "wireless"):
		shutil.copy(dev.root / "etc" / "config" / name,
		            fs / "etc" / "config" / name)
	dev.root = fs
	return dev


def _stage_and_abort(env, dev):
	"""Stage a transaction with the REAL router program on the fake
	router and abort it, so the router holds what an abort leaves: the
	transaction lock (with the program keeping <sid>.health in it) and
	the program's run-time files under /tmp/newton."""
	helper = dev.root / "usr/libexec/newton/newton-safe-apply"
	helper.write_text(STAGE_HELPER)
	helper.chmod(0o755)
	res = dev.stage(batch=b"set dhcp.cfg01.domain=lan\n")
	assert res.rc == 0, (res.rc, res.out, res.err)
	sid = res.out.strip()
	res = dev.forced("abort %s" % sid, caller="agent-one")
	assert res.rc == 0, (res.rc, res.out, res.err)
	assert res.out.strip() == "aborted %s discarded" % sid, res.out
	return sid


def test_uninstall_leaves_exactly_the_leftovers_the_block_names(setup_env,
                                                                tmp_path):
	"""A staged-then-aborted transaction, then an uninstall: what is left
	on the router is exactly what the block names, nothing more.
	The transaction is a real one: the router program stages it and the
	abort keeps the transaction lock, which the block has to name."""
	env = setup_env
	seed_known_hosts(env)
	fs = env.router.root / "fs"
	dev = _graft_router_harness(env, tmp_path)
	before = _router_paths(fs)
	r = env.run(env.device, "install", typed=(GOOD_PW, YES))
	assert r.rc == 0, r.out
	_stage_and_abort(env, dev)
	# the abort left the transaction lock and the program's run-time files
	assert (fs / "tmp/owrt-safe-apply.lock").is_dir()
	r = env.run(env.device, "uninstall", typed=(GOOD_PW,))
	assert r.rc == 0, r.out + r.err
	after = _router_paths(fs)
	block = flat(render_block(REPO))
	# everything Newton left behind is what the block names
	left = {p for p in after - before
	        if any(p == tree or p.startswith(tree + "/") for tree in NEWTON_TREES)
	        and p not in FIXTURE_MARKERS}
	for path in sorted(left):
		assert any(path == named or path.startswith(named + "/")
		           for named, _ in NAMED_LEFTOVERS), path
	# and the names the block gives for the leftovers are really there
	for named, words in NAMED_LEFTOVERS:
		if not any(path == named or path.startswith(named + "/")
		           for path in left):
			continue
		# the block has to name the leftover in words, not only the test
		assert words in block, words
