import io
import os
from pathlib import Path
import pwd
import pty
import re
import select
import shlex
import shutil
import socket
import subprocess
import tarfile
import zlib

import pytest


ROOT = Path(__file__).resolve().parents[2]
INSTALL = ROOT / "scripts" / "newton-install"
DOCTOR = ROOT / "scripts" / "newton-doctor"
BOOTSTRAP = ROOT / "scripts" / "newton-bootstrap"


def run(script, *args, env=None):
    return subprocess.run(
        [str(script), *args], text=True, capture_output=True, env=env, timeout=10
    )


def make_install_repo(tmp_path):
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    (repo / "mcp").mkdir()
    shutil.copy2(INSTALL, repo / "scripts/newton-install")
    shutil.copy2(DOCTOR, repo / "scripts/newton-doctor")
    shutil.copy2(BOOTSTRAP, repo / "scripts/newton-bootstrap")
    shutil.copy2(ROOT / "scripts/newton-scan", repo / "scripts/newton-scan")
    shutil.copy2(
        ROOT / "scripts/newton-vantage-setup",
        repo / "scripts/newton-vantage-setup",
    )
    (repo / "mcp/placeholder.py").write_text("# package placeholder\n")
    (repo / "mcp/pyproject.toml").write_text(
        "[project]\nname = 'newton-mcp'\nversion = '0'\n"
    )
    (repo / "mcp/requirements.lock").write_text(
        "# hash-pinned dependencies (fixture stand-in)\n"
    )
    # the router sources the installer must find (design 7.2 row INST)
    for rel in (
        "device/openwrt/newton-router/newton-router",
        "device/openwrt/newton-router/router-tools.txt",
        "device/openwrt/newton-router/grammar.tsv",
        "device/openwrt/newton-guard/newton-guard",
        "device/openwrt/newton-guard/newton-guard.init",
        "profiles/openwrt/manifest.toml",
        "profiles/openwrt/standard.uci",
        "profiles/openwrt/hardened.uci",
        "profiles/openwrt/lockdown.uci",
        "profiles/openwrt/intents.toml",
    ):
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# fixture source for %s\n" % rel)
    (repo / "SKILL.md").write_text("# Newton\n")
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Test Operator"], check=True
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "operator@example.test"],
        check=True,
    )
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-q", "-m", "trusted source"],
        check=True,
    )
    return repo


def install_test_env(tmp_path):
    env = os.environ.copy()
    env.update(NEWTON_INSTALL_ROOT=str(tmp_path / "root"), SUDO_USER="agent")
    return env


def rootless_root_command(*args):
    unshare = shutil.which("unshare")
    if unshare is None:
        pytest.skip("unshare is unavailable; cannot test installer gates as root")
    probe = subprocess.run(
        [unshare, "-Ur", "true"], text=True, capture_output=True, timeout=10
    )
    if probe.returncode != 0:
        reason = probe.stderr.strip() or f"unshare exited {probe.returncode}"
        pytest.skip(f"unshare -Ur is unavailable; cannot test installer gates as root: {reason}")
    return [unshare, "-Ur", "--", *map(str, args)]


def test_install_check_uses_fake_root_without_writing(tmp_path):
    fake_root = tmp_path / "root"
    env = os.environ.copy()
    env.update(NEWTON_INSTALL_ROOT=str(fake_root), SUDO_USER="agent")

    result = run(INSTALL, "--check", env=env)

    assert result.returncode == 0, result.stderr
    assert not fake_root.exists()
    assert "CHECK ONLY: no changes will be made" in result.stdout
    assert 'agent ALL=(newton) NOPASSWD: /usr/local/bin/newton-mcp ""' in result.stdout
    assert "agent ALL=(newton) /usr/local/bin/newton-approve" in result.stdout
    assert "sudo -n -u newton /usr/local/bin/newton-mcp" in result.stdout
    for path in (
        "/var/lib/newton",
        "/opt/newton/{scripts,mcp,device,profiles,SKILL.md}",
        "/opt/newton/venv",
        "/usr/local/bin/newton-mcp",
        "/usr/local/bin/newton-approve",
        "/usr/local/bin/newton-router-setup",
        "/usr/local/bin/newton-vantage-setup",
        "/usr/local/bin/newton-enrol",
        "/usr/local/bin/newton-ad-setup",
        "/etc/sudoers.d/newton-mcp",
    ):
        assert path in result.stdout


# ---- the approve and setup launchers' sudoers rules drop the timestamp cache ----

SUDOERS_HEADER = (
    "Would validate and install sudoers rules: /etc/sudoers.d/newton-mcp"
    " (root:root 0440)"
)
EXPECTED_SUDOERS_LINES = [
    'agent ALL=(newton) NOPASSWD: /usr/local/bin/newton-mcp ""',
    "agent ALL=(newton) /usr/local/bin/newton-approve",
    "Defaults!/usr/local/bin/newton-approve timestamp_timeout=0",
    "agent ALL=(newton) /usr/local/bin/newton-router-setup",
    "Defaults!/usr/local/bin/newton-router-setup timestamp_timeout=0",
    "agent ALL=(newton) /usr/local/bin/newton-vantage-setup",
    "Defaults!/usr/local/bin/newton-vantage-setup timestamp_timeout=0",
    "agent ALL=(newton) /usr/local/bin/newton-enrol",
    "Defaults!/usr/local/bin/newton-enrol timestamp_timeout=0",
    "agent ALL=(newton) /usr/local/bin/newton-ad-setup",
    "Defaults!/usr/local/bin/newton-ad-setup timestamp_timeout=0",
]


def check_listing(tmp_path):
    env = install_test_env(tmp_path)
    result = run(INSTALL, "--check", env=env)
    assert result.returncode == 0, result.stderr
    return result.stdout.splitlines()


def test_install_check_lists_approve_timestamp_defaults_line(tmp_path):
    lines = check_listing(tmp_path)
    assert "Defaults!/usr/local/bin/newton-approve timestamp_timeout=0" in lines


def test_install_sudoers_user_lines_keep_nopasswd_only_for_mcp(tmp_path):
    lines = check_listing(tmp_path)
    user_lines = [line for line in lines if line.startswith("agent ALL=")]
    assert user_lines == [
        EXPECTED_SUDOERS_LINES[0],
        EXPECTED_SUDOERS_LINES[1],
        EXPECTED_SUDOERS_LINES[3],
        EXPECTED_SUDOERS_LINES[5],
        EXPECTED_SUDOERS_LINES[7],
        EXPECTED_SUDOERS_LINES[9],
    ]
    assert not any(
        "NOPASSWD" in line and "newton-approve" in line for line in lines
    )
    assert not any(
        "NOPASSWD" in line and "newton-router-setup" in line for line in lines
    )
    assert not any(
        "NOPASSWD" in line and "newton-vantage-setup" in line for line in lines
    )
    assert not any(
        "NOPASSWD" in line and "newton-enrol" in line for line in lines
    )
    assert not any(
        "NOPASSWD" in line and "newton-ad-setup" in line for line in lines
    )


def test_install_check_sudoers_lines_pass_visudo(tmp_path):
    visudo = Path("/usr/sbin/visudo")
    if not visudo.exists():
        pytest.skip("/usr/sbin/visudo is not installed")
    lines = check_listing(tmp_path)
    start = lines.index(SUDOERS_HEADER)
    sudoers_lines = lines[start + 1 : start + 1 + len(EXPECTED_SUDOERS_LINES)]
    assert sudoers_lines == EXPECTED_SUDOERS_LINES
    sudoers_file = tmp_path / "newton-mcp.sudoers"
    sudoers_file.write_text("\n".join(sudoers_lines) + "\n")
    result = subprocess.run(
        [str(visudo), "-cf", str(sudoers_file)],
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_install_printf_writes_the_same_sudoers_variables_it_lists():
    source = INSTALL.read_text()
    assert (
        'SUDOERS_APPROVE_DEFAULTS_LINE="Defaults!$APPROVE_LAUNCHER timestamp_timeout=0"'
        in source
    )
    writers = [
        line for line in source.splitlines()
        if "printf" in line and "sudoers_tmp" in line
    ]
    assert len(writers) == 1
    for variable in (
        "$SUDOERS_MCP_LINE",
        "$SUDOERS_APPROVE_LINE",
        "$SUDOERS_APPROVE_DEFAULTS_LINE",
        "$SUDOERS_SETUP_LINE",
        "$SUDOERS_SETUP_DEFAULTS_LINE",
        "$SUDOERS_VANTAGE_SETUP_LINE",
        "$SUDOERS_VANTAGE_SETUP_DEFAULTS_LINE",
        "$SUDOERS_ENROL_LINE",
        "$SUDOERS_ENROL_DEFAULTS_LINE",
    ):
        assert f'"{variable}"' in writers[0]
    listing = source.split("Would validate and install sudoers rules", 1)[1]
    listing = listing.split("EOF", 1)[0]
    for variable in (
        "$SUDOERS_MCP_LINE",
        "$SUDOERS_APPROVE_LINE",
        "$SUDOERS_APPROVE_DEFAULTS_LINE",
        "$SUDOERS_SETUP_LINE",
        "$SUDOERS_SETUP_DEFAULTS_LINE",
        "$SUDOERS_VANTAGE_SETUP_LINE",
        "$SUDOERS_VANTAGE_SETUP_DEFAULTS_LINE",
        "$SUDOERS_ENROL_LINE",
        "$SUDOERS_ENROL_DEFAULTS_LINE",
    ):
        assert variable in listing


def test_install_check_prints_commit_and_tree_state_without_prompt(tmp_path):
    # the identity block comes from the authenticated commit
    # file, not git porcelain, and --check never reaches the prompt.
    repo = make_install_repo(tmp_path)
    script = repo / "scripts/newton-install"
    env = install_test_env(tmp_path)

    result = run(script, "--check", env=env)

    head = git_out(repo, "rev-parse", "HEAD")
    tree = git_out(repo, "rev-parse", "HEAD^{tree}")
    assert result.returncode == 0, result.stderr
    assert f"Source repository: {repo.resolve()}" in result.stdout
    assert f"Commit:  {head}" in result.stdout
    assert f"Tree:    {tree}" in result.stdout
    assert "Author:  Test Operator <operator@example.test>" in result.stdout
    date_line = next(
        line for line in result.stdout.splitlines() if line.startswith("Date:    ")
    )
    assert "UTC" in date_line
    assert re.search(r"\(author timezone [+-][0-9]{4}\)$", date_line)
    assert "Subject: trusted source" in result.stdout
    assert (
        "Remote branches containing this commit "
        "(as reported by the repo; check it matches GitHub):" in result.stdout
    )
    assert "  (none)" in result.stdout
    assert "Working tree (informational, from the repo): clean" in result.stdout
    assert "Compare the commit id" not in result.stderr
    assert not (tmp_path / "root").exists()


def test_install_dirty_tracked_tree_reaches_prompt_r2c(tmp_path):
    # a dirty or untracked working tree is reported but no
    # longer blocks; the run reaches the prompt and the snapshot is
    # still exactly HEAD's tree.
    repo = make_install_repo(tmp_path)
    head_tree = git_out(repo, "rev-parse", "HEAD^{tree}")
    head12 = git_out(repo, "rev-parse", "HEAD")[:12]
    (repo / "SKILL.md").write_text("changed after review\n")
    (repo / "untracked-notes.txt").write_text("never reviewed\n")
    env = install_test_env(tmp_path)
    command = rootless_root_command(repo / "scripts/newton-install")
    master, slave = pty.openpty()
    try:
        os.write(master, b"not approved\n")
        result = subprocess.run(
            command,
            stdin=slave,
            text=True,
            capture_output=True,
            env=env,
            timeout=30,
        )
    finally:
        os.close(slave)
        os.close(master)

    assert result.returncode == 1, result.stdout + result.stderr
    assert f"Tree:    {head_tree}" in result.stdout
    assert (
        f"Working tree (informational, from the repo): 1 tracked change(s), "
        f"1 untracked file(s); none of them are installed "
        f"(only commit {head12} is)" in result.stdout
    )
    assert "Compare the commit id" in result.stderr
    assert "refusing to install" not in result.stderr
    assert "confirmation did not match; installation aborted" in result.stderr
    assert not (tmp_path / "root").exists()


def test_install_checks_euid_before_terminal_and_commit_prompt(tmp_path):
    repo = make_install_repo(tmp_path)
    env = install_test_env(tmp_path)

    result = run(repo / "scripts/newton-install", env=env)

    assert result.returncode == 1
    assert "must run as root" in result.stderr
    assert "Compare the commit id" not in result.stderr
    assert not (tmp_path / "root").exists()


def test_install_euid_check_precedes_confirmation_even_with_terminal(tmp_path):
    repo = make_install_repo(tmp_path)
    env = install_test_env(tmp_path)
    master, slave = pty.openpty()
    try:
        os.write(master, b"not approved\n")
        result = subprocess.run(
            [str(repo / "scripts/newton-install")],
            stdin=slave,
            text=True,
            capture_output=True,
            env=env,
            timeout=10,
        )
    finally:
        os.close(slave)
        os.close(master)

    assert result.returncode == 1
    assert "must run as root" in result.stderr
    assert "Compare the commit id" not in result.stderr
    assert not (tmp_path / "root").exists()


def test_install_without_terminal_refuses_before_changes_as_root(tmp_path):
    repo = make_install_repo(tmp_path)
    env = install_test_env(tmp_path)

    result = subprocess.run(
        rootless_root_command(repo / "scripts/newton-install"),
        input="",
        text=True,
        capture_output=True,
        env=env,
        timeout=10,
    )

    assert result.returncode == 1
    assert "refusing non-interactive install" in result.stderr
    assert "must run as root" not in result.stderr
    assert not (tmp_path / "root").exists()


def test_install_wrong_confirmation_aborts_before_changes_as_root(tmp_path):
    repo = make_install_repo(tmp_path)
    env = install_test_env(tmp_path)
    command = rootless_root_command(repo / "scripts/newton-install")
    master, slave = pty.openpty()
    try:
        os.write(master, b"not approved\n")
        result = subprocess.run(
            command,
            stdin=slave,
            text=True,
            capture_output=True,
            env=env,
            timeout=10,
        )
    finally:
        os.close(slave)
        os.close(master)

    assert result.returncode == 1
    assert "confirmation did not match; installation aborted" in result.stderr
    assert "Compare the commit id" in result.stderr
    assert "must run as root" not in result.stderr
    assert not (tmp_path / "root").exists()


# ---- the installer's sanitizer for repo-derived text ----


def sanitize_text_call(data, max_bytes=None):
	limit = "" if max_bytes is None else f" {max_bytes}"
	result = subprocess.run(
		[
			"bash",
			"-c",
			f'source scripts/newton-install; sanitize_text "$1"{limit}',
			"sanitize_text",
			data,
		],
		cwd=str(ROOT),
		capture_output=True,
		timeout=10,
	)
	assert result.returncode == 0, result.stderr
	return result.stdout


def test_sanitize_text_escapes_terminal_control_bytes_f3():
	out = sanitize_text_call(b"\x1b[31mred\x1b]0;title\x07\x1bOK\rworld\tend")
	assert out == b"\\x1b[31mred\\x1b]0;title\\x07\\x1bOK\\x0dworld\\x09end\n"


def test_sanitize_text_escapes_backslash_f3():
	assert sanitize_text_call(b"a\\b") == b"a\\\\b\n"


def test_sanitize_text_escapes_del_f3():
	assert sanitize_text_call(b"\x7f") == b"\\x7f\n"


def test_sanitize_text_escapes_utf8_bytes_f3():
	assert sanitize_text_call("café".encode()) == b"caf\\xc3\\xa9\n"


def test_sanitize_text_truncates_long_input_f3():
	out = sanitize_text_call(b"a" * 5000)
	assert out == b"a" * 200 + b"...[truncated]\n"
	assert len(out) <= 200 + len(b"...[truncated]\n")
	# The cut is on input bytes before escaping, not on output length.
	out = sanitize_text_call(b"\x1b" * 250)
	assert out == b"\\x1b" * 200 + b"...[truncated]\n"


def test_sanitize_text_custom_max_bytes_f3():
	assert sanitize_text_call(b"abcdef", 3) == b"abc...[truncated]\n"
	assert sanitize_text_call(b"abc", 3) == b"abc\n"
	assert sanitize_text_call(b"abcdefgh", 200) == b"abcdefgh\n"


def test_sanitize_text_empty_input_f3():
	assert sanitize_text_call(b"") == b"\n"


def test_install_check_shows_escaped_author_and_subject_f3(tmp_path):
	repo = make_install_repo(tmp_path)
	subject = "setup \x1b[31mred\x1b[0m subject"
	author = "Evil \x1b]0;pwn\x07 Author <evil@example.test>"
	subprocess.run(
		[
			"git",
			"-C",
			str(repo),
			"commit",
			"-q",
			"--allow-empty",
			"--amend",
			f"--author={author}",
			"-m",
			subject,
		],
		check=True,
	)
	env = install_test_env(tmp_path)

	result = run(repo / "scripts/newton-install", "--check", env=env)

	assert result.returncode == 0, result.stderr
	assert "\x1b" not in result.stdout
	assert "\\x1b[31mred\\x1b[0m subject" in result.stdout
	assert "Evil \\x1b]0;pwn\\x07 Author" in result.stdout


def launcher_text(name="launcher_tmp"):
    source = INSTALL.read_text()
    match = re.search(
        rf'''cat >"\${name}" <<'EOF'\n(.*?)\nEOF\n''', source, re.DOTALL
    )
    assert match, "launcher template not found"
    return match.group(1) + "\n"


# ---- the verified commit snapshot taken before the prompt ----


def git_run(repo, *args):
    subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    )


def git_out(repo, *args):
    return subprocess.check_output(
        ["git", "-C", str(repo), *args], text=True
    ).strip()


def run_make_snapshot(repo, env_extra=None):
    env = os.environ.copy()
    env.update(env_extra or {})
    code = (
        'source "$1"/scripts/newton-install\n'
        "REPO=$1\n"
        "INSTALL_ROOT=${NEWTON_INSTALL_ROOT:-1}\n"
        "invoking_user=$(id -un)\n"
        "if make_snapshot; then printf 'SNAPSHOT_OK\\n'; else printf 'SNAPSHOT_FAILED\\n'; fi\n"
        'printf "WORK=%s\\n" "${WORK:-}"\n'
        'printf "TREE_ID=%s\\n" "${TREE_ID:-}"\n'
        'printf "SNAP_FILE_COUNT=%s\\n" "${SNAP_FILE_COUNT:-}"\n'
    )
    return subprocess.run(
        ["bash", "-c", code, "make_snapshot", str(repo)],
        text=True,
        capture_output=True,
        env=env,
        timeout=30,
    )


def snapshot_fields(result):
    fields = {}
    for line in result.stdout.splitlines():
        key, sep, value = line.partition("=")
        if sep and key in ("WORK", "TREE_ID", "SNAP_FILE_COUNT"):
            fields[key] = value
    return fields


def assert_snapshot_refused(result):
    assert "SNAPSHOT_FAILED" in result.stdout.splitlines(), result.stdout + result.stderr
    assert "SNAPSHOT_OK" not in result.stdout
    assert "ERROR: " in result.stderr
    assert "; nothing installed" in result.stderr
    work = snapshot_fields(result).get("WORK", "")
    if work:
        assert not Path(work).exists()


def assert_snapshot_matches_head(result, repo):
    assert "SNAPSHOT_OK" in result.stdout.splitlines(), result.stdout + result.stderr
    fields = snapshot_fields(result)
    assert fields["TREE_ID"] == git_out(repo, "rev-parse", "HEAD^{tree}")
    expected = len(git_out(repo, "ls-tree", "-r", "--name-only", "HEAD").splitlines())
    assert fields["SNAP_FILE_COUNT"] == str(expected)
    assert not Path(fields["WORK"]).exists()


def overwrite_object_bytes(repo, target_id, source_id):
    """Replace the loose object file of target_id with the zlib stream of
    source_id (the same bytes git would store for that object)."""
    obj_type = git_out(repo, "cat-file", "-t", source_id)
    content = subprocess.check_output(
        ["git", "-C", str(repo), "cat-file", obj_type, source_id]
    )
    raw = (
        obj_type.encode()
        + b" "
        + str(len(content)).encode()
        + b"\0"
        + content
    )
    objects = Path(
        git_out(repo, "rev-parse", "--path-format=absolute", "--git-path", "objects")
    )
    obj_path = objects / target_id[:2] / target_id[2:]
    obj_path.parent.mkdir(parents=True, exist_ok=True)
    if obj_path.exists():
        obj_path.chmod(0o644)
    obj_path.write_bytes(zlib.compress(raw))


def make_sentinel(tmp_path):
    sentinel = tmp_path / "sentinel-was-run"
    script = tmp_path / "sentinel.sh"
    script.write_text("#!/bin/sh\ntouch '%s'\n" % sentinel)
    script.chmod(0o755)
    return script, sentinel


def test_make_snapshot_verifies_head_tree_f1(tmp_path):
    repo = make_install_repo(tmp_path)

    result = run_make_snapshot(repo)

    assert_snapshot_matches_head(result, repo)
    assert result.stderr == ""


def test_make_snapshot_works_after_gc_f1(tmp_path):
    repo = make_install_repo(tmp_path)
    git_run(repo, "gc", "--quiet", "--prune=now")

    result = run_make_snapshot(repo)

    assert_snapshot_matches_head(result, repo)


def test_make_snapshot_works_from_linked_worktree_f1(tmp_path):
    repo = make_install_repo(tmp_path)
    worktree = tmp_path / "linked"
    git_run(repo, "worktree", "add", "-q", "-b", "wt", str(worktree))
    (worktree / "mcp/placeholder.py").write_text("# changed in worktree\n")
    git_run(worktree, "add", "-A")
    git_run(worktree, "commit", "-q", "-m", "worktree change")

    result = run_make_snapshot(worktree)

    assert_snapshot_matches_head(result, worktree)


def test_make_snapshot_tampered_commit_stops_before_install_f1(tmp_path):
    repo = make_install_repo(tmp_path)
    other = git_out(repo, "commit-tree", git_out(repo, "rev-parse", "HEAD^{tree}"), "-m", "other")
    head = git_out(repo, "rev-parse", "HEAD")
    overwrite_object_bytes(repo, head, other)

    result = run_make_snapshot(repo)

    # A hash-mismatched commit object never reaches the root-side sha1
    # proof: git itself refuses it in the invoking-user reads that run
    # first (git branch --contains / git status), so this only asserts
    # the clean stop. The root-side proof is exercised by
    # test_make_snapshot_refuses_tampered_commit_printed_by_git_f1.
    assert_snapshot_refused(result)


def test_make_snapshot_tampered_tree_stops_before_install_f1(tmp_path):
    repo = make_install_repo(tmp_path)
    tree1 = git_out(repo, "rev-parse", "HEAD^{tree}")
    head = git_out(repo, "rev-parse", "HEAD")
    (repo / "extra.txt").write_text("extra\n")
    git_run(repo, "add", "extra.txt")
    git_run(repo, "commit", "-q", "-m", "extra")
    tree2 = git_out(repo, "rev-parse", "HEAD^{tree}")
    git_run(repo, "reset", "-q", "--hard", head)
    overwrite_object_bytes(repo, tree1, tree2)

    result = run_make_snapshot(repo)

    # As with the tampered commit: the invoking-user reads (git branch
    # --contains / git status) already refuse the mismatched tree object,
    # so the root-side tree proof is not what stops this run.
    assert_snapshot_refused(result)


def test_make_snapshot_refuses_tampered_blob_object_f1(tmp_path):
    repo = make_install_repo(tmp_path)
    tree = git_out(repo, "rev-parse", "HEAD^{tree}")
    blob1 = git_out(repo, "rev-parse", "HEAD:mcp/placeholder.py")
    blob2 = subprocess.check_output(
        ["git", "-C", str(repo), "hash-object", "-w", "--stdin"],
        input="tampered contents\n",
        text=True,
    ).strip()
    overwrite_object_bytes(repo, blob1, blob2)

    result = run_make_snapshot(repo)

    assert_snapshot_refused(result)
    # For a blob only the root-side tree proof can catch the tamper, so
    # the specific message is part of the contract.
    assert "snapshot files do not match tree" in result.stderr


def make_tampering_git_wrapper(tmp_path, mode, archive=None):
    """A /usr/bin/git stand-in that passes everything through to
    /usr/lib/git-core/git except one root-side call, whose output it
    tampers with. mode is 'commit' (rewrite the author line of the
    src.git cat-file commit read), 'write-tree' (print a wrong tree
    id from the verify.git write-tree call) or 'archive' (replace the
    src.git git archive output with the crafted tar at `archive`)."""
    real = "/usr/lib/git-core/git"
    if mode == "commit":
        tamper = (
            'if [ "${GIT_DIR:-}" != "${GIT_DIR%/src.git}" ]'
            ' && [ "${1:-}" = --no-pager ]'
            ' && [ "${2:-}" = cat-file ]'
            ' && [ "${3:-}" = commit ]; then\n'
            f'  {real} "$@"'
            " | sed 's/^author .*/author Mallory <m@example.test> 1 +0000/'\n"
            "  exit 0\n"
            "fi\n"
        )
    elif mode == "archive":
        tamper = (
            'if [ "${GIT_DIR:-}" != "${GIT_DIR%/src.git}" ]'
            ' && [ "${1:-}" = --no-pager ]'
            ' && case " $* " in *" archive "*) true;; *) false;; esac; then\n'
            f'  cat "{archive}"\n'
            "  exit 0\n"
            "fi\n"
        )
    else:
        tamper = (
            "last=\n"
            'for arg in "$@"; do last=$arg; done\n'
            'if [ "${GIT_DIR:-}" != "${GIT_DIR%/verify.git}" ]'
            ' && [ "$last" = write-tree ]; then\n'
            "  printf '%s\\n' 0000000000000000000000000000000000000001\n"
            "  exit 0\n"
            "fi\n"
        )
    wrapper = tmp_path / f"git-wrapper-{mode}"
    wrapper.write_text(f"#!/bin/sh\n{tamper}exec {real} \"$@\"\n")
    wrapper.chmod(0o755)
    return wrapper


def run_make_snapshot_with_git_wrapper(tmp_path, repo, wrapper):
    """Run make_snapshot inside a user+mount namespace with the wrapper
    bind-mounted over /usr/bin/git, so the root-side git calls (which
    use a PATH of system directories) go through it too."""
    unshare = shutil.which("unshare")
    if unshare is None:
        pytest.skip("unshare is unavailable")
    if not Path("/usr/lib/git-core/git").exists():
        pytest.skip("/usr/lib/git-core/git is missing")
    if not Path("/usr/bin/git").exists():
        pytest.skip("/usr/bin/git is missing; cannot bind-mount over it")
    probe = subprocess.run(
        [unshare, "-Urm", "true"], text=True, capture_output=True, timeout=10
    )
    if probe.returncode != 0:
        reason = probe.stderr.strip() or f"unshare exited {probe.returncode}"
        pytest.skip(f"unshare -Urm is unavailable: {reason}")
    code = (
        'mount --bind "$2" /usr/bin/git || exit 99\n'
        'source "$1"/scripts/newton-install\n'
        "REPO=$1\n"
        "INSTALL_ROOT=${NEWTON_INSTALL_ROOT:-1}\n"
        "invoking_user=$(id -un)\n"
        "if make_snapshot; then printf 'SNAPSHOT_OK\\n'; else printf 'SNAPSHOT_FAILED\\n'; fi\n"
        'printf "WORK=%s\\n" "${WORK:-}"\n'
        'printf "TREE_ID=%s\\n" "${TREE_ID:-}"\n'
        'printf "SNAP_FILE_COUNT=%s\\n" "${SNAP_FILE_COUNT:-}"\n'
    )
    return subprocess.run(
        [unshare, "-Urm", "--", "bash", "-c", code, "make_snapshot", str(repo), str(wrapper)],
        text=True,
        capture_output=True,
        env=os.environ.copy(),
        timeout=60,
    )


def test_make_snapshot_refuses_tampered_commit_printed_by_git_f1(tmp_path):
    # git itself refuses a hash-mismatched object file, so the sha1
    # proof of the commit object is only reached when git happily hands
    # out different bytes for the id: this wrapper rewrites the author
    # line of the root-side cat-file read, and the proof must catch it.
    repo = make_install_repo(tmp_path)
    wrapper = make_tampering_git_wrapper(tmp_path, "commit")

    result = run_make_snapshot_with_git_wrapper(tmp_path, repo, wrapper)

    assert_snapshot_refused(result)
    assert "commit object does not match its id" in result.stderr


def test_make_snapshot_refuses_wrong_write_tree_id_from_git_f1(tmp_path):
    # The root-side write-tree on verify.git is the only proof of the
    # extracted files: when it lies (a wrong tree id), make_snapshot
    # must refuse instead of trusting it.
    repo = make_install_repo(tmp_path)
    wrapper = make_tampering_git_wrapper(tmp_path, "write-tree")

    result = run_make_snapshot_with_git_wrapper(tmp_path, repo, wrapper)

    assert_snapshot_refused(result)
    assert "snapshot files do not match tree" in result.stderr


def craft_archive_with_extra_member(repo, tmp_path, member_name, tag):
    """The real archive of HEAD plus one extra regular member, so the
    only thing that can refuse the archive is the member's name."""
    archive = tmp_path / f"crafted-archive-{tag}.tar"
    with open(archive, "wb") as handle:
        subprocess.run(
            ["git", "-C", str(repo), "archive", "--format=tar", "HEAD"],
            check=True,
            stdout=handle,
        )
    content = b"marker\n"
    with tarfile.open(archive, "a") as tar:
        info = tarfile.TarInfo(member_name)
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
    return archive


def run_with_crafted_archive(repo, tmp_path, member_name, tag):
    archive = craft_archive_with_extra_member(repo, tmp_path, member_name, tag)
    wrapper = make_tampering_git_wrapper(tmp_path, "archive", archive)
    return run_make_snapshot_with_git_wrapper(tmp_path, repo, wrapper)


def test_make_snapshot_refuses_dotdot_archive_member_f1(tmp_path):
    # git archive itself never writes a '..' name, so the only way to
    # reach the installer's own check is a lying root-side git archive.
    repo = make_install_repo(tmp_path)

    result = run_with_crafted_archive(repo, tmp_path, "../escape-marker", "dotdot")

    assert_snapshot_refused(result)
    assert "snapshot archive path escapes the extraction directory" in result.stderr
    assert "snapshot contains an entry that is not" not in result.stderr
    assert not list(tmp_path.glob("*escape-marker*"))


def test_make_snapshot_refuses_absolute_archive_member_f1(tmp_path):
    repo = make_install_repo(tmp_path)
    marker_dir = tmp_path / "abs-escape"
    marker = marker_dir / "abs-marker"

    result = run_with_crafted_archive(
        repo, tmp_path, str(marker), "absolute"
    )

    assert_snapshot_refused(result)
    assert "snapshot archive contains an absolute path" in result.stderr
    assert "snapshot contains an entry that is not" not in result.stderr
    assert not marker.exists()
    assert not marker_dir.exists()


def test_make_snapshot_refuses_git_directory_archive_member_f1(tmp_path):
    repo = make_install_repo(tmp_path)

    result = run_with_crafted_archive(repo, tmp_path, "sub/.git/config", "gitdir")

    assert_snapshot_refused(result)
    assert "snapshot archive contains a .git path" in result.stderr
    assert "snapshot contains an entry that is not" not in result.stderr


def make_symlink_repo(tmp_path):
    repo = make_install_repo(tmp_path)
    blob = subprocess.check_output(
        ["git", "-C", str(repo), "hash-object", "-w", "--stdin"],
        input="/etc/passwd\n",
        text=True,
    ).strip()
    git_run(repo, "update-index", "--add", "--cacheinfo", f"120000,{blob},link")
    tree = git_out(repo, "write-tree")
    commit = git_out(repo, "commit-tree", tree, "-p", "HEAD", "-m", "add symlink")
    git_run(repo, "reset", "-q", "--hard", commit)
    return repo


def test_make_snapshot_refuses_symlink_tree_entry_f1(tmp_path):
    repo = make_symlink_repo(tmp_path)

    result = run_make_snapshot(repo)

    assert_snapshot_refused(result)
    # The pre-extraction tar listing scan must be what refuses the
    # symlink, not the later post-extraction find re-check (GNU tar
    # 1.35 itself refuses to write through a symlink it extracted, so
    # the message is the only observable difference).
    assert "snapshot archive entry is not a regular file or directory" in result.stderr
    assert "snapshot contains an entry that is not" not in result.stderr
    assert "link" in result.stderr


def make_duplicate_name_repo(tmp_path):
    """A commit whose root tree contains the name 'a' twice: a symlink
    to an absolute directory inside tmp_path and a directory holding
    'payload'. git archive writes both members, so only the installer's
    own pre-extraction scan can stop the symlink."""
    repo = make_install_repo(tmp_path)
    target = tmp_path / "escape-target"
    target.mkdir()
    link_blob = subprocess.check_output(
        ["git", "-C", str(repo), "hash-object", "-w", "--stdin"],
        input=f"{target}\n",
        text=True,
    ).strip()
    payload_blob = subprocess.check_output(
        ["git", "-C", str(repo), "hash-object", "-w", "--stdin"],
        input="payload\n",
        text=True,
    ).strip()
    subtree = subprocess.check_output(
        ["git", "-C", str(repo), "mktree"],
        input=f"100644 blob {payload_blob}\tpayload\n",
        text=True,
    ).strip()

    def entry(mode, name, sha_hex):
        return mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(sha_hex)

    tree_body = (
        entry("120000", "a", link_blob) + entry("40000", "a", subtree)
    )
    tree = subprocess.check_output(
        ["git", "-C", str(repo), "hash-object", "-w", "-t", "tree", "--literally", "--stdin"],
        input=tree_body,
    ).strip().decode()
    commit = git_out(repo, "commit-tree", tree, "-p", "HEAD", "-m", "duplicate name")
    git_run(repo, "update-ref", "refs/heads/main", commit)
    return repo, target


def test_make_snapshot_refuses_duplicate_name_symlink_tree_entry_f1(tmp_path):
    repo, target = make_duplicate_name_repo(tmp_path)

    result = run_make_snapshot(repo)

    assert_snapshot_refused(result)
    # The symlink member must be caught by the pre-extraction scan (the
    # duplicate directory entry would let tar extract the symlink first
    # and write payload through it afterwards).
    assert "snapshot archive entry is not a regular file or directory" in result.stderr
    assert "snapshot contains an entry that is not" not in result.stderr
    assert not (target / "payload").exists()


def test_make_snapshot_refuses_gitattributes_in_tree_f1(tmp_path):
    repo = make_install_repo(tmp_path)
    (repo / ".gitattributes").write_text("* filter=x\n")
    git_run(repo, "add", ".gitattributes")
    git_run(repo, "commit", "-q", "-m", "attributes")

    result = run_make_snapshot(repo)

    assert_snapshot_refused(result)
    assert ".gitattributes" in result.stderr


def test_make_snapshot_refuses_archive_over_size_cap_f1(tmp_path):
    repo = make_install_repo(tmp_path)

    result = run_make_snapshot(
        repo, env_extra={"NEWTON_INSTALL_MAX_ARCHIVE_BYTES": "10"}
    )

    assert_snapshot_refused(result)
    assert "size cap" in result.stderr


def test_make_snapshot_size_cap_is_exact_f1(tmp_path):
    # The write is bounded by ulimit -f in whole 1 KiB blocks just above the
    # cap, so an archive only a few bytes over the cap is written in full and
    # only the size check after the write refuses it.
    repo = make_install_repo(tmp_path)
    archive = subprocess.run(
        ["git", "-C", str(repo), "archive", "--format=tar", "HEAD"],
        capture_output=True,
        check=True,
        timeout=30,
    )
    size = len(archive.stdout)

    over = run_make_snapshot(
        repo, env_extra={"NEWTON_INSTALL_MAX_ARCHIVE_BYTES": str(size - 1)}
    )
    exact = run_make_snapshot(
        repo, env_extra={"NEWTON_INSTALL_MAX_ARCHIVE_BYTES": str(size)}
    )

    assert_snapshot_refused(over)
    assert "size cap" in over.stderr
    assert_snapshot_matches_head(exact, repo)


def archive_cap_call(install_root, maximum):
    result = subprocess.run(
        [
            "bash",
            "-c",
            "source scripts/newton-install; "
            f"INSTALL_ROOT={install_root}; "
            f"NEWTON_INSTALL_MAX_ARCHIVE_BYTES={maximum}; "
            "archive_size_cap",
        ],
        cwd=str(ROOT),
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.decode()


def test_archive_size_cap_test_variable_needs_the_seam_f1():
    assert archive_cap_call("1", "10") == "10\n"
    # Without NEWTON_INSTALL_ROOT the cap variable is ignored (100 MiB).
    assert archive_cap_call("", "10") == "104857600\n"


def test_make_snapshot_never_runs_repo_filter_driver_f1(tmp_path):
    repo = make_install_repo(tmp_path)
    script, sentinel = make_sentinel(tmp_path)
    git_run(repo, "config", "filter.x.process", f"{script} %f")
    git_run(repo, "config", "filter.x.required", "true")
    (repo / ".git/info").mkdir(exist_ok=True)
    (repo / ".git/info/attributes").write_text("* filter=x\n")

    result = run_make_snapshot(repo)

    assert_snapshot_matches_head(result, repo)
    assert not sentinel.exists()


def test_make_snapshot_never_runs_promisor_ssh_command_f1(tmp_path):
    repo = make_install_repo(tmp_path)
    script, sentinel = make_sentinel(tmp_path)
    git_run(repo, "config", "core.sshCommand", f"{script}")
    git_run(repo, "config", "remote.origin.url", "ssh://192.0.2.2/newton.git")
    git_run(repo, "config", "remote.origin.promisor", "true")
    git_run(repo, "config", "remote.origin.partialclonefilter", "blob:none")
    git_run(repo, "config", "extensions.partialClone", "origin")
    fake_tree = "0" * 40
    commit_text = (
        f"tree {fake_tree}\n"
        "author T <t@example.test> 1700000000 +0000\n"
        "committer T <t@example.test> 1700000000 +0000\n"
        "\n"
        "points at a missing tree\n"
    )
    fake_commit = subprocess.check_output(
        ["git", "-C", str(repo), "hash-object", "-w", "-t", "commit", "--stdin"],
        input=commit_text,
        text=True,
    ).strip()
    git_run(repo, "update-ref", "refs/heads/main", fake_commit)

    result = run_make_snapshot(repo)

    assert_snapshot_refused(result)
    assert not sentinel.exists()


def test_make_snapshot_ignores_replace_refs_f1(tmp_path):
    repo = make_install_repo(tmp_path)
    head = git_out(repo, "rev-parse", "HEAD")
    head_tree = git_out(repo, "rev-parse", f"{head}^{{tree}}")
    git_run(repo, "commit", "-q", "--allow-empty", "-m", "second")
    second = git_out(repo, "rev-parse", "HEAD")
    git_run(repo, "replace", head, second)

    result = run_make_snapshot(repo)

    assert "SNAPSHOT_OK" in result.stdout.splitlines(), result.stdout + result.stderr
    # The snapshot proves the ORIGINAL commit, not its replacement.
    assert snapshot_fields(result)["TREE_ID"] == head_tree


def test_install_check_prints_snapshot_summary_f1(tmp_path):
    repo = make_install_repo(tmp_path)
    env = install_test_env(tmp_path)

    result = run(repo / "scripts/newton-install", "--check", env=env)

    assert result.returncode == 0, result.stderr
    head = git_out(repo, "rev-parse", "HEAD")
    tree = git_out(repo, "rev-parse", "HEAD^{tree}")
    count = len(git_out(repo, "ls-tree", "-r", "--name-only", "HEAD").splitlines())
    assert f"Commit:  {head}" in result.stdout
    assert f"Tree:    {tree}" in result.stdout
    assert f"Snapshot: {count} files verified against tree {tree}" in result.stdout


def test_install_check_lists_snapshot_and_doctor_lines_r2c(tmp_path):
    repo = make_install_repo(tmp_path)
    head = git_out(repo, "rev-parse", "HEAD")
    tree = git_out(repo, "rev-parse", "HEAD^{tree}")
    env = install_test_env(tmp_path)

    result = run(repo / "scripts/newton-install", "--check", env=env)

    assert result.returncode == 0, result.stderr
    assert f"Would install a verified snapshot of commit {head} (tree {tree})" in (
        result.stdout
    )
    assert (
        "Would install: /usr/local/bin/newton-doctor "
        "(root:root 0755; test seams disabled)" in result.stdout
    )


# ---- display and prompt from the authenticated commit file ----


def run_install_pty(repo, tmp_path, feed=b"not approved\n"):
    """Run the fixture installer as root through the rootless fake root
    (unshare -Ur) with a pty on stdin, so the interactive gates pass and
    stdout/stderr stay separately captured pipes."""
    env = install_test_env(tmp_path)
    command = rootless_root_command(repo / "scripts/newton-install")
    master, slave = pty.openpty()
    try:
        os.write(master, feed)
        result = subprocess.run(
            command,
            stdin=slave,
            text=True,
            capture_output=True,
            env=env,
            timeout=60,
        )
    finally:
        os.close(slave)
        os.close(master)
    return result


def run_install_pty_merged(repo, tmp_path, feed=b"not approved\n"):
    """Same as run_install_pty but with stdout and stderr merged into the
    pty, so the relative order of the identity block and the prompt (both
    streams) can be compared."""
    env = install_test_env(tmp_path)
    command = rootless_root_command(repo / "scripts/newton-install")
    master, slave = pty.openpty()
    proc = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave, env=env)
    os.close(slave)
    os.write(master, feed)
    chunks = []
    try:
        while True:
            ready, _, _ = select.select([master], [], [], 60)
            if not ready:
                break
            try:
                data = os.read(master, 65536)
            except OSError:
                break
            if not data:
                break
            chunks.append(data)
        rc = proc.wait(timeout=60)
    finally:
        os.close(master)
        proc.wait(timeout=60)
    return rc, b"".join(chunks)


def run_install_pty_with_git_wrapper(repo, tmp_path, wrapper, feed=b"not approved\n"):
    """Run the complete interactive installer while a mount namespace
    replaces /usr/bin/git with a wrapper for the root-side verification."""
    unshare = shutil.which("unshare")
    if unshare is None:
        pytest.skip("unshare is unavailable")
    if not Path("/usr/bin/git").exists():
        pytest.skip("/usr/bin/git is missing; cannot bind-mount over it")
    probe = subprocess.run(
        [unshare, "-Urm", "true"], text=True, capture_output=True, timeout=10
    )
    if probe.returncode != 0:
        reason = probe.stderr.strip() or f"unshare exited {probe.returncode}"
        pytest.skip(f"unshare -Urm is unavailable: {reason}")
    code = (
        'mount --bind "$2" /usr/bin/git || exit 99\n'
        'exec "$1"/scripts/newton-install\n'
    )
    command = [
        unshare,
        "-Urm",
        "--",
        "bash",
        "-c",
        code,
        "installer",
        str(repo),
        str(wrapper),
    ]
    env = install_test_env(tmp_path)
    master, slave = pty.openpty()
    try:
        os.write(master, feed)
        result = subprocess.run(
            command,
            stdin=slave,
            text=True,
            capture_output=True,
            env=env,
            timeout=60,
        )
    finally:
        os.close(slave)
        os.close(master)
    return result


def test_install_identity_block_contents_r2c(tmp_path):
    repo = make_install_repo(tmp_path)
    head = git_out(repo, "rev-parse", "HEAD")
    tree = git_out(repo, "rev-parse", "HEAD^{tree}")
    count = len(git_out(repo, "ls-tree", "-r", "--name-only", "HEAD").splitlines())

    result = run_install_pty(repo, tmp_path)

    assert result.returncode == 1, result.stdout + result.stderr
    assert f"Source repository: {repo.resolve()}" in result.stdout
    assert f"Commit:  {head}" in result.stdout
    assert f"Tree:    {tree}" in result.stdout
    assert "Author:  Test Operator <operator@example.test>" in result.stdout
    date_line = next(
        line for line in result.stdout.splitlines() if line.startswith("Date:    ")
    )
    assert "UTC" in date_line
    assert re.search(r"\(author timezone [+-][0-9]{4}\)$", date_line)
    assert "Subject: trusted source" in result.stdout
    assert (
        "Remote branches containing this commit "
        "(as reported by the repo; check it matches GitHub):" in result.stdout
    )
    assert "  (none)" in result.stdout
    assert "Working tree (informational, from the repo): clean" in result.stdout
    assert f"Snapshot: {count} files verified against tree {tree}" in result.stdout
    assert "Compare the commit id" in result.stderr
    assert not (tmp_path / "root").exists()


def test_install_identity_block_limits_remote_branches_r2c(tmp_path):
    repo = make_install_repo(tmp_path)
    head = git_out(repo, "rev-parse", "HEAD")
    expected = [f"origin/b{index:02d}" for index in range(1, 26)]
    for branch in expected:
        git_run(repo, "update-ref", f"refs/remotes/{branch}", head)

    result = run(repo / "scripts/newton-install", "--check", env=install_test_env(tmp_path))

    assert result.returncode == 0, result.stdout + result.stderr
    lines = result.stdout.splitlines()
    heading = lines.index(
        "Remote branches containing this commit "
        "(as reported by the repo; check it matches GitHub):"
    )
    working_tree = next(
        index
        for index, line in enumerate(lines)
        if line.startswith("Working tree (informational, from the repo):")
    )
    branch_lines = lines[heading + 1 : working_tree]
    assert [line.strip() for line in branch_lines[:20]] == expected[:20]
    assert branch_lines[20:] == ["  ... and 5 more not shown"]


def test_install_prompt_comes_after_identity_block_r2c(tmp_path):
    repo = make_install_repo(tmp_path)

    rc, merged = run_install_pty_merged(repo, tmp_path)

    assert rc == 1
    prompt_at = merged.index(b"Compare the commit id")
    assert merged.index(b"Commit:  ") < prompt_at
    assert merged.index(b"Tree:    ") < prompt_at
    assert merged.index(b"Author:  ") < prompt_at
    assert merged.index(b"Subject: ") < prompt_at
    assert merged.index(b"Working tree (informational, from the repo):") < prompt_at
    assert merged.index(b"Snapshot: ") < prompt_at


@pytest.mark.parametrize(
    ("kind", "error"),
    [
        pytest.param("commit", "commit object does not match its id", id="commit"),
        pytest.param("write-tree", "snapshot files do not match tree", id="tree"),
    ],
)
def test_install_no_prompt_when_verification_fails_r2c(tmp_path, kind, error):
    repo = make_install_repo(tmp_path)
    wrapper = make_tampering_git_wrapper(tmp_path, kind)

    result = run_install_pty_with_git_wrapper(repo, tmp_path, wrapper)

    assert result.returncode == 1, result.stdout + result.stderr
    assert error in result.stderr
    assert "nothing installed" in result.stderr
    assert "Compare the commit id" not in result.stderr
    assert "confirmation did not match" not in result.stderr
    assert not (tmp_path / "root").exists()


def test_install_wrong_confirmation_variants_abort_r2c(tmp_path):
    repo = make_install_repo(tmp_path)
    head = git_out(repo, "rev-parse", "HEAD")
    head12 = head[:12]
    head39 = head[:39]
    short_sha = git_out(repo, "rev-parse", "--short", "HEAD")
    assert len(short_sha) < 12
    wrong_inputs = [
        b"not approved\n",
        f"install {short_sha}\n".encode(),
        b"\n",
        f"install {head12}\n".encode(),
        f"install {head39}\n".encode(),
        f"install {head.upper()}\n".encode(),
        f"install {head} \n".encode(),
        f"install  {head}\n".encode(),
        f"{head}\n".encode(),
    ]

    for feed in wrong_inputs:
        result = run_install_pty(repo, tmp_path, feed=feed)

        assert result.returncode == 1, result.stdout + result.stderr
        assert "Compare the commit id" in result.stderr
        assert "confirmation did not match; installation aborted" in result.stderr
        assert not (tmp_path / "root").exists()


def test_install_correct_confirmation_hits_seam_stop_r2c(tmp_path):
    repo = make_install_repo(tmp_path)
    head_full = git_out(repo, "rev-parse", "HEAD")

    # the second line answers the Claude Code guard question: the
    # empty line is the default, no
    result = run_install_pty(
        repo, tmp_path, feed=f"install {head_full}\n\n".encode()
    )

    assert result.returncode == 2, result.stdout + result.stderr
    assert "test seam" in result.stderr
    assert not (tmp_path / "root").exists()


def test_install_real_run_shows_escaped_author_and_subject_r2c(tmp_path):
    repo = make_install_repo(tmp_path)
    subject = "setup \x1b[31mred\x1b[0m subject"
    author = "Evil \x1b]0;pwn\x07 Author <evil@example.test>"
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "commit",
            "-q",
            "--allow-empty",
            "--amend",
            f"--author={author}",
            "-m",
            subject,
        ],
        check=True,
    )

    rc, merged = run_install_pty_merged(repo, tmp_path)

    assert rc == 1
    assert b"\x1b" not in merged
    assert b"Evil \\x1b]0;pwn\\x07 Author" in merged
    assert b"\\x1b[31mred\\x1b[0m subject" in merged


def test_install_post_confirmation_text_never_uses_repo_r2c():
	source = INSTALL.read_text()
	# The last occurrence of confirm_install is the call inside main, so
	# the tail is everything the script runs after the confirmation.
	_, _, tail = source.rpartition("confirm_install")
	assert tail, "the confirm_install call was not found in main"
	# REPO in any form ($REPO, ${REPO}, "${REPO}") must be gone; word
	# boundaries keep REPOSITORY-like names out of the match.
	assert not re.search(r"\bREPO\b", tail)
	assert "git_as_invoking_user" not in tail
	assert "HERE" not in tail
	# main delegates everything after the prompt to perform_install (shared
	# with --from-snapshot), which calls install_code_root.
	assert "perform_install" in tail
	assert "install_code_root" in bash_function_text("perform_install")
	# Everything copied after the prompt comes from the verified snapshot,
	# and now lives in install_code_root rather than directly in main.
	body = bash_function_text("install_code_root")
	assert '"$SNAP/scripts"' in body
	assert '"$SNAP/mcp"' in body
	assert '"$SNAP/SKILL.md"' in body
	assert not re.search(r"\bREPO\b", body)
	assert "git_as_invoking_user" not in body
	assert "HERE" not in body


def snapshot_base_dir_call(env):
	result = subprocess.run(
		["bash", "-c", "source scripts/newton-install; snapshot_base_dir"],
		cwd=str(ROOT),
		capture_output=True,
		timeout=10,
		env=env,
	)
	assert result.returncode == 0, result.stderr
	return result.stdout


def test_snapshot_base_dir_production_ignores_tmpdir_r2c2():
	env = dict(os.environ, INSTALL_ROOT="", TMPDIR="/somewhere")
	assert snapshot_base_dir_call(env) == b"/var/tmp\n"


def test_snapshot_base_dir_seam_honours_tmpdir_r2c2():
	env = dict(os.environ, INSTALL_ROOT="/fake-root", TMPDIR="/somewhere")
	assert snapshot_base_dir_call(env) == b"/somewhere\n"


def test_snapshot_base_dir_seam_without_tmpdir_r2c2():
	env = dict(os.environ, INSTALL_ROOT="/fake-root")
	env.pop("TMPDIR", None)
	assert snapshot_base_dir_call(env) == b"/tmp\n"
	assert "$(snapshot_base_dir)" in INSTALL.read_text()


# ---- only trusted system programs run as root  ----


def run_install_source(code, *args, env=None, timeout=30):
    return subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; shift; ' + code,
            "install-source",
            str(INSTALL),
            *map(str, args),
        ],
        text=True,
        capture_output=True,
        env=env,
        timeout=timeout,
    )


def bash_function_text(name):
    source = INSTALL.read_text()
    marker = f"{name}() {{\n"
    assert marker in source
    return source.split(marker, 1)[1].split("\n}\n", 1)[0]


def require_host_root_ownership_view():
    if os.stat("/").st_uid != 0 or os.stat("/usr/bin/python3").st_uid != 0:
        pytest.skip("the sandbox uid map does not expose host root ownership")


def test_require_root_owned_chain_refuses_user_script_f2(tmp_path):
    script = tmp_path / "agent-script"
    script.write_text("#!/bin/sh\nexit 0\n")
    script.chmod(0o700)

    result = run_install_source(
        'require_root_owned_chain "$1" test-program', script
    )

    assert result.returncode != 0
    assert (
        f"ERROR: test-program at {script} is not owned by root; "
        "refusing to run it as root" in result.stderr
    )


def test_require_root_owned_chain_refuses_user_owned_0755_file_f2(tmp_path):
    program = tmp_path / "looks-executable"
    program.write_text("not really a program\n")
    program.chmod(0o755)

    result = run_install_source(
        'require_root_owned_chain "$1" test-program', program
    )

    assert result.returncode != 0
    assert f"test-program at {program} is not owned by root" in result.stderr


def test_require_root_owned_chain_checks_symlink_parent_f2(tmp_path):
    require_host_root_ownership_view()
    link = tmp_path / "python-link"
    link.symlink_to("/usr/bin/python3")

    result = run_install_source(
        'require_root_owned_chain "$1" test-program', link
    )

    assert result.returncode != 0
    assert f"test-program at {tmp_path} is not owned by root" in result.stderr
    assert "/usr/bin/python3 is not owned by root" not in result.stderr


def test_require_root_owned_chain_refuses_group_writable_path_f2(tmp_path):
    unsafe_parent = tmp_path / "group-writable"
    unsafe_parent.mkdir()
    unsafe_parent.chmod(0o775)

    result = run_install_source(
        'require_root_owned_chain "$1" test-program', unsafe_parent
    )

    assert result.returncode != 0
    assert (
        f"ERROR: test-program at {unsafe_parent} is writable by group or other; "
        "refusing to run it as root" in result.stderr
    )


def test_require_root_owned_chain_refuses_missing_path_f2(tmp_path):
    missing = tmp_path / "does-not-exist"

    result = run_install_source(
        'require_root_owned_chain "$1" test-program', missing
    )

    assert result.returncode != 0
    assert (
        f"ERROR: test-program at {missing} is missing; "
        "refusing to run it as root" in result.stderr
    )


@pytest.mark.parametrize("program", ["/usr/bin/python3", "/usr/bin/git"])
def test_require_root_owned_chain_accepts_system_programs_f2(program):
    require_host_root_ownership_view()
    result = run_install_source(
        'require_root_owned_chain "$1" test-program', program
    )

    assert result.returncode == 0, result.stderr


def test_check_root_programs_passes_real_host_program_list_f2():
    require_host_root_ownership_view()
    result = run_install_source("check_root_programs")

    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "shadow",
    ["awk() { :; }", "shopt -s expand_aliases; alias awk=:"],
    ids=["function", "alias"],
)
def test_check_root_programs_rejects_shell_shadow_f2(shadow):
    result = run_install_source(f"{shadow}; check_root_programs")

    assert result.returncode != 0
    assert "ERROR: awk resolves as" in result.stderr
    assert "not an external file" in result.stderr


def test_root_program_list_has_no_dead_entries_f2():
    source = INSTALL.read_text()
    declaration = re.search(r"ROOT_PROGRAMS=\(\n(.*?)\n\)", source, re.DOTALL)
    assert declaration
    entries = shlex.split(declaration.group(1))
    body = source[: declaration.start()] + source[declaration.end() :]
    body = "\n".join(
        line for line in body.splitlines() if not line.lstrip().startswith("#")
    )

    for entry in entries:
        if entry.startswith("/"):
            assert entry in body, f"unused ROOT_PROGRAMS entry: {entry}"
        else:
            assert re.search(
                rf"(?<![A-Za-z0-9_/-]){re.escape(entry)}(?![A-Za-z0-9_/-])",
                body,
            ), f"unused ROOT_PROGRAMS entry: {entry}"


def test_root_program_list_covers_installer_external_commands_f2():
    source = INSTALL.read_text()
    declaration = re.search(r"ROOT_PROGRAMS=\(\n(.*?)\n\)", source, re.DOTALL)
    assert declaration
    assert set(shlex.split(declaration.group(1))) == {
        "awk",
        "cat",
        "chmod",
        "chown",
        "date",
        "dirname",
        "env",
        "find",
        "getent",
        "git",
        "groupadd",
        "head",
        "id",
        "install",
        "mkdir",
        "mktemp",
        "mv",
        "readlink",
        "rm",
        "sha1sum",
        "stat",
        "tar",
        "useradd",
        "wc",
        "/usr/sbin/runuser",
        "/usr/sbin/visudo",
        "/usr/bin/python3",
    }


def test_build_venv_pins_clean_environment_and_pip_commands_f2():
    body = bash_function_text("build_venv")
    compact = " ".join(body.replace("\\\n", " ").split())
    assert (
        'cd "$WORK/pip-cwd.1" || exit 1 env -i '
        'PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root TMPDIR="$WORK/tmp" '
        '"$CODE_ROOT/venv/bin/python" -m pip install '
        '--isolated --no-input --no-cache-dir --require-hashes '
        '--only-binary=:all: --no-deps -r "$SNAP/mcp/requirements.lock"'
        in compact
    )
    assert (
        'cd "$WORK/pip-cwd.2" || exit 1 env -i '
        'PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root TMPDIR="$WORK/tmp" '
        '"$CODE_ROOT/venv/bin/python" -m pip install '
        '--isolated --no-input --no-cache-dir --no-deps '
        '--no-build-isolation "$SNAP/mcp"'
        in compact
    )
    assert (
        'for pip_cwd in "$WORK/pip-cwd.1" "$WORK/pip-cwd.2"; do '
        'install -d -o root -g root -m 0700 "$pip_cwd"'
        in compact
    )


def test_build_venv_uses_only_snapshot_inputs_f2():
    body = bash_function_text("build_venv")

    assert '"$SNAP/mcp/requirements.lock"' in body
    assert '"$SNAP/mcp"' in body
    assert "REPO" not in body
    assert "HERE" not in body


def test_installer_has_no_untrusted_python_or_package_runner_f2():
    source = INSTALL.read_text()
    build_body = bash_function_text("build_venv")
    outside_build = source.replace(build_body, "", 1)
    commands = "\n".join(
        line for line in source.splitlines() if not line.lstrip().startswith("#")
    )
    outside_commands = "\n".join(
        line
        for line in outside_build.splitlines()
        if not line.lstrip().startswith("#")
    )

    assert not re.search(r"(?m)^\s*uv(?:\s|$)", commands)
    assert "command -v uv" not in commands
    assert not re.search(r"(?<!/usr/bin/)python3\s+-m", commands)
    assert "/usr/bin/python3 -I -m venv" in commands
    assert not re.search(r"\bpip\b", outside_commands)


def test_check_root_programs_skipped_under_install_root_f2(tmp_path):
    env = install_test_env(tmp_path)
    code = (
        "check_root_programs() { printf 'CHECK_ROOT_PROGRAMS\\n'; return 91; }; "
        "make_snapshot() { printf 'MAKE_SNAPSHOT\\n'; return 92; }; "
        "main --check"
    )

    result = run_install_source(code, env=env)

    assert result.returncode == 92, result.stdout + result.stderr
    assert result.stdout.splitlines() == ["MAKE_SNAPSHOT"]


def test_check_root_programs_skipped_for_nonroot_check_f2():
    if os.geteuid() == 0:
        pytest.skip("this assertion requires the normal non-root test user")
    env = dict(os.environ, SUDO_USER="agent")
    env.pop("NEWTON_INSTALL_ROOT", None)
    code = (
        "check_root_programs() { printf 'CHECK_ROOT_PROGRAMS\\n'; return 91; }; "
        "make_snapshot() { printf 'MAKE_SNAPSHOT\\n'; return 92; }; "
        "main --check"
    )

    result = run_install_source(code, env=env)

    assert result.returncode == 92, result.stdout + result.stderr
    assert result.stdout.splitlines() == ["MAKE_SNAPSHOT"]


@pytest.mark.parametrize("check_mode", [True, False], ids=["check", "install"])
def test_root_main_checks_programs_before_snapshot_f2(check_mode):
    env = dict(os.environ, SUDO_USER="agent")
    env.pop("NEWTON_INSTALL_ROOT", None)
    code = (
        'source "$1"\n'
        "check_root_programs() { printf 'CHECK_ROOT_PROGRAMS\\n'; return 0; }\n"
        "make_snapshot() { printf 'MAKE_SNAPSHOT\\n'; return 92; }\n"
        f"main {'--check' if check_mode else ''}\n"
    )
    command = rootless_root_command(
        "bash", "-c", code, "root-main", str(INSTALL)
    )
    if check_mode:
        result = subprocess.run(
            command, text=True, capture_output=True, env=env, timeout=30
        )
    else:
        master, slave = pty.openpty()
        try:
            result = subprocess.run(
                command,
                stdin=slave,
                text=True,
                capture_output=True,
                env=env,
                timeout=30,
            )
        finally:
            os.close(slave)
            os.close(master)

    assert result.returncode == 92, result.stdout + result.stderr
    assert result.stdout.splitlines() == ["CHECK_ROOT_PROGRAMS", "MAKE_SNAPSHOT"]


def make_executable(path, text):
    path.write_text(text)
    path.chmod(0o755)


def test_launcher_rejects_arguments_and_wrong_user_and_sets_clean_env(tmp_path):
    fake_id = tmp_path / "id"
    make_executable(
        fake_id,
        "#!/bin/sh\n"
        "if [ \"${2:-}\" = newton ]; then echo 4242; else echo \"${FAKE_UID:-4242}\"; fi\n",
    )
    fake_env = tmp_path / "env"
    make_executable(fake_env, "#!/bin/sh\nprintf '%s\\n' \"$@\"\n")
    launcher = tmp_path / "newton-mcp"
    text = launcher_text().replace("/usr/bin/id", str(fake_id)).replace(
        "/usr/bin/env", str(fake_env)
    )
    make_executable(launcher, text)

    with_arg = run(launcher, "--x")
    assert with_arg.returncode == 2
    assert "arguments are not allowed" in with_arg.stderr

    wrong_env = os.environ.copy()
    wrong_env["FAKE_UID"] = "9999"
    wrong_user = run(launcher, env=wrong_env)
    assert wrong_user.returncode == 1
    assert "must run as user newton" in wrong_user.stderr

    good = run(launcher)
    assert good.returncode == 0
    assert good.stdout.splitlines() == [
        "-i",
        "NEWTON_HOME=/opt/newton",
        "NEWTON_STATE_DIR=/var/lib/newton/state",
        "NEWTON_INVENTORY=/var/lib/newton/devices.toml",
        "OWRT_BACKUP_DIR=/var/lib/newton/state/backups",
        "OWRT_AUDIT_LOG=/var/lib/newton/state/audit.log",
        "HOME=/var/lib/newton",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "/opt/newton/venv/bin/newton-mcp",
    ]


def test_mcp_launcher_passes_owrt_state_envs_and_other_launchers_do_not():
    # the installed MCP server runs scripts/owrt-change.sh, whose
    # $OWRT_BACKUP_DIR and $OWRT_AUDIT_LOG default to
    # $HOME/.local/state/network-agent/. With the launcher's HOME set
    # to /var/lib/newton the defaults would land under
    # /var/lib/newton/.local/state/..., bloating the home tree; the MCP
    # launcher must point both at NEWTON_STATE_DIR=/var/lib/newton/state.
    # The approve and setup launchers never run owrt-change.sh, so they
    # must NOT carry these env lines.
    mcp_text = launcher_text("launcher_tmp")
    approve_text = launcher_text("approve_launcher_tmp")
    setup_text = launcher_text("setup_launcher_tmp")

    assert "OWRT_BACKUP_DIR=/var/lib/newton/state/backups" in mcp_text
    assert "OWRT_AUDIT_LOG=/var/lib/newton/state/audit.log" in mcp_text

    assert "OWRT_BACKUP_DIR" not in approve_text
    assert "OWRT_AUDIT_LOG" not in approve_text

    assert "OWRT_BACKUP_DIR" not in setup_text
    assert "OWRT_AUDIT_LOG" not in setup_text


def test_approve_launcher_requires_one_id_and_preserves_validated_sudo_user(tmp_path):
    fake_id = tmp_path / "id"
    make_executable(
        fake_id,
        "#!/bin/sh\n"
        "if [ \"${2:-}\" = newton ]; then echo 4242; else echo \"${FAKE_UID:-4242}\"; fi\n",
    )
    fake_env = tmp_path / "env"
    make_executable(fake_env, "#!/bin/sh\nprintf '%s\\n' \"$@\"\n")
    launcher = tmp_path / "newton-approve"
    text = launcher_text("approve_launcher_tmp").replace(
        "/usr/bin/id", str(fake_id)
    ).replace("/usr/bin/env", str(fake_env))
    make_executable(launcher, text)

    env = os.environ.copy()
    env["SUDO_USER"] = "labuser"
    good = run(launcher, "0123456789abcdef0123456789abcdef", env=env)
    assert good.returncode == 0, good.stderr
    assert good.stdout.splitlines() == [
        "-i",
        "NEWTON_HOME=/opt/newton",
        "NEWTON_STATE_DIR=/var/lib/newton/state",
        "NEWTON_INVENTORY=/var/lib/newton/devices.toml",
        "HOME=/var/lib/newton",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "SUDO_USER=labuser",
        "/opt/newton/venv/bin/newton-approve",
        "0123456789abcdef0123456789abcdef",
    ]

    assert run(launcher, env=env).returncode == 2
    assert run(launcher, "BAD", env=env).returncode == 2
    bad_env = env.copy()
    bad_env["SUDO_USER"] = "root"
    rejected = run(launcher, "0123456789abcdef0123456789abcdef", env=bad_env)
    assert rejected.returncode == 1
    assert "valid non-root SUDO_USER" in rejected.stderr


@pytest.fixture
def doctor_env(tmp_path):
    fake_root = tmp_path / "root"
    newton_home = fake_root / "var/lib/newton"
    code = fake_root / "opt/newton/package"
    venv = fake_root / "opt/newton/venv"
    launcher = fake_root / "usr/local/bin/newton-mcp"
    approve = fake_root / "usr/local/bin/newton-approve"
    doctor_file = fake_root / "usr/local/bin/newton-doctor"
    setup = fake_root / "usr/local/bin/newton-router-setup"
    vantage_setup = fake_root / "usr/local/bin/newton-vantage-setup"
    enrol = fake_root / "usr/local/bin/newton-enrol"
    ad_setup = fake_root / "usr/local/bin/newton-ad-setup"
    sudoers = fake_root / "etc/sudoers.d/newton-mcp"
    managed_settings = fake_root / "etc/claude-code/managed-settings.json"
    bindir = tmp_path / "bin"
    bindir.mkdir(parents=True)
    newton_home.mkdir(parents=True)
    code.mkdir(parents=True)
    (venv / "bin").mkdir(parents=True)
    launcher.parent.mkdir(parents=True)
    sudoers.parent.mkdir(parents=True)
    managed_settings.parent.mkdir(parents=True)

    inventory = newton_home / "devices.toml"
    inventory.write_text("[devices.real]\nplatform='openwrt'\nhost='192.0.2.2'\nuser='root'\n")
    inventory.chmod(0o000)
    (code / "server.py").write_text("# installed code\n")
    (code / "server.py").chmod(0o444)
    (venv / "bin/python").symlink_to("/usr/bin/python3")
    for path, text in (
        (launcher, "#!/bin/sh\n"),
        (approve, "#!/bin/sh\n"),
        (doctor_file, "#!/bin/sh\n"),
        (setup, "#!/bin/sh\n"),
        (vantage_setup, "#!/bin/sh\n"),
        (enrol, "#!/bin/sh\n"),
        (ad_setup, "#!/bin/sh\n"),
    ):
        path.write_text(text)
        path.chmod(0o555)
    sudoers.write_text(
        'agent ALL=(newton) NOPASSWD: /usr/local/bin/newton-mcp ""\n'
        "agent ALL=(newton) /usr/local/bin/newton-approve\n"
    )
    sudoers.chmod(0o440)
    # the Claude Code managed settings guard the doctor checks
    managed_settings.write_text('{"allowManagedHooksOnly": true}\n')
    managed_settings.chmod(0o644)
    for directory in (
        fake_root / "opt",
        fake_root / "opt/newton",
        code,
        venv,
        venv / "bin",
        fake_root / "usr",
        fake_root / "usr/local",
        launcher.parent,
        fake_root / "var",
        fake_root / "etc",
        sudoers.parent,
        managed_settings.parent,
    ):
        directory.chmod(0o555)

    sudo = bindir / "sudo"
    make_executable(
        sudo,
        """#!/bin/sh
if [ "${1:-}" = -n ] && [ "${2:-}" = -l ]; then
  if [ -n "${DOCTOR_STUB_SUDOL_FAIL:-}" ]; then
    printf '%s\\n' "$DOCTOR_STUB_SUDOL_FAIL" >&2
    exit 1
  fi
  if [ -n "${DOCTOR_STUB_SUDOL:-}" ]; then
    cat "$DOCTOR_STUB_SUDOL"
  else
    printf 'User agent may run the following commands on this host:\\n'
    printf '    (newton) NOPASSWD: /usr/local/bin/newton-mcp ""\\n'
    printf '    (ALL : ALL) ALL\\n'
  fi
  exit 0
fi
case "${DOCTOR_STUB_MODE:-ok}:$*" in
  allow-id:*'/usr/bin/id') exit 0 ;;
  allow-args:*'newton-mcp --x') exit 0 ;;
esac
case "$*" in
  *'/usr/bin/id') exit 1 ;;
  *'newton-mcp --x') exit 1 ;;
esac
case "$*" in
  *'/usr/local/bin/newton-router-setup'*)
    if [ -n "${DOCTOR_STUB_SETUP_ARGS:-}" ]; then
      printf '%s\n' "$@" > "$DOCTOR_STUB_SETUP_ARGS"
    fi
    if [ -n "${DOCTOR_STUB_SETUP_FAIL:-}" ]; then
      printf '%s\n' "$DOCTOR_STUB_SETUP_FAIL" >&2
      exit "${DOCTOR_STUB_SETUP_RC_FAIL:-1}"
    fi
    if [ -n "${DOCTOR_STUB_SETUP_PROMPT:-}" ]; then
      printf '%s' "$DOCTOR_STUB_SETUP_PROMPT" >&2
    fi
    if [ -n "${DOCTOR_STUB_SETUP_REPORT:-}" ]; then
      cat "$DOCTOR_STUB_SETUP_REPORT"
    fi
    exit "${DOCTOR_STUB_SETUP_RC:-0}"
    ;;
esac
[ "${DOCTOR_STUB_MODE:-ok}" = mcp-fail ] && exit 1
payload=$(cat)
case "$payload" in
  *'"id":1'*) printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fake","version":"1"}}}' ;;
esac
case "$payload" in
  *newton_list_devices*)
    if [ "${DOCTOR_STUB_MODE:-ok}" = env-leak ]; then
      value=$(cat "$NEWTON_INVENTORY")
    else
      value='real'
    fi
    printf '{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"%s"}]}}\n' "$value"
    ;;
esac
""",
    )
    ssh = bindir / "ssh"
    make_executable(
        ssh,
        '#!/bin/sh\n'
        'if [ -n "${DOCTOR_STUB_SSH_ARGS:-}" ]; then\n'
        "printf '%s\\n' \"$@\" > \"$DOCTOR_STUB_SSH_ARGS\"\n"
        'fi\n'
        'case "$*" in\n'
        '  *failhost*)\n'
        '    err=${DOCTOR_STUB_SSH_ERR_FAIL:-}\n'
        '    rc=${DOCTOR_STUB_SSH_RC_FAIL:-0}\n'
        '    ;;\n'
        '  *)\n'
        '    err=${DOCTOR_STUB_SSH_ERR:-root@router: Permission denied (publickey).}\n'
        '    rc=${DOCTOR_STUB_SSH_RC:-255}\n'
        '    ;;\n'
        'esac\n'
        'if [ -n "$err" ]; then printf \'%s\\n\' "$err" >&2; fi\n'
        'exit "$rc"\n',
    )

    env = os.environ.copy()
    agent_home = tmp_path / "agent-home"
    agent_home.mkdir()
    env.update(
        NEWTON_DOCTOR_ROOT=str(fake_root),
        NEWTON_DOCTOR_HOLD="0",
        NEWTON_DOCTOR_AGENT_UID=str(os.getuid() + 1),
        NEWTON_DOCTOR_ROOT_UID=str(os.getuid()),
        NEWTON_DOCTOR_GROUPS="",
        PATH=f"{bindir}:{env['PATH']}",
        DOCTOR_STUB_MODE="ok",
        HOME=str(agent_home),
    )
    return {
        "env": env,
        "inventory": inventory,
        "code": code,
        "launcher": launcher,
        "approve": approve,
        "doctor_file": doctor_file,
        "setup": setup,
        "vantage_setup": vantage_setup,
        "enrol": enrol,
        "ad_setup": ad_setup,
        "sudoers": sudoers,
        "managed_settings": managed_settings,
        "venv": venv,
        "root": fake_root,
        "tmp": tmp_path,
    }


def test_doctor_all_pass_paths(doctor_env):
    result = run(
        DOCTOR,
        "--router",
        "root@192.0.2.1",
        env=doctor_env["env"],
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines() == [
        "INFO test seams in use: NEWTON_DOCTOR_AGENT_UID NEWTON_DOCTOR_GROUPS "
        "NEWTON_DOCTOR_HOLD NEWTON_DOCTOR_ROOT NEWTON_DOCTOR_ROOT_UID "
        "(repo copy; run /usr/local/bin/newton-doctor for the host report)",
        "INFO agent-readable credentials: none (lab devices only)",
        "PASS creds-unreadable",
        "PASS restricted-key-unreadable: no keys directory this account can see",
        "PASS agent-has-no-root-path",
        "PASS sudo-only-mcp",
        "PASS sudo-mcp-works",
        "PASS env-ignored",
        "PASS claude-debug-logging",
        "PASS managed-settings-guard",
        "PASS code-not-writable",
        "PASS router-unreachable[root@192.0.2.1]",
        "INFO router-line check skipped (no --device given; pass --device NAME to prove the restricted router line)",
    ]


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        ("creds", "FAIL creds-unreadable:"),
        ("allow-id", "FAIL sudo-only-mcp:"),
        ("allow-args", "FAIL sudo-only-mcp:"),
        ("mcp-fail", "FAIL sudo-mcp-works:"),
        ("env-leak", "FAIL env-ignored:"),
        ("writable", "FAIL code-not-writable:"),
        ("ssh-works", "FAIL router-unreachable[root@192.0.2.1]:"),
    ],
)
def test_doctor_fail_paths(doctor_env, failure, expected):
    env = doctor_env["env"]
    if failure == "creds":
        doctor_env["inventory"].chmod(0o644)
    elif failure == "writable":
        doctor_env["code"].chmod(0o755)
    elif failure == "ssh-works":
        env["DOCTOR_STUB_SSH_RC"] = "0"
    else:
        env["DOCTOR_STUB_MODE"] = failure

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=env)

    assert result.returncode == 1
    assert expected in result.stdout


def test_doctor_reports_agent_readable_credentials_as_information(doctor_env):
    config = Path(doctor_env["env"]["HOME"]) / ".config/newton"
    config.mkdir(parents=True)
    password = config / "router.pw"
    inventory = config / "devices.toml"
    ignored = config / "notes.txt"
    password.write_text("lab-password\n")
    inventory.write_text("[devices.lab]\n")
    ignored.write_text("not a credential filename\n")

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 0, result.stdout + result.stderr
    info = result.stdout.splitlines()[1]
    assert info.startswith("INFO agent-readable credentials:")
    assert str(password) in info
    assert str(inventory) in info
    assert str(ignored) not in info
    assert info.endswith("(lab devices only)")


# ---- agent-has-no-root-path ----

# Reconstructed from the sudoers(5) man page and the agent-host evidence; the
# parser must stay tolerant of small layout differences.
AGENT_SUDOL = (
    "Matching Defaults entries for labuser on the agent host:\n"
    "    env_reset, mail_badpass, "
    "secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin, "
    "use_pty\n"
    "\n"
    "User labuser may run the following commands on the agent host:\n"
    "    (ALL : ALL) ALL\n"
    "    (ALL) NOPASSWD: /usr/bin/apt-get install *, "
    "/usr/bin/systemctl enable *, /usr/bin/systemctl start *, "
    "/usr/bin/systemctl restart *, /usr/bin/systemctl stop *, "
    "/usr/bin/ufw, /usr/bin/fail2ban-client\n"
    '    (newton) NOPASSWD: /usr/local/bin/newton-mcp ""\n'
    "    (newton) /usr/local/bin/newton-approve\n"
)

AGENT_USER = pwd.getpwuid(os.getuid()).pw_name


def write_sudol(doctor_env, tmp_path, text):
    sudol = tmp_path / "sudo-l-output"
    sudol.write_text(text)
    doctor_env["env"]["DOCTOR_STUB_SUDOL"] = str(sudol)


def test_doctor_flags_agent_sudo_rules_f4(doctor_env, tmp_path):
    write_sudol(doctor_env, tmp_path, AGENT_SUDOL)

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 1, result.stdout + result.stderr
    assert (
        "FAIL agent-has-no-root-path: sudo NOPASSWD rule runs as root: "
        "/usr/bin/apt-get install * (maintainer scripts run as root)"
        in result.stdout
    )
    assert (
        "FAIL agent-has-no-root-path: sudo NOPASSWD rule runs as root: "
        "/usr/bin/systemctl enable * (unit files run as root)"
        in result.stdout
    )
    assert (
        "FAIL agent-has-no-root-path: sudo NOPASSWD rule runs as root: "
        "/usr/bin/systemctl stop * (unit files run as root)"
        in result.stdout
    )
    assert (
        "FAIL agent-has-no-root-path: sudo NOPASSWD rule runs as root: "
        "/usr/bin/ufw (rewrites the host firewall)"
        in result.stdout
    )
    assert (
        "FAIL agent-has-no-root-path: sudo NOPASSWD rule runs as root: "
        "/usr/bin/fail2ban-client (actions run as root)"
        in result.stdout
    )
    # The password-required rule, the sanctioned mcp line and the
    # password-required approve rule are not root paths.
    assert "(ALL : ALL) ALL" not in result.stdout
    assert "runs as newton" not in result.stdout
    assert "newton-approve" not in result.stdout


def test_doctor_flags_passwordless_all_f4(doctor_env, tmp_path):
    write_sudol(
        doctor_env,
        tmp_path,
        "User agent may run the following commands on this host:\n"
        "    (ALL) NOPASSWD: ALL\n",
    )

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 1, result.stdout + result.stderr
    assert (
        "FAIL agent-has-no-root-path: sudo NOPASSWD rule runs as root: "
        "ALL (unrestricted root)" in result.stdout
    )


def test_doctor_defaults_authenticate_makes_every_rule_passwordless_f4(
    doctor_env, tmp_path
):
    write_sudol(
        doctor_env,
        tmp_path,
        "Matching Defaults entries for agent on this host:\n"
        "    !authenticate, env_reset\n"
        "User agent may run the following commands on this host:\n"
        "    (root) /usr/bin/id\n",
    )

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 1, result.stdout + result.stderr
    assert (
        "FAIL agent-has-no-root-path: sudo defaults contain !authenticate: "
        "every sudo rule is treated as passwordless" in result.stdout
    )
    assert (
        "FAIL agent-has-no-root-path: sudo NOPASSWD rule runs as root: "
        "/usr/bin/id" in result.stdout
    )


def test_doctor_flags_newton_runas_all_f4(doctor_env, tmp_path):
    write_sudol(
        doctor_env,
        tmp_path,
        "User agent may run the following commands on this host:\n"
        "    (newton) NOPASSWD: ALL\n",
    )

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 1, result.stdout + result.stderr
    assert (
        "FAIL agent-has-no-root-path: sudo NOPASSWD rule runs as newton "
        "(the credential owner): ALL" in result.stdout
    )


def test_doctor_flags_extra_command_on_newton_line_f4(doctor_env, tmp_path):
    write_sudol(
        doctor_env,
        tmp_path,
        "User agent may run the following commands on this host:\n"
        '    (newton) NOPASSWD: /usr/local/bin/newton-mcp "", /usr/bin/id\n',
    )

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 1, result.stdout + result.stderr
    newton_lines = [
        line
        for line in result.stdout.splitlines()
        if "runs as newton" in line
    ]
    assert newton_lines == [
        "FAIL agent-has-no-root-path: sudo NOPASSWD rule runs as newton "
        '(the credential owner): /usr/local/bin/newton-mcp ""',
        "FAIL agent-has-no-root-path: sudo NOPASSWD rule runs as newton "
        "(the credential owner): /usr/bin/id",
    ]


def test_doctor_accepts_exact_mcp_line_and_password_rules_f4(doctor_env):
    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS agent-has-no-root-path" in result.stdout


def test_doctor_fails_closed_when_sudo_l_is_unreadable_f4(doctor_env):
    env = doctor_env["env"].copy()
    env["DOCTOR_STUB_SUDOL_FAIL"] = "sudo: a password is required"

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=env)

    assert result.returncode == 1, result.stdout + result.stderr
    assert (
        "FAIL agent-has-no-root-path: cannot read sudo rules with 'sudo -n -l' "
        "(sudo: a password is required); "
        "cannot prove there is no passwordless root path" in result.stdout
    )


def test_doctor_accepts_may_not_run_sudo_f4(doctor_env):
    env = doctor_env["env"].copy()
    env["DOCTOR_STUB_SUDOL_FAIL"] = "agent is not allowed to run sudo on this host."

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=env)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS agent-has-no-root-path" in result.stdout


def test_doctor_fails_closed_on_unparsed_nopasswd_rule_f4(doctor_env, tmp_path):
    write_sudol(
        doctor_env,
        tmp_path,
        "User agent may run the following commands on this host:\n"
        "    (ALL) NOPASSWD:\n",
    )

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 1, result.stdout + result.stderr
    assert (
        "FAIL agent-has-no-root-path: unparsed sudo rule containing NOPASSWD: "
        "(ALL) NOPASSWD:" in result.stdout
    )


ROOT_GROUPS = [
    ("docker", "mount / and run as root"),
    ("lxd", "privileged container"),
    ("incus", "privileged container"),
    ("libvirt", "define or run VMs with host devices"),
    ("kvm", "define or run VMs with host devices"),
    ("disk", "raw read/write of the block devices"),
]


@pytest.mark.parametrize(("group", "why"), ROOT_GROUPS)
def test_doctor_flags_root_equivalent_group_f4(doctor_env, group, why):
    env = doctor_env["env"].copy()
    env["NEWTON_DOCTOR_GROUPS"] = group

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=env)

    assert result.returncode == 1, result.stdout + result.stderr
    assert (
        f"FAIL agent-has-no-root-path: {AGENT_USER} is in group {group}, "
        f"which gives root ({why})" in result.stdout
    )


def test_doctor_accepts_docker_users_group_f4(doctor_env):
    env = doctor_env["env"].copy()
    env["NEWTON_DOCTOR_GROUPS"] = "docker-users"

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=env)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS agent-has-no-root-path" in result.stdout


def make_root_socket(doctor_env, name, mode):
    var = doctor_env["root"] / "var"
    var.chmod(0o755)
    run_dir = var / "run"
    run_dir.mkdir()
    sock_path = run_dir / name
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(sock_path))
    server.listen(1)
    os.chmod(sock_path, mode)
    var.chmod(0o555)
    return server, sock_path


def test_doctor_flags_writable_docker_socket_f4(doctor_env):
    server, sock_path = make_root_socket(doctor_env, "docker.sock", 0o666)
    try:
        result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])
    finally:
        server.close()

    assert result.returncode == 1, result.stdout + result.stderr
    assert (
        f"FAIL agent-has-no-root-path: {AGENT_USER} can write {sock_path} "
        "(the docker daemon runs as root)" in result.stdout
    )


def test_doctor_accepts_unwritable_docker_socket_f4(doctor_env):
    server, _sock_path = make_root_socket(doctor_env, "docker.sock", 0o444)
    try:
        result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])
    finally:
        server.close()

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS agent-has-no-root-path" in result.stdout


# ---- review repairs ----

def test_doctor_installed_copy_forces_path_before_running_id_r1c():
    lines = DOCTOR.read_text().splitlines()
    path_at = next(
        i for i, line in enumerate(lines)
        if line.strip() == "PATH=/usr/sbin:/usr/bin:/sbin:/bin"
    )
    uid_at = next(
        i for i, line in enumerate(lines)
        if line.strip() == "AGENT_UID=$(id -u)"
    )
    assert uid_at > path_at, "the installed copy must force PATH before id runs"


def test_doctor_escapes_hostile_paths_in_fail_messages_r1c(doctor_env):
    venv = doctor_env["venv"]
    venv.chmod(0o755)
    rogue = venv / "rogue\x1bbad.py"
    rogue.write_text("import os\n")
    venv.chmod(0o555)

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 1, result.stdout + result.stderr
    assert "\x1b" not in result.stdout
    assert "rogue\\x1bbad.py" in result.stdout


# ---- review repairs ----

@pytest.mark.parametrize(
    "rule",
    [
        "(ALL, !root) NOPASSWD: ALL",
        "(root, www-data) NOPASSWD: /usr/bin/id",
        "(ALL:ALL) NOPASSWD: ALL",
        "(www-data, root) NOPASSWD: /usr/bin/id",
    ],
)
def test_doctor_flags_root_runas_tokenisation_r1d(doctor_env, tmp_path, rule):
    write_sudol(
        doctor_env,
        tmp_path,
        "User agent may run the following commands on this host:\n"
        f"    {rule}\n",
    )

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 1, result.stdout + result.stderr
    expected_command = "ALL (unrestricted root)" if rule.endswith("ALL") else "/usr/bin/id"
    assert (
        "FAIL agent-has-no-root-path: sudo NOPASSWD rule runs as root: "
        f"{expected_command}" in result.stdout
    )


def test_doctor_negated_root_without_all_is_not_root_r1d(doctor_env, tmp_path):
    write_sudol(
        doctor_env,
        tmp_path,
        "User agent may run the following commands on this host:\n"
        "    (!root, !www-data) NOPASSWD: /usr/bin/id\n",
    )

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS agent-has-no-root-path" in result.stdout


@pytest.mark.parametrize(
    "rule",
    [
        "NOPASSWD apt-get install everything",
        "(root) NOPASSWD /usr/bin/id",
    ],
)
def test_doctor_fails_closed_on_nopasswd_without_tag_token_r1d(
    doctor_env, tmp_path, rule
):
    write_sudol(
        doctor_env,
        tmp_path,
        "User agent may run the following commands on this host:\n"
        f"    {rule}\n",
    )

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 1, result.stdout + result.stderr
    assert (
        "FAIL agent-has-no-root-path: unparsed sudo rule containing NOPASSWD: "
        f"{rule}" in result.stdout
    )


# ---- code-not-writable covers the whole chain ----

def test_doctor_flags_writable_parent_directory_f7(doctor_env):
    root = doctor_env["root"]
    (root / "opt").chmod(0o755)

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 1, result.stdout + result.stderr
    assert f"FAIL code-not-writable: agent can write {root}/opt" in result.stdout


def test_doctor_flags_symlinked_launcher_to_writable_file_f7(doctor_env):
    launcher = doctor_env["launcher"]
    target = doctor_env["tmp"] / "writable-target"
    target.write_text("#!/bin/sh\n")
    launcher.parent.chmod(0o755)
    launcher.unlink()
    launcher.symlink_to(target)
    launcher.parent.chmod(0o555)

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 1, result.stdout + result.stderr
    assert (
        f"FAIL code-not-writable: symlink {launcher} -> {target}: "
        f"target path {target} is writable" in result.stdout
    )


def test_doctor_flags_symlinked_parent_to_writable_directory_f7(doctor_env):
    root = doctor_env["root"]
    real = doctor_env["tmp"] / "writable-opt"
    for sub in ("newton/venv/bin", "newton/package"):
        (real / sub).mkdir(parents=True)
    (real / "newton/venv/bin/python").symlink_to("/usr/bin/python3")
    for sub in ("newton", "newton/venv", "newton/venv/bin", "newton/package"):
        (real / sub).chmod(0o555)
    (root / "opt").chmod(0o755)
    (root / "opt").rename(doctor_env["tmp"] / "opt-real")
    (root / "opt").symlink_to(real, target_is_directory=True)

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 1, result.stdout + result.stderr
    assert (
        f"FAIL code-not-writable: symlink {root}/opt -> {real}: "
        f"target path {real} is writable" in result.stdout
    )


def test_doctor_flags_agent_owned_item_f7(doctor_env):
    env = doctor_env["env"].copy()
    env["NEWTON_DOCTOR_AGENT_UID"] = str(os.getuid())

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=env)

    assert result.returncode == 1, result.stdout + result.stderr
    assert (
        f"FAIL code-not-writable: agent owns {doctor_env['root']}/opt "
        "(an owner can chmod it)" in result.stdout
    )


@pytest.mark.parametrize(
    "key",
    ["approve", "doctor_file", "sudoers", "setup", "vantage_setup", "enrol", "ad_setup"],
)
def test_doctor_flags_writable_installed_files_f7(doctor_env, key):
    path = doctor_env[key]
    path.chmod(0o644)

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 1, result.stdout + result.stderr
    assert f"FAIL code-not-writable: agent can write {path}" in result.stdout


def test_doctor_flags_missing_approve_launcher_f7(doctor_env):
    approve = doctor_env["approve"]
    approve.parent.chmod(0o755)
    approve.unlink()
    approve.parent.chmod(0o555)

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 1, result.stdout + result.stderr
    assert (
        f"FAIL code-not-writable: installed code or launcher is missing: {approve}"
        in result.stdout
    )


@pytest.mark.parametrize(
    "key",
    [
        pytest.param("setup", id="router-setup"),
        pytest.param("vantage_setup", id="vantage-setup"),
        pytest.param("enrol", id="enrol"),
        pytest.param("ad_setup", id="ad-setup"),
    ],
)
def test_doctor_flags_missing_enrol_launcher_f7(doctor_env, key):
    path = doctor_env[key]
    path.parent.chmod(0o755)
    path.unlink()
    path.parent.chmod(0o555)

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 1, result.stdout + result.stderr
    assert (
        f"FAIL code-not-writable: installed code or launcher is missing: {path}"
        in result.stdout
    )


def test_doctor_flags_writable_file_inside_venv_f7(doctor_env):
    venv = doctor_env["venv"]
    venv.chmod(0o755)
    rogue = venv / "rogue.py"
    rogue.write_text("import os\n")
    venv.chmod(0o555)

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 1, result.stdout + result.stderr
    assert f"FAIL code-not-writable: agent can write {rogue}" in result.stdout


def test_doctor_lists_venv_hits_with_and_more_line_f7(doctor_env):
    venv = doctor_env["venv"]
    venv.chmod(0o755)
    for index in range(25):
        (venv / f"rogue{index}.py").write_text("import os\n")
    venv.chmod(0o555)

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 1, result.stdout + result.stderr
    writable_lines = [
        line
        for line in result.stdout.splitlines()
        if line.startswith("FAIL code-not-writable: agent can write ")
    ]
    assert len(writable_lines) == 20
    assert "FAIL code-not-writable: ... and 5 more" in result.stdout


# ---- the router check classifies ssh results instead of trusting any failure ----

ROUTER = "root@doctor-test.invalid"
AUTH_DENIED_ERR = "root@doctor-test.invalid: Permission denied (publickey)."
AUTH_SUCCEEDED = "FAIL router-unreachable[%s]: SSH authentication succeeded from the agent user"


@pytest.mark.parametrize(
    ("ssh_rc", "ssh_err", "expected_line", "expected_rc"),
    [
        pytest.param(255, AUTH_DENIED_ERR, "PASS router-unreachable[", 0, id="denied"),
        pytest.param(0, AUTH_DENIED_ERR, AUTH_SUCCEEDED % ROUTER, 1, id="auth-success"),
        pytest.param(1, "remote command exited 1", AUTH_SUCCEEDED % ROUTER, 1, id="remote-exit-1"),
        pytest.param(124, "", "INCONCLUSIVE router-unreachable[%s]: timeout" % ROUTER, 3, id="timeout"),
        pytest.param(
            125,
            "timeout: failed to run ssh",
            "INCONCLUSIVE router-unreachable[%s]: unexpected ssh exit status 125" % ROUTER,
            3,
            id="timeout-failed-125",
        ),
        pytest.param(
            126,
            "ssh: permission denied trying to execute",
            "INCONCLUSIVE router-unreachable[%s]: unexpected ssh exit status 126" % ROUTER,
            3,
            id="not-executable-126",
        ),
        pytest.param(
            127,
            "ssh: command not found",
            "INCONCLUSIVE router-unreachable[%s]: unexpected ssh exit status 127" % ROUTER,
            3,
            id="not-found-127",
        ),
        pytest.param(
            128,
            "",
            "INCONCLUSIVE router-unreachable[%s]: unexpected ssh exit status 128" % ROUTER,
            3,
            id="exit-128-never-passes",
        ),
        pytest.param(
            130,
            "",
            "INCONCLUSIVE router-unreachable[%s]: unexpected ssh exit status 130" % ROUTER,
            3,
            id="killed-by-signal-130",
        ),
        pytest.param(
            255,
            "root@doctor-test.invalid: Permission denied",
            "INCONCLUSIVE router-unreachable[%s]: unrecognised ssh result: "
            "root@doctor-test.invalid: Permission denied" % ROUTER,
            3,
            id="denial-words-without-ssh-denial-format",
        ),
        pytest.param(
            255,
            "Host key verification failed.",
            "INCONCLUSIVE router-unreachable[%s]: host key unknown or changed" % ROUTER,
            3,
            id="host-key-verification",
        ),
        pytest.param(
            255,
            "REMOTE HOST IDENTIFICATION HAS CHANGED!",
            "INCONCLUSIVE router-unreachable[%s]: host key unknown or changed" % ROUTER,
            3,
            id="host-key-changed",
        ),
        pytest.param(
            255,
            "Offending ECDSA key in /home/agent/.ssh/known_hosts:3",
            "INCONCLUSIVE router-unreachable[%s]: host key unknown or changed" % ROUTER,
            3,
            id="offending-key",
        ),
        pytest.param(
            255,
            "No RSA host key is known for doctor-test.invalid",
            "INCONCLUSIVE router-unreachable[%s]: host key unknown or changed" % ROUTER,
            3,
            id="no-host-key-known",
        ),
        pytest.param(
            255,
            "ssh: connect to host doctor-test.invalid port 22: Connection refused",
            "INCONCLUSIVE router-unreachable[%s]: refused" % ROUTER,
            3,
            id="refused",
        ),
        pytest.param(
            255,
            "ssh: Could not resolve hostname doctor-test.invalid",
            "INCONCLUSIVE router-unreachable[%s]: dns" % ROUTER,
            3,
            id="dns-resolve",
        ),
        pytest.param(
            255,
            "ssh: doctor-test.invalid: Name or service not known",
            "INCONCLUSIVE router-unreachable[%s]: dns" % ROUTER,
            3,
            id="dns-name-or-service",
        ),
        pytest.param(
            255,
            "ssh: Temporary failure in name resolution",
            "INCONCLUSIVE router-unreachable[%s]: dns" % ROUTER,
            3,
            id="dns-temporary",
        ),
        pytest.param(
            255,
            "ssh: connect to host doctor-test.invalid port 22: No route to host",
            "INCONCLUSIVE router-unreachable[%s]: no route" % ROUTER,
            3,
            id="no-route",
        ),
        pytest.param(
            255,
            "ssh: connect to host doctor-test.invalid port 22: Network is unreachable",
            "INCONCLUSIVE router-unreachable[%s]: no route" % ROUTER,
            3,
            id="network-unreachable",
        ),
        pytest.param(
            255,
            "weird \x1b[31m ssh failure",
            "INCONCLUSIVE router-unreachable[%s]: unrecognised ssh result: "
            "weird \\x1b[31m ssh failure" % ROUTER,
            3,
            id="unrecognised-escaped",
        ),
    ],
)
def test_doctor_router_classification_f5(doctor_env, ssh_rc, ssh_err, expected_line, expected_rc):
    env = doctor_env["env"].copy()
    env["DOCTOR_STUB_SSH_RC"] = str(ssh_rc)
    env["DOCTOR_STUB_SSH_ERR"] = ssh_err

    result = run(DOCTOR, "--router", ROUTER, env=env)

    assert result.returncode == expected_rc, result.stdout + result.stderr
    assert expected_line in result.stdout


def test_doctor_router_inconclusive_plus_fail_exits_1_f5(doctor_env):
    env = doctor_env["env"].copy()
    env["DOCTOR_STUB_SSH_ERR"] = (
        "ssh: connect to host doctor-test.invalid port 22: Connection refused"
    )
    env["DOCTOR_STUB_SSH_RC"] = "255"

    result = run(DOCTOR, "--router", ROUTER, "--router", "root@failhost.test", env=env)

    assert result.returncode == 1, result.stdout + result.stderr
    assert "INCONCLUSIVE router-unreachable[%s]: refused" % ROUTER in result.stdout
    assert "FAIL router-unreachable[root@failhost.test]: SSH authentication succeeded" in result.stdout


def test_doctor_without_router_errors_and_runs_no_check_f5(doctor_env):
    result = run(DOCTOR, env=doctor_env["env"])

    assert result.returncode == 2
    assert (
        "ERROR: at least one --router user@host is required "
        "(the router check proves the agent user cannot log in)" in result.stderr
    )
    assert result.stdout == ""


# ---- the installed copy ignores every test seam ----


def reference_installed_doctor_text():
    lines = DOCTOR.read_text().splitlines(keepends=True)
    assert lines[0].startswith("#!")
    lines[0] = "#!/bin/bash -p\n"
    replaced = 0
    for i, line in enumerate(lines):
        if line.startswith("NEWTON_DOCTOR_SEAMS=1"):
            lines[i] = "NEWTON_DOCTOR_SEAMS=0  # installed copy: test seams disabled\n"
            replaced += 1
    assert replaced == 1, "exactly one NEWTON_DOCTOR_SEAMS=1 marker line expected"
    return "".join(lines)


def installed_doctor_copy(tmp_path):
    installed = tmp_path / "newton-doctor-installed"
    result = subprocess.run(
        [
            "bash",
            "-c",
            'source scripts/newton-install; render_installed_doctor "$1" "$2"',
            "render_installed_doctor",
            str(DOCTOR),
            str(installed),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    installed.chmod(0o755)
    return installed


def installed_doctor_unshare(tmp_path, installed, seam_env):
    """Run the installed copy hermetically: a user+mount namespace with a
    tmpfs over /var/lib and /opt, and bind-mounted sudo/ssh stubs over the
    absolute system paths /usr/bin/sudo and /usr/bin/ssh."""
    unshare = shutil.which("unshare")
    if unshare is None:
        pytest.skip("unshare is unavailable")
    probe = subprocess.run(
        [unshare, "-Urm", "true"], text=True, capture_output=True, timeout=10
    )
    if probe.returncode != 0:
        reason = probe.stderr.strip() or f"unshare exited {probe.returncode}"
        pytest.skip(f"unshare -Urm is unavailable: {reason}")
    for target in ("/usr/bin/sudo", "/usr/bin/ssh"):
        if not Path(target).exists():
            pytest.skip(f"{target} is missing; cannot bind-mount a stub over it")

    sudo_call_log = tmp_path / "system-sudo-calls"
    sudo_env_log = tmp_path / "sudo-env-log"
    ssh_env_log = tmp_path / "ssh-env-log"
    seam_sudo_called = tmp_path / "seam-sudo-called"
    seam_ssh_called = tmp_path / "seam-ssh-called"
    bind_sudo = tmp_path / "bind-sudo"
    make_executable(
        bind_sudo,
        "#!/bin/sh\n"
        f"env >> {sudo_env_log}\n"
        f'printf \'%s\\n\' "$*" >> {sudo_call_log}\n'
        'if [ "${1:-}" = -n ] && [ "${2:-}" = -l ]; then\n'
        '  printf \'%s is not allowed to run sudo on this host.\\n\' "$(id -un)" >&2\n'
        "  exit 1\n"
        "fi\n"
        "exit 1\n",
    )
    bind_ssh = tmp_path / "bind-ssh"
    make_executable(
        bind_ssh,
        "#!/bin/sh\n"
        f"env >> {ssh_env_log}\n"
        "printf 'root@doctor-test.invalid: Permission denied (publickey).\\n' >&2\n"
        "exit 255\n",
    )
    seam_sudo = tmp_path / "seam-sudo"
    make_executable(seam_sudo, f"#!/bin/sh\ntouch {seam_sudo_called}\nexit 1\n")
    seam_ssh = tmp_path / "seam-ssh"
    make_executable(seam_ssh, f"#!/bin/sh\ntouch {seam_ssh_called}\nexit 1\n")
    home = tmp_path / "ns-home"
    home.mkdir()

    env = os.environ.copy()
    env.update(seam_env)
    env.update(
        NEWTON_DOCTOR_SUDO=str(seam_sudo),
        NEWTON_DOCTOR_SSH=str(seam_ssh),
        STUB_SUDO=str(bind_sudo),
        STUB_SSH=str(bind_ssh),
        INSTALLED=str(installed),
        HOME=str(home),
    )
    command = [
        unshare,
        "-Urm",
        "--",
        "bash",
        "-c",
        "mkdir -p /var/lib /opt && "
        'mount -t tmpfs tmpfs /var/lib && '
        'mount -t tmpfs tmpfs /opt && '
        'mount --bind "$STUB_SUDO" /usr/bin/sudo && '
        'mount --bind "$STUB_SSH" /usr/bin/ssh && '
        'exec "$INSTALLED" --router root@doctor-test.invalid',
    ]
    return command, env, {
        "sudo_call_log": sudo_call_log,
        "sudo_env_log": sudo_env_log,
        "ssh_env_log": ssh_env_log,
        "seam_sudo_called": seam_sudo_called,
        "seam_ssh_called": seam_ssh_called,
        "seam_sudo": seam_sudo,
        "seam_ssh": seam_ssh,
    }


def run_installed_copy_unshared(tmp_path, installed, seam_env):
    command, env, artifacts = installed_doctor_unshare(tmp_path, installed, seam_env)
    result = subprocess.run(
        command, env=env, text=True, capture_output=True, timeout=60
    )
    # The doctor runs as mapped root inside the namespace, so extra FAIL
    # lines are expected; this only proves the script really ran there.
    assert "newton-doctor must run as the agent user" in result.stdout, (
        result.stdout + result.stderr
    )
    return result, artifacts


def test_doctor_installed_copy_ignores_test_seams_f6(doctor_env, tmp_path):
    installed = installed_doctor_copy(tmp_path)
    seam_root = tmp_path / "seam-root"
    seam_inventory = seam_root / "var/lib/newton/devices.toml"
    seam_inventory.parent.mkdir(parents=True)
    seam_inventory.write_text("[devices.seam]\n")
    seam_inventory.chmod(0o644)
    seam_env = {
        "NEWTON_DOCTOR_ROOT": str(seam_root),
        "NEWTON_DOCTOR_TIMEOUT": "seventy-seven",
        "NEWTON_DOCTOR_HOLD": "seventy-seven",
        "NEWTON_DOCTOR_GROUPS": "seamgroup",
        "NEWTON_DOCTOR_AGENT_UID": "0",
    }

    result, called = run_installed_copy_unshared(tmp_path, installed, seam_env)

    seam_names = sorted(
        list(seam_env) + ["NEWTON_DOCTOR_SUDO", "NEWTON_DOCTOR_SSH"]
    )
    assert [
        line
        for line in result.stdout.splitlines()
        if line.startswith("INFO ignored test seam")
    ] == [
        "INFO ignored test seam %s (disabled in the installed copy)" % name
        for name in seam_names
    ]
    for value in (
        "seventy-seven",
        "seamgroup",
        str(called["seam_sudo"]),
        str(called["seam_ssh"]),
        str(seam_root),
        str(seam_inventory),
    ):
        assert value not in result.stdout
    assert not called["seam_sudo_called"].exists()
    assert not called["seam_ssh_called"].exists()
    # The real /var/lib is hidden by the tmpfs: creds-unreadable passes.
    assert "PASS creds-unreadable" in result.stdout
    assert "FAIL creds-unreadable" not in result.stdout
    # The bind-mounted /usr/bin/sudo stub was used through the absolute path.
    assert called["sudo_call_log"].exists()
    assert "-n -l" in called["sudo_call_log"].read_text()


def test_doctor_usage_says_router_is_required():
    result = run(DOCTOR, "--bogus")

    assert result.returncode == 2
    assert (
        "usage: newton-doctor --router user@host [--router user@host]... "
        "[--device NAME]..." in result.stderr
    )


def test_doctor_installed_copy_reports_seams_variable_itself_f6(doctor_env, tmp_path):
    installed = installed_doctor_copy(tmp_path)
    seam_root = tmp_path / "seam-root"
    seam_env = {
        "NEWTON_DOCTOR_SEAMS": "1",
        "NEWTON_DOCTOR_ROOT": str(seam_root),
        "NEWTON_DOCTOR_HOLD": "0",
    }

    result, _called = run_installed_copy_unshared(tmp_path, installed, seam_env)

    assert (
        "INFO ignored test seam NEWTON_DOCTOR_SEAMS (disabled in the installed copy)"
        in result.stdout
    )
    assert "INFO test seams in use" not in result.stdout
    assert str(seam_root) not in result.stdout


# ---- installer side: render_installed_doctor and the install-time wiring ----


def render_installed_doctor_call(src, dst):
    return subprocess.run(
        [
            "bash",
            "-c",
            'source scripts/newton-install; render_installed_doctor "$1" "$2"',
            "render_installed_doctor",
            str(src),
            str(dst),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_render_installed_doctor_bytes_match_reference_f6(tmp_path):
    installed = installed_doctor_copy(tmp_path)

    assert installed.read_bytes() == reference_installed_doctor_text().encode()


def test_render_installed_doctor_differs_in_two_lines_f6(tmp_path):
    installed = installed_doctor_copy(tmp_path)

    src_lines = DOCTOR.read_text().splitlines()
    dst_lines = installed.read_text().splitlines()
    assert len(src_lines) == len(dst_lines)
    diffs = [i for i, (a, b) in enumerate(zip(src_lines, dst_lines)) if a != b]
    marker_idx = next(
        i for i, line in enumerate(src_lines) if line.startswith("NEWTON_DOCTOR_SEAMS=1")
    )
    assert diffs == [0, marker_idx]
    assert dst_lines[0] == "#!/bin/bash -p"
    assert dst_lines[marker_idx] == "NEWTON_DOCTOR_SEAMS=0  # installed copy: test seams disabled"


def test_render_installed_doctor_source_without_marker_line_f6(tmp_path):
    src = tmp_path / "no-marker.sh"
    src.write_text("#!/bin/bash\necho hello\n\nexit 0\n", encoding="utf-8")
    dst = tmp_path / "out"

    result = render_installed_doctor_call(src, dst)

    assert result.returncode != 0
    assert "ERROR" in result.stderr
    assert not dst.exists()


def test_render_installed_doctor_source_with_two_marker_lines_f6(tmp_path):
    src = tmp_path / "two-markers.sh"
    src.write_text(
        "#!/bin/bash\nNEWTON_DOCTOR_SEAMS=1\necho hi\nNEWTON_DOCTOR_SEAMS=1\nexit 0\n",
        encoding="utf-8",
    )
    dst = tmp_path / "out"

    result = render_installed_doctor_call(src, dst)

    assert result.returncode != 0
    assert "ERROR" in result.stderr
    assert not dst.exists()


def test_render_installed_doctor_preserves_no_trailing_newline_f6(tmp_path):
    src = tmp_path / "no-trailing-newline.sh"
    src.write_bytes(b"#!/bin/bash\nNEWTON_DOCTOR_SEAMS=1  # marker\nexit 0")
    dst = tmp_path / "out"

    result = render_installed_doctor_call(src, dst)

    assert result.returncode == 0, result.stderr
    data = dst.read_bytes()
    assert data[-1:] != b"\n"
    assert data == (
        b"#!/bin/bash -p\n"
        + b"NEWTON_DOCTOR_SEAMS=0  # installed copy: test seams disabled\nexit 0"
    )


def test_render_installed_doctor_first_line_not_shebang_f6(tmp_path):
    src = tmp_path / "bad-first.sh"
    src.write_text("not a shebang\nNEWTON_DOCTOR_SEAMS=1\nexit 0\n", encoding="utf-8")
    dst = tmp_path / "out"

    result = render_installed_doctor_call(src, dst)

    assert result.returncode != 0
    assert "ERROR" in result.stderr
    assert not dst.exists()


def test_render_installed_doctor_static_install_wiring_f6():
    src = INSTALL.read_text()

    assert 'render_installed_doctor "$SNAP/scripts/newton-doctor"' in src
    assert 'install -o root -g root -m 0755 "$doctor_tmp" "$DOCTOR_LAUNCHER"' in src
    cleanup_match = re.search(r"cleanup\(\)\s*\{", src)
    assert cleanup_match is not None
    cleanup_open = src.find("{", cleanup_match.end() - 1)
    depth = 0
    end = None
    for i in range(cleanup_open, len(src)):
        ch = src[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    assert end is not None
    cleanup_body = src[cleanup_open:end]
    assert '"$doctor_tmp"' in cleanup_body

    lines = src.splitlines()
    success_idx = next(
        i for i, line in enumerate(lines) if "Newton installed successfully" in line
    )
    assert "--router root@<router-ip>" in lines[success_idx + 1]


def test_skill_md_documents_installed_doctor_f6():
    skill_text = (ROOT / "SKILL.md").read_text()

    assert "/usr/local/bin/newton-doctor" in skill_text
    assert "The installed copy ignores every" in skill_text
    assert "test variable" in skill_text


# ---- review repairs ----


def test_doctor_escapes_terminal_bytes_in_credential_filename_a(doctor_env):
    config = Path(doctor_env["env"]["HOME"]) / ".config/newton"
    config.mkdir(parents=True)
    evil = config / "evil\x1b[2Jx.pw"
    evil.write_text("password\n")

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 0, result.stdout + result.stderr
    info = result.stdout.splitlines()[1]
    assert info.startswith("INFO agent-readable credentials:")
    assert "evil\\x1b[2Jx.pw" in info
    assert "\x1b" not in result.stdout
    assert info.endswith("(lab devices only)")


def test_doctor_continues_same_indent_root_rule_f4_c(doctor_env, tmp_path):
    write_sudol(
        doctor_env,
        tmp_path,
        "User agent may run the following commands on this host:\n"
        "    (root) NOPASSWD: /usr/bin/ok,\n"
        "    /usr/bin/hidden\n",
    )

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 1, result.stdout + result.stderr
    assert (
        "FAIL agent-has-no-root-path: sudo NOPASSWD rule runs as root: "
        "/usr/bin/hidden" in result.stdout
    )


def test_doctor_continues_same_indent_newton_rule_f4_c(doctor_env, tmp_path):
    write_sudol(
        doctor_env,
        tmp_path,
        "User agent may run the following commands on this host:\n"
        '    (newton) NOPASSWD: /usr/local/bin/newton-mcp "",\n'
        "    /usr/bin/hidden2\n",
    )

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 1, result.stdout + result.stderr
    assert (
        "FAIL agent-has-no-root-path: sudo NOPASSWD rule runs as newton "
        "(the credential owner): /usr/bin/hidden2" in result.stdout
    )


def test_doctor_continues_deeper_indent_root_rule_f4_c(doctor_env, tmp_path):
    write_sudol(
        doctor_env,
        tmp_path,
        "User agent may run the following commands on this host:\n"
        "    (root) NOPASSWD: /usr/bin/ok,\n"
        "        /usr/bin/deeper\n",
    )

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 1, result.stdout + result.stderr
    assert (
        "FAIL agent-has-no-root-path: sudo NOPASSWD rule runs as root: "
        "/usr/bin/deeper" in result.stdout
    )


def test_doctor_password_rule_continued_stays_password_rule_f4_c(
    doctor_env, tmp_path
):
    write_sudol(
        doctor_env,
        tmp_path,
        "User agent may run the following commands on this host:\n"
        "    (root) PASSWD: /usr/bin/a,\n"
        "    /usr/bin/b\n"
        '    (newton) NOPASSWD: /usr/local/bin/newton-mcp ""\n',
    )

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS agent-has-no-root-path" in result.stdout


# ---- review repairs ----


def test_doctor_path_force_precedes_compgen_in_source_m2b():
    """scripts/newton-doctor must force PATH before it runs
    `compgen -A variable NEWTON_DOCTOR_ | LC_ALL=C sort`; otherwise a fake
    `sort` on the caller's PATH runs in the installed copy before PATH is
    reset to the system directories."""
    lines = DOCTOR.read_text().splitlines()
    path_idx = next(
        (
            i
            for i, line in enumerate(lines)
            if line.strip() == "PATH=/usr/sbin:/usr/bin:/sbin:/bin"
        ),
        None,
    )
    compgen_idx = next(
        (
            i
            for i, line in enumerate(lines)
            if "compgen -A variable NEWTON_DOCTOR_" in line
        ),
        None,
    )
    assert path_idx is not None, "PATH force line not found in scripts/newton-doctor"
    assert compgen_idx is not None, (
        "compgen -A variable NEWTON_DOCTOR_ line not found in scripts/newton-doctor"
    )
    assert path_idx < compgen_idx, (
        "PATH=/usr/sbin:/usr/bin:/sbin:/bin at line %d must precede "
        "compgen -A variable NEWTON_DOCTOR_ at line %d"
        % (path_idx + 1, compgen_idx + 1)
    )


def test_doctor_installed_copy_uses_system_path_for_compgen_m2b(tmp_path):
    """installed copy: PATH must be forced before the SEAM_ENV_VARS
    collection runs, so a fake 'sort' or 'id' on the caller's PATH cannot
    be reached inside the installed copy."""
    installed = installed_doctor_copy(tmp_path)

    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    marker = tmp_path / "fakebin-marker"

    fake_sort = fakebin / "sort"
    make_executable(
        fake_sort,
        "#!/bin/sh\n"
        "printf 'sort\\n' >> %s\n"
        "exec /usr/bin/sort \"$@\"\n" % marker,
    )
    fake_id = fakebin / "id"
    make_executable(
        fake_id,
        "#!/bin/sh\n"
        "printf 'id\\n' >> %s\n"
        "exec /usr/bin/id \"$@\"\n" % marker,
    )

    seam_env = {"NEWTON_DOCTOR_PROBE": "1"}
    command, env, _artifacts = installed_doctor_unshare(
        tmp_path, installed, seam_env
    )
    env["PATH"] = str(fakebin) + os.pathsep + env["PATH"]

    result = subprocess.run(
        command, env=env, text=True, capture_output=True, timeout=60
    )

    assert not marker.exists(), (
        "fake sort/id in fakebin was reached by the installed copy:\n"
        "stdout=%s\nstderr=%s" % (result.stdout, result.stderr)
    )
    assert (
        "INFO ignored test seam NEWTON_DOCTOR_PROBE (disabled in the installed copy)"
        in result.stdout
    )


def with_shebang(installed, new_shebang, tmp_path):
    """Return a copy of the installed doctor with its first line replaced
    by `new_shebang` (kept in column 0, with a trailing newline).  Used
    by the shebang pin tests below and their positive controls."""
    safe = re.sub(r"[^A-Za-z0-9]+", "_", new_shebang).strip("_") or "x"
    variant = tmp_path / ("doctor-" + safe)
    lines = installed.read_text().splitlines(keepends=True)
    assert lines[0].startswith("#!"), "installed copy must start with a shebang"
    lines[0] = new_shebang + "\n"
    variant.write_text("".join(lines))
    variant.chmod(0o755)
    return variant


def test_doctor_installed_copy_shebang_ignores_bash_env_f6(tmp_path):
    """installed copy runs under `#!/bin/bash -p`: bash -p does not
    process BASH_ENV or ENV, so a startup file pointed at by BASH_ENV (and
    ENV) must not be sourced even when the outer shell is /bin/sh."""
    installed = installed_doctor_copy(tmp_path)

    marker = tmp_path / "bash-env-marker"
    touch_sh = tmp_path / "touch.sh"
    make_executable(touch_sh, "#!/bin/sh\ntouch %s\n" % marker)

    control = subprocess.run(
        ["/bin/sh", "-c", "true"],
        env={**os.environ, "BASH_ENV": str(touch_sh)},
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert control.returncode == 0, control.stderr
    if marker.exists():
        pytest.skip(
            "/bin/sh reads BASH_ENV on this host; cannot pin bash -p BASH_ENV behaviour"
        )

    command, env, _artifacts = installed_doctor_unshare(tmp_path, installed, {})
    assert command[3] == "bash", command
    command[3] = "/bin/sh"
    env["BASH_ENV"] = str(touch_sh)
    env["ENV"] = str(touch_sh)

    result = subprocess.run(
        command, env=env, text=True, capture_output=True, timeout=60
    )

    assert not marker.exists(), (
        "BASH_ENV/ENV reached the doctor under `#!/bin/bash -p`:\n"
        "stdout=%s\nstderr=%s" % (result.stdout, result.stderr)
    )
    assert "newton-doctor must run as the agent user" in result.stdout


def test_doctor_installed_copy_shebang_ignores_exported_functions_f6(tmp_path):
    """installed copy runs under `#!/bin/bash -p`: bash -p does not
    inherit exported shell functions, so BASH_FUNC_sort%% / BASH_FUNC_id%%
    in the environment must not turn `sort` or `id` inside the doctor
    into a fakesort/fakeid."""
    installed = installed_doctor_copy(tmp_path)

    command, env, _artifacts = installed_doctor_unshare(tmp_path, installed, {})
    env["BASH_FUNC_sort%%"] = "() { echo FAKESORT; }"
    env["BASH_FUNC_id%%"] = "() { echo 4242; }"

    result = subprocess.run(
        command, env=env, text=True, capture_output=True, timeout=60
    )

    assert "newton-doctor must run as the agent user" in result.stdout, (
        result.stdout + result.stderr
    )
    assert "FAKESORT" not in result.stdout, (
        "exported shell function reached the doctor under `#!/bin/bash -p`:\n"
        "stdout=%s\nstderr=%s" % (result.stdout, result.stderr)
    )


def test_doctor_installed_copy_shebang_control_runs_bash_env_f6(tmp_path):
    """positive control: when the same first line is `#!/bin/bash` (no
    -p), the doctor DOES process BASH_ENV and touches the marker.  This
    proves test_doctor_installed_copy_shebang_ignores_bash_env_f6 is not
    vacuous."""
    installed = installed_doctor_copy(tmp_path)
    no_p = with_shebang(installed, "#!/bin/bash", tmp_path)

    marker = tmp_path / "bash-env-marker"
    touch_sh = tmp_path / "touch.sh"
    make_executable(touch_sh, "#!/bin/sh\ntouch %s\n" % marker)

    control = subprocess.run(
        ["/bin/sh", "-c", "true"],
        env={**os.environ, "BASH_ENV": str(touch_sh)},
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert control.returncode == 0, control.stderr
    if marker.exists():
        pytest.skip(
            "/bin/sh reads BASH_ENV on this host; cannot run control for bash -p BASH_ENV behaviour"
        )

    command, env, _artifacts = installed_doctor_unshare(tmp_path, no_p, {})
    assert command[3] == "bash", command
    command[3] = "/bin/sh"
    env["BASH_ENV"] = str(touch_sh)
    env["ENV"] = str(touch_sh)

    result = subprocess.run(
        command, env=env, text=True, capture_output=True, timeout=60
    )

    assert marker.exists(), (
        "control: BASH_ENV was NOT processed by the doctor without -p:\n"
        "stdout=%s\nstderr=%s" % (result.stdout, result.stderr)
    )
    marker.unlink(missing_ok=True)
    assert "newton-doctor must run as the agent user" in result.stdout


def test_doctor_installed_copy_reexec_drops_exported_functions_even_without_p_r2_03(tmp_path):
    """the installed copy's `reexec_with_clean_environment` re-execs
    under `env -i ... /bin/bash -p`, which discards exported shell
    functions (BASH_FUNC_*) even when the shebang itself is
    `#!/bin/bash` (no -p).  The shebang's -p flag is stage 1; the
    re-exec is the second line of defence and makes it impossible for
    a caller-exported BASH_FUNC_sort%% to run as `sort` inside the
    installed copy."""
    installed = installed_doctor_copy(tmp_path)
    no_p = with_shebang(installed, "#!/bin/bash", tmp_path)

    command, env, _artifacts = installed_doctor_unshare(tmp_path, no_p, {})
    env["BASH_FUNC_sort%%"] = "() { echo FAKESORT; }"
    env["BASH_FUNC_id%%"] = "() { echo 4242; }"

    result = subprocess.run(
        command, env=env, text=True, capture_output=True, timeout=60
    )

    assert "newton-doctor must run as the agent user" in result.stdout, (
        result.stdout + result.stderr
    )
    assert "FAKESORT" not in result.stdout, (
        "control: exported function reached the doctor via re-exec even without -p:\n"
        "stdout=%s\nstderr=%s" % (result.stdout, result.stderr)
    )


# ---- venv creation ----


def test_create_venv_runs_isolated_in_clean_env_from_empty_dir_r2_01():
    body = bash_function_text("create_venv")
    compact = " ".join(body.replace("\\\n", " ").split())
    assert (
        'cd "$venv_cwd" || exit 1 env -i '
        'PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root TMPDIR="$WORK/tmp" '
        '/usr/bin/python3 -I -m venv "$CODE_ROOT/venv"'
        in compact
    )
    assert "if ! create_venv; then" in bash_function_text("build_venv")


def test_main_leaves_caller_directory_after_snapshot_r2_01():
    lines = INSTALL.read_text().splitlines()
    snap_indices = [
        i
        for i, line in enumerate(lines)
        if line.strip() == "make_snapshot || exit $?"
    ]
    assert len(snap_indices) == 2
    for idx in snap_indices:
        next_line = lines[idx + 1].strip() if idx + 1 < len(lines) else ""
        assert next_line == 'cd -- "$WORK" || exit 1'


def test_build_venv_ignores_cwd_user_site_and_pythonpath_r2_01(tmp_path):
    # On the old code the sentinels are written because python ran in the
    # caller's cwd and environment.
    plant = tmp_path / "plant"
    plant.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    pypath = tmp_path / "pypath"
    pypath.mkdir()
    work = tmp_path / "work"
    snap = tmp_path / "snap"
    code_root = tmp_path / "code_root"
    sentinel_cwd = tmp_path / "sentinel-cwd"
    sentinel_user = tmp_path / "sentinel-user"
    sentinel_pythonpath = tmp_path / "sentinel-pythonpath"

    cwd_literal = repr(str(sentinel_cwd))
    user_literal = repr(str(sentinel_user))
    pypath_literal = repr(str(sentinel_pythonpath))

    (plant / "venv").mkdir()
    (plant / "venv/__init__.py").write_text(
        f"open({cwd_literal}, 'w').write('ran')\n"
    )
    (plant / "venv.py").write_text(
        f"open({cwd_literal}, 'w').write('ran')\n"
    )

    user_site_result = subprocess.run(
        ["/usr/bin/python3", "-c", "import site; print(site.getusersitepackages())"],
        env={**os.environ, "HOME": str(home)},
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert user_site_result.returncode == 0, user_site_result.stderr
    user_site = Path(user_site_result.stdout.strip())
    user_site.mkdir(parents=True, exist_ok=True)
    (user_site / "usercustomize.py").write_text(
        f"open({user_literal}, 'w').write('ran')\n"
    )

    (pypath / "sitecustomize.py").write_text(
        f"open({pypath_literal}, 'w').write('ran')\n"
    )

    env = dict(os.environ)
    env["HOME"] = str(home)
    env["PYTHONPATH"] = str(pypath)

    result = subprocess.run(
        rootless_root_command(
            "bash",
            "-c",
            'source "$1"; WORK=$2; SNAP=$3; CODE_ROOT=$4; '
            'mkdir -p "$WORK" "$CODE_ROOT" "$SNAP"; cd "$5"; build_venv',
            "x",
            str(INSTALL),
            str(work),
            str(snap),
            str(code_root),
            str(plant),
        ),
        env=env,
        text=True,
        capture_output=True,
        timeout=180,
    )
    del result

    assert not sentinel_cwd.exists()
    assert not sentinel_user.exists()
    assert not sentinel_pythonpath.exists()
    assert (code_root / "venv/bin/python").exists()


def test_main_runs_install_steps_in_work_dir_r2_01(tmp_path):
    env = dict(os.environ, SUDO_USER="agent")
    env.pop("NEWTON_INSTALL_ROOT", None)
    env["MARK_DIR"] = str(tmp_path)
    code = (
        'source "$1"\n'
        "BOOTSTRAP_DEST=$MARK_DIR/no-bootstrap\n"
        "check_root_programs() { return 0; }\n"
        "make_snapshot() { WORK=$MARK_DIR/work; mkdir -p \"$WORK\"; "
        "SNAP=$WORK/snap; return 0; }\n"
        "print_identity_block() { :; }\n"
        "confirm_install() { :; }\n"
        "getent() { pwd -P >\"$MARK_DIR/cwd\"; exit 93; }\n"
        "cd /\n"
        "main\n"
    )
    command = rootless_root_command(
        "bash", "-c", code, "root-main", str(INSTALL)
    )
    master, slave = pty.openpty()
    try:
        # the empty line answers the Claude Code guard question:
        # the default is no
        os.write(master, b"\n")
        result = subprocess.run(
            command,
            stdin=slave,
            text=True,
            capture_output=True,
            env=env,
            timeout=30,
        )
    finally:
        os.close(slave)
        os.close(master)

    assert result.returncode == 93, result.stdout + result.stderr
    assert (tmp_path / "cwd").read_text().strip() == str(
        (tmp_path / "work").resolve()
    )


# ---- full commit id ----


def test_install_prompt_asks_for_full_id_and_does_not_print_it_r2_05(tmp_path):
    repo = make_install_repo(tmp_path)
    head = git_out(repo, "rev-parse", "HEAD")

    result = run_install_pty(repo, tmp_path)

    assert result.returncode == 1, result.stdout + result.stderr
    assert (
        'type "install " followed by the full 40-hex commit id' in result.stderr
    )
    assert head not in result.stderr
    assert head[:12] not in result.stderr
    assert head in result.stdout


def test_confirm_install_requires_full_commit_id_r2_05():
    body = bash_function_text("confirm_install")
    assert 'expected="install $COMMIT_ID"' in body
    assert ":0:" not in body


# ---- router check ignores the ssh config ----


def test_doctor_router_check_passes_dash_F_dev_null_to_ssh_r2_04(doctor_env, tmp_path):
    args_log = tmp_path / "ssh-args.txt"
    env = doctor_env["env"].copy()
    env["DOCTOR_STUB_SSH_ARGS"] = str(args_log)

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=env)

    assert result.returncode == 0, result.stdout + result.stderr
    args = args_log.read_text().splitlines()
    assert args.count("-F") == 1
    f_index = args.index("-F")
    assert args[f_index + 1] == "/dev/null"
    assert "root@192.0.2.1" in args
    assert "true" in args


def test_doctor_router_check_ignores_ssh_config_that_forges_a_denial_r2_04(
    doctor_env, tmp_path
):
    if not Path("/usr/bin/ssh").exists():
        pytest.skip("/usr/bin/ssh not available")

    hostile = tmp_path / "hostile.conf"
    hostile.write_text(
        "Host forged.invalid\n"
        "    ProxyCommand sh -c 'echo \"root@forged.invalid: "
        'Permission denied (publickey,password)." >&2; exit 1\'\n'
    )
    wrapper = tmp_path / "ssh-with-config"
    make_executable(
        wrapper,
        "#!/bin/sh\n"
        f"exec /usr/bin/ssh -F {shlex.quote(str(hostile))} \"$@\"\n",
    )

    control = subprocess.run(
        [str(wrapper), "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
         "root@forged.invalid", "true"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=30,
        text=True,
    )
    assert control.returncode == 255, (
        control.stdout + control.stderr
    )
    assert "Permission denied (publickey,password)" in control.stderr

    env = doctor_env["env"].copy()
    env["NEWTON_DOCTOR_SSH"] = str(wrapper)

    result = subprocess.run(
        [str(DOCTOR), "--router", "root@forged.invalid"],
        text=True,
        capture_output=True,
        env=env,
        timeout=60,
    )

    assert result.returncode == 3, result.stdout + result.stderr
    assert not any(
        line.startswith("PASS router-unreachable")
        for line in result.stdout.splitlines()
    )
    assert any(
        line.startswith("INCONCLUSIVE router-unreachable[root@forged.invalid]")
        for line in result.stdout.splitlines()
    )


# ---- numeric and group runas ----


NUMERIC_ROOT_RULES = [
    "(#0) NOPASSWD: /bin/sh",
    "(0) NOPASSWD: /bin/sh",
    "(#00) NOPASSWD: /bin/sh",
    "(#0 : #0) NOPASSWD: ALL",
    "(www-data, #0) NOPASSWD: /bin/sh",
]


@pytest.mark.parametrize("rule", NUMERIC_ROOT_RULES)
def test_doctor_flags_numeric_root_runas_r2_06(doctor_env, tmp_path, rule):
    write_sudol(
        doctor_env,
        tmp_path,
        "User agent may run the following commands on this host:\n"
        f"    {rule}\n",
    )

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 1, result.stdout + result.stderr
    if rule.endswith("ALL"):
        expected = (
            "FAIL agent-has-no-root-path: sudo NOPASSWD rule runs as root: "
            "ALL (unrestricted root)"
        )
    else:
        expected = (
            "FAIL agent-has-no-root-path: sudo NOPASSWD rule runs as root: "
            "/bin/sh (runs or writes arbitrary files as root)"
        )
    assert expected in result.stdout


NUMERIC_NON_ROOT_RULES = [
    "(#1000) NOPASSWD: /bin/sh",
    "(#10) NOPASSWD: /bin/sh",
    "(10) NOPASSWD: /bin/sh",
    "(#100) NOPASSWD: /bin/sh",
]


@pytest.mark.parametrize("rule", NUMERIC_NON_ROOT_RULES)
def test_doctor_numeric_non_root_runas_is_not_root_r2_06(doctor_env, tmp_path, rule):
    write_sudol(
        doctor_env,
        tmp_path,
        "User agent may run the following commands on this host:\n"
        f"    {rule}\n",
    )

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS agent-has-no-root-path" in result.stdout


GROUP_RUNAS_CASES = [
    (
        "(%wheel) NOPASSWD: ALL",
        "FAIL agent-has-no-root-path: sudo NOPASSWD rule runs as members of "
        "%wheel (cannot prove root is not among them): ALL",
    ),
    (
        "(+admins) NOPASSWD: /usr/bin/id",
        "FAIL agent-has-no-root-path: sudo NOPASSWD rule runs as members of "
        "+admins (cannot prove root is not among them): /usr/bin/id",
    ),
]


@pytest.mark.parametrize(("rule", "expected"), GROUP_RUNAS_CASES)
def test_doctor_flags_group_runas_r2_06(doctor_env, tmp_path, rule, expected):
    write_sudol(
        doctor_env,
        tmp_path,
        "User agent may run the following commands on this host:\n"
        f"    {rule}\n",
    )

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 1, result.stdout + result.stderr
    assert expected in result.stdout


def test_doctor_group_runas_edge_cases_r2_06(doctor_env, tmp_path):
    # (%wheel) ALL: no NOPASSWD: tag, password required, never flagged.
    write_sudol(
        doctor_env,
        tmp_path,
        "User agent may run the following commands on this host:\n"
        "    (%wheel) ALL\n",
    )
    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS agent-has-no-root-path" in result.stdout

    # (!%wheel) NOPASSWD: ...: negated group starts with "!", not matched.
    write_sudol(
        doctor_env,
        tmp_path,
        "User agent may run the following commands on this host:\n"
        "    (!%wheel) NOPASSWD: /usr/bin/id\n",
    )
    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS agent-has-no-root-path" in result.stdout

    # (root, %wheel) NOPASSWD: /usr/bin/id: root present, only the root
    # branch fires; no "members of" line is produced.
    write_sudol(
        doctor_env,
        tmp_path,
        "User agent may run the following commands on this host:\n"
        "    (root, %wheel) NOPASSWD: /usr/bin/id\n",
    )
    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])
    assert result.returncode == 1, result.stdout + result.stderr
    assert (
        "FAIL agent-has-no-root-path: sudo NOPASSWD rule runs as root: "
        "/usr/bin/id" in result.stdout
    )
    assert "members of" not in result.stdout


# ---- installed copy drops the caller's environment ----


def test_doctor_installed_copy_drops_poisoned_environment_r2_03(tmp_path):
    installed = installed_doctor_copy(tmp_path)
    seam_env = {
        "LD_PRELOAD": "/nonexistent-preload.so",
        "BASH_ENV": "/dev/null",
        "PYTHONPATH": "/nonexistent-pythonpath",
        "FOO_CUSTOM": "1",
        "NEWTON_DOCTOR_PROBE": "1",
    }
    command, env, artifacts = installed_doctor_unshare(
        tmp_path, installed, seam_env
    )
    result = subprocess.run(
        command, env=env, text=True, capture_output=True, timeout=60
    )
    lines = result.stdout.splitlines()
    assert any(
        "INFO dropped environment variable LD_PRELOAD" in line
        and "the installed copy runs with a clean environment" in line
        for line in lines
    ), result.stdout + result.stderr
    assert any(
        "INFO dropped environment variable BASH_ENV" in line
        and "the installed copy runs with a clean environment" in line
        for line in lines
    ), result.stdout + result.stderr
    assert any(
        line
        == "INFO ignored test seam NEWTON_DOCTOR_PROBE (disabled in the installed copy)"
        for line in lines
    ), result.stdout + result.stderr
    assert not any("FOO_CUSTOM" in line for line in lines), (
        "FOO_CUSTOM should not appear in doctor stdout: "
        + result.stdout
        + result.stderr
    )
    assert not any("PYTHONPATH" in line for line in lines), (
        "PYTHONPATH should not appear in doctor stdout: "
        + result.stdout
        + result.stderr
    )
    assert "newton-doctor must run as the agent user" in result.stdout, (
        result.stdout + result.stderr
    )

    sudo_env_log = artifacts["sudo_env_log"]
    ssh_env_log = artifacts["ssh_env_log"]
    assert sudo_env_log.exists(), f"missing sudo env log: {sudo_env_log}"
    assert ssh_env_log.exists(), f"missing ssh env log: {ssh_env_log}"
    sudo_env_text = sudo_env_log.read_text()
    ssh_env_text = ssh_env_log.read_text()
    for leak in (
        "LD_PRELOAD",
        "BASH_ENV",
        "PYTHONPATH",
        "FOO_CUSTOM",
        "NEWTON_DOCTOR_PROBE",
    ):
        assert leak not in sudo_env_text, (
            f"{leak} leaked into sudo env: {sudo_env_text}"
        )
        assert leak not in ssh_env_text, (
            f"{leak} leaked into ssh env: {ssh_env_text}"
        )
    for env_text in (sudo_env_text, ssh_env_text):
        assert "PATH=/usr/sbin:/usr/bin:/sbin:/bin" in env_text, (
            "expected pinned PATH line missing in stub env log:\n" + env_text
        )


def test_doctor_installed_copy_keeps_allowlisted_variables_r2_03(tmp_path):
    installed = installed_doctor_copy(tmp_path)
    seam_env = {
        "SSH_AUTH_SOCK": "/nonexistent/agent.sock",
        "TERM": "dumb",
        "LANG": "C",
        "FOO_CUSTOM": "1",
    }
    command, env, artifacts = installed_doctor_unshare(
        tmp_path, installed, seam_env
    )
    result = subprocess.run(
        command, env=env, text=True, capture_output=True, timeout=60
    )

    ssh_env_log = artifacts["ssh_env_log"]
    assert ssh_env_log.exists(), f"missing ssh env log: {ssh_env_log}"
    ssh_env_lines = ssh_env_log.read_text().splitlines()
    assert "SSH_AUTH_SOCK=/nonexistent/agent.sock" in ssh_env_lines, (
        "SSH_AUTH_SOCK line missing in ssh env log:\n" + "\n".join(ssh_env_lines)
    )
    assert "TERM=dumb" in ssh_env_lines, (
        "TERM=dumb line missing in ssh env log:\n" + "\n".join(ssh_env_lines)
    )
    assert "LANG=C" in ssh_env_lines, (
        "LANG=C line missing in ssh env log:\n" + "\n".join(ssh_env_lines)
    )
    assert any(line.startswith("HOME=") for line in ssh_env_lines), (
        "HOME= line missing in ssh env log:\n" + "\n".join(ssh_env_lines)
    )
    assert not any("FOO_CUSTOM" in line for line in ssh_env_lines), (
        "FOO_CUSTOM should not appear in ssh env log:\n"
        + "\n".join(ssh_env_lines)
    )
    assert "FOO_CUSTOM" not in ssh_env_log.read_text(), (
        "FOO_CUSTOM leaked into ssh env log:\n" + ssh_env_log.read_text()
    )

    for env_log in (artifacts["sudo_env_log"], ssh_env_log):
        env_text = env_log.read_text()
        assert "_NEWTON_DOCTOR_CLEAN" not in env_text, (
            f"guard name leaked into env log:\n{env_text}"
        )


def test_doctor_installed_copy_exit_code_not_forged_by_ld_preload_r2_03(tmp_path):
    """the installed copy's re-exec must strip LD_PRELOAD: an attacker
    who only controls the caller's environment cannot forge the
    doctor's exit code by preloading a libc that hooks exit()."""
    cc = shutil.which("cc")
    if cc is None:
        pytest.skip("cc is unavailable; cannot build the LD_PRELOAD forge")

    forge_c = tmp_path / "forge.c"
    forge_c.write_text(
        "#define _GNU_SOURCE\n"
        "#include <dlfcn.h>\n"
        "#include <stdlib.h>\n"
        "static void (*real_exit)(int) __attribute__((noreturn)) = NULL;\n"
        "void exit(int s) {\n"
        "  if (real_exit == NULL) {\n"
        "    real_exit = (void (*)(int))dlsym(RTLD_NEXT, \"exit\");\n"
        "  }\n"
        "  real_exit(0);\n"
        "}\n"
    )
    forge_so = tmp_path / "forge.so"
    subprocess.run(
        [
            cc,
            "-shared",
            "-fPIC",
            "-O1",
            "-o",
            str(forge_so),
            str(forge_c),
            "-ldl",
        ],
        check=True,
        text=True,
        capture_output=True,
        timeout=30,
    )

    installed = installed_doctor_copy(tmp_path)

    command, env, _artifacts = installed_doctor_unshare(tmp_path, installed, {})
    clean = subprocess.run(
        command, env=env, text=True, capture_output=True, timeout=60
    )
    assert clean.returncode == 1, clean.stdout + clean.stderr
    assert "FAIL non-root" in clean.stdout, clean.stdout + clean.stderr

    infected_root = tmp_path / "infected-stubs"
    infected_root.mkdir()
    command2, env2, _artifacts2 = installed_doctor_unshare(
        infected_root, installed, {"FORGE": str(forge_so)}
    )
    last = command2[-1]
    assert 'exec "$INSTALLED"' in last
    command2[-1] = last.replace(
        'exec "$INSTALLED"',
        'exec /usr/bin/env LD_PRELOAD="$FORGE" "$INSTALLED"',
    )
    infected = subprocess.run(
        command2, env=env2, text=True, capture_output=True, timeout=60
    )

    assert infected.returncode == clean.returncode, (
        "LD_PRELOAD forged the doctor's exit code: clean=%d infected=%d\n"
        "clean stdout=%s\nclean stderr=%s\n"
        "infected stdout=%s\ninfected stderr=%s"
        % (
            clean.returncode,
            infected.returncode,
            clean.stdout,
            clean.stderr,
            infected.stdout,
            infected.stderr,
        )
    )
    assert infected.returncode == 1
    assert "FAIL non-root" in infected.stdout, infected.stdout + infected.stderr


def test_doctor_installed_copy_refuses_dirty_environment_after_reexec_r2_03(tmp_path):
    """the installed copy's re-exec must verify the post-reexec
    environment: if _NEWTON_DOCTOR_CLEAN=1 is set (so the re-exec
    knew it was the re-exec), LD_PRELOAD (or anything else from the
    caller's environment) must NOT have followed us through.  Instead
    of forging a 0 exit, the doctor refuses with exit code 2 and no
    check runs."""
    installed = installed_doctor_copy(tmp_path)
    seam_env = {
        "_NEWTON_DOCTOR_CLEAN": "1",
        "LD_PRELOAD": "/nonexistent-preload.so",
    }
    command, env, _artifacts = installed_doctor_unshare(
        tmp_path, installed, seam_env
    )
    result = subprocess.run(
        command, env=env, text=True, capture_output=True, timeout=60
    )

    assert result.returncode == 2, result.stdout + result.stderr
    assert "environment is not clean after the re-exec" in result.stderr, (
        result.stdout + result.stderr
    )
    assert "LD_PRELOAD" in result.stderr, result.stdout + result.stderr
    assert not any(
        line.startswith("PASS ") or line.startswith("FAIL ")
        for line in result.stdout.splitlines()
    ), "no PASS/FAIL line should run before the dirty-env check fires:\n" + result.stdout


def test_doctor_repo_copy_never_reexecs_r2_03(doctor_env):
    """the repo copy (scripts/newton-doctor) must not re-exec: a
    caller-set FOO_CUSTOM and BASH_ENV that are NOT in the seam
    allowlist must not be touched -- no "INFO dropped" line, the
    first stdout line still announces the repo-copy test seams."""
    env = doctor_env["env"].copy()
    env["FOO_CUSTOM"] = "1"
    env["BASH_ENV"] = "/dev/null"

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=env)

    assert result.returncode == 0, result.stdout + result.stderr
    lines = result.stdout.splitlines()
    assert lines, "doctor produced no stdout"
    assert lines[0].startswith("INFO test seams in use:"), (
        "first stdout line should announce test seams, got: %r" % lines[0]
    )
    assert "INFO dropped" not in result.stdout, (
        "repo copy must not re-exec and drop environment variables:\n"
        + result.stdout
    )


# ---- transactional code root ----


def run_install_code_root(
    tmp_path, *, build_ok=True, old_tree=True, leftover_old=False, signal=False,
):
    snap = tmp_path / "snap"
    snap.mkdir(parents=True)
    (snap / "scripts").mkdir()
    (snap / "scripts" / "a.sh").write_text("#!/bin/sh\nexit 0\n")
    (snap / "mcp").mkdir()
    (snap / "mcp" / "pyproject.toml").write_text(
        "[project]\nname = 'x'\nversion = '0'\n"
    )
    (snap / "SKILL.md").write_text("new skill\n")
    for rel in (
        "device/openwrt/newton-router/newton-router",
        "device/openwrt/newton-router/router-tools.txt",
        "device/openwrt/newton-router/grammar.tsv",
        "device/openwrt/newton-guard/newton-guard",
        "device/openwrt/newton-guard/newton-guard.init",
        "profiles/openwrt/manifest.toml",
        "profiles/openwrt/standard.uci",
        "profiles/openwrt/hardened.uci",
        "profiles/openwrt/lockdown.uci",
        "profiles/openwrt/intents.toml",
    ):
        path = snap / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("src %s\n" % rel)

    code = tmp_path / "code"
    if old_tree:
        code.mkdir(parents=True)
        (code / "scripts").mkdir()
        (code / "scripts" / "old.sh").write_text("old-sh\n")
        (code / "mcp").mkdir()
        (code / "mcp" / "old.txt").write_text("old-mcp\n")
        (code / "venv").mkdir()
        (code / "venv" / "old-marker").write_text("old-venv\n")
        (code / "SKILL.md").write_text("old skill\n")

    if leftover_old:
        code_old = tmp_path / "code.old"
        code_old.mkdir(parents=True)
        (code_old / "marker").write_text("leftover\n")

    work = tmp_path / "work"

    if signal:
        build_fn = 'mkdir -p "$CODE_ROOT/venv"; kill -TERM $$'
        traps = "trap cleanup EXIT; trap 'exit 143' TERM"
    elif build_ok:
        build_fn = (
            'mkdir -p "$CODE_ROOT/venv"; '
            'touch "$CODE_ROOT/venv/new-marker"'
        )
        traps = "trap cleanup EXIT"
    else:
        build_fn = 'mkdir -p "$CODE_ROOT/venv"; return 1'
        traps = "trap cleanup EXIT"

    bash_code = (
        'source "$1"; '
        'WORK=$2; SNAP=$3; CODE_ROOT=$4; '
        f'{traps}; '
        f'build_venv() {{ {build_fn}; }}; '
        'install_code_root'
    )
    return subprocess.run(
        rootless_root_command(
            "bash", "-c", bash_code, "x", str(INSTALL),
            str(work), str(snap), str(code),
        ),
        env=os.environ, text=True, capture_output=True, timeout=60,
    )


def test_install_code_root_fresh_install_build_ok_r2_07(tmp_path):
    code = tmp_path / "code"
    result = run_install_code_root(tmp_path, build_ok=True, old_tree=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (code / "scripts" / "a.sh").exists()
    assert (code / "mcp" / "pyproject.toml").exists()
    assert (code / "SKILL.md").read_text() == "new skill\n"
    assert (code / "venv" / "new-marker").exists()
    assert not (tmp_path / "code.old").exists()


def test_install_code_root_upgrade_build_ok_replaces_tree_r2_07(tmp_path):
    code = tmp_path / "code"
    result = run_install_code_root(tmp_path, build_ok=True, old_tree=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not (code / "scripts" / "old.sh").exists()
    assert not (code / "mcp" / "old.txt").exists()
    assert not (code / "venv" / "old-marker").exists()
    assert (code / "scripts" / "a.sh").exists()
    assert (code / "mcp" / "pyproject.toml").exists()
    assert (code / "SKILL.md").read_text() == "new skill\n"
    assert (code / "venv" / "new-marker").exists()
    assert not (tmp_path / "code.old").exists()


def test_install_code_root_upgrade_build_fail_restores_old_r2_07(tmp_path):
    code = tmp_path / "code"
    result = run_install_code_root(tmp_path, build_ok=False, old_tree=True)
    assert result.returncode != 0
    assert (code / "scripts" / "old.sh").exists()
    assert (code / "mcp" / "old.txt").exists()
    assert (code / "venv" / "old-marker").exists()
    assert (code / "SKILL.md").read_text() == "old skill\n"
    assert not (code / "scripts" / "a.sh").exists()
    assert not (code / "mcp" / "pyproject.toml").exists()
    assert not (tmp_path / "code.old").exists()
    assert "restored" in result.stderr


def test_install_code_root_fresh_install_build_fail_removes_code_r2_07(tmp_path):
    code = tmp_path / "code"
    result = run_install_code_root(tmp_path, build_ok=False, old_tree=False)
    assert result.returncode != 0
    assert not code.exists()


def test_install_code_root_leftover_code_old_refuses_r2_07(tmp_path):
    code = tmp_path / "code"
    code_old = tmp_path / "code.old"
    result = run_install_code_root(
        tmp_path, build_ok=True, old_tree=True, leftover_old=True,
    )
    assert result.returncode != 0
    assert "an earlier install did not finish" in result.stderr
    assert (code / "scripts" / "old.sh").exists()
    assert (code_old / "marker").exists()


def test_install_code_root_sigterm_restores_old_r2_07(tmp_path):
    code = tmp_path / "code"
    result = run_install_code_root(
        tmp_path, build_ok=False, old_tree=True, signal=True,
    )
    assert result.returncode == 143
    assert (code / "scripts" / "old.sh").exists()


def test_main_calls_install_code_root_as_plain_statement_r2_07():
    source = INSTALL.read_text()
    body = bash_function_text("perform_install")
    stripped = [line.strip() for line in body.splitlines()]
    assert "install_code_root" in stripped
    assert not any(line == "build_venv" for line in stripped)



# ---- pin  ----


def test_doctor_reexec_runs_env_i_and_bash_p_r2_03():
    """The installed copy re-executes `/usr/bin/env -i ... /bin/bash -p`.
    The -p keeps BASH_ENV, ENV and exported functions out of the second
    process even if a variable were re-injected after the first exec; the
    behaviour tests cannot see it because env -i already removes them."""
    lines = [
        line.strip()
        for line in DOCTOR.read_text().splitlines()
        if line.strip().startswith("exec /usr/bin/env")
    ]
    assert len(lines) == 1, lines
    assert lines[0].startswith(
        "exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin "
        "_NEWTON_DOCTOR_CLEAN=1 "
    )
    assert lines[0].endswith('/bin/bash -p -- "${BASH_SOURCE[0]}" "$@"')
