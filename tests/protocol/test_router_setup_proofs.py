"""Wrong-answer tests of the restricted-key proofs of scripts/newton-router-setup
(design 8.3 sub-step 3).

Test touch-up after a planted-defect run: with a
working mutation harness, a proof that ignored one field of its answer
(agent=0 in the hello, the exit status of probe) still passed every test,
because the existing failing-proof tests only use a broken or a vulnerable
router.  Here every proof gets an answer that is right in one part and
wrong in another, and must FAIL; the right answer must PASS.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_router_setup_units import (  # noqa: E402,F401
	router_unit, _proof_setup, _assert_proof)

PROGRAM = "usr/libexec/newton/newton-router"


def _reply_program(case_lines):
	"""A forced-command program: `case_lines` maps the request text
	(SSH_ORIGINAL_COMMAND, with a nonce replaced by NONCE) to
	(stdout, stderr, exit status)."""
	body = ['#!/bin/sh', 'req=$SSH_ORIGINAL_COMMAND',
		'case "$req" in']
	for request, (out, err, rc) in case_lines.items():
		# quoted literal parts, a wildcard where the nonce goes
		pattern = "*".join('"%s"' % part for part in request.split("NONCE"))
		body.append("\t%s)" % pattern)
		if out:
			body.append("\t\tprintf '%%s\\n' '%s'" % out)
		if err:
			body.append("\t\tprintf '%%s\\n' '%s' >&2" % err)
		body.append("\t\texit %d ;;" % rc)
	body += ['\t*) echo "error unknown-subcommand" >&2; exit 2 ;;', 'esac']
	return "\n".join(body) + "\n"


def _run(router_unit, proof, program_text, role="change"):
	key = _proof_setup(router_unit, role=role)
	router_unit.router.write(PROGRAM, program_text, 0o755)
	return router_unit.run('%s "%s" lab-runner %s; echo rc=$?\n'
		% (proof, key, role))


GOOD_PROBE = {"probe": ("probe fail fail planted", "", 1)}
# right text with the wrong exit status, right status with the wrong text
@pytest.mark.parametrize("out,rc,passed", [
	("probe fail fail planted", 1, True),
	("probe fail fail planted", 0, False),
	("probe fail fail planted", 2, False),
	("probe fail ok planted", 1, False),
	("", 1, False),
])
def test_proof_probe_fail_needs_the_text_and_exit_one(router_unit, out, rc, passed):
	program = _reply_program({"probe": (out, "", rc)})
	r = _run(router_unit, "proof_probe_fail", program)
	_assert_proof(r, "probe-fail", passed=passed)


@pytest.mark.parametrize("err,rc,passed", [
	("error bad-arg 1", 2, True),
	("error bad-arg 1", 0, False),
	("error bad-arg 1", 3, False),
	("error bad-arg 2", 2, False),
	("", 2, False),
])
def test_proof_bad_arg_needs_the_text_and_exit_two(router_unit, err, rc, passed):
	program = _reply_program({"hello zz": ("", err, rc)})
	r = _run(router_unit, "proof_bad_arg", program)
	_assert_proof(r, "bad-arg", passed=passed)


@pytest.mark.parametrize("err,rc,passed", [
	("error direct-only", 3, True),
	("error direct-only", 0, False),
	("error direct-only", 2, False),
	("error role", 3, False),
	("", 3, False),
])
def test_proof_selftest_refused_needs_the_text_and_exit_three(router_unit, err, rc, passed):
	program = _reply_program({"approval-selftest NONCE": ("", err, rc)})
	r = _run(router_unit, "proof_selftest_refused", program)
	_assert_proof(r, "selftest-refused", passed=passed)


@pytest.mark.parametrize("err,rc,passed", [
	("error role", 3, True),
	("error role", 0, False),
	("error role", 2, False),
	("error other", 3, False),
	("", 3, False),
])
def test_proof_backup_read_role_needs_the_text_and_exit_three(router_unit, err, rc, passed):
	program = _reply_program({"backup": ("", err, rc)})
	r = _run(router_unit, "proof_backup", program, role="read")
	_assert_proof(r, "backup", passed=passed)


@pytest.mark.parametrize("unknown,empty,passed", [
	(("error unknown-subcommand", 2), ("error empty-request", 2), True),
	(("error unknown-subcommand", 0), ("error empty-request", 2), False),
	(("error unknown-subcommand", 2), ("error empty-request", 0), False),
	(("error empty-request", 2), ("error empty-request", 2), False),
	(("error unknown-subcommand", 2), ("error unknown-subcommand", 2), False),
])
def test_proof_unknown_and_empty_checks_both_answers(router_unit, unknown, empty, passed):
	program = _reply_program({
		"id": ("", unknown[0], unknown[1]),
		"": ("", empty[0], empty[1]),
	})
	r = _run(router_unit, "proof_unknown_and_empty", program)
	_assert_proof(r, "unknown-and-empty", passed=passed)


# proof_hello looks at five fields of the answer; a router that gets one of
# them wrong must fail (the fixture program lets a test replace a hello word
# through etc/newton/fixture-lie)
@pytest.mark.parametrize("lie", [
	"agent=1", "role=read", "door=root", "mode=test", "caller=somebody-else",
])
def test_proof_hello_checks_every_field(router_unit, lie):
	key = _proof_setup(router_unit)
	router_unit.router.write("etc/newton/fixture-lie", lie + "\n")
	r = router_unit.run('proof_hello "%s" lab-runner change; echo rc=$?\n' % key)
	_assert_proof(r, "hello", passed=False)


def test_proof_hello_passes_without_a_lie(router_unit):
	key = _proof_setup(router_unit)
	r = router_unit.run('proof_hello "%s" lab-runner change; echo rc=$?\n' % key)
	_assert_proof(r, "hello", passed=True)
