"""Design 9.2 group 7, 5.4 approval token tests.

Tests the `approval-selftest` direct-mode proof (3.5f), the
`check_approval` order in `cmd_apply` (5.4), the lab/prod profile rule
(5.3, M32), the token-vs-digest binding and the precedence of stale-stage
and guard over approval (M33). Each test asserts something a plausible
defect would break.
"""

import hashlib
import hmac
import random
import re

import pytest

from conftest import SID


SID2 = "fedcba9876543210fedcba9876543210"
NONCE_SHORT = "0123456789abcdef"  # 16 hex, the minimum `is_nonce` accepts
NONCE_LONG = "f" * 64             # 64 hex, the maximum `is_nonce` accepts


KEY_ZERO = "00" * 32
KEY_FF = "ff" * 32
KEY_START00 = "00" + "ab" * 31
KEY_ENDFF = "ab" * 31 + "ff"
KEY_BOTH = "00" + "ff" + "ab" * 30
KEY_DEFAULT = "0123456789abcdef" * 4


def _random_keys():
    rng = random.Random(7)
    return [rng.randbytes(32).hex() for _ in range(6)]


RANDOM_KEYS = _random_keys()
ALL_KEYS = [
    KEY_ZERO, KEY_FF, KEY_START00, KEY_ENDFF, KEY_BOTH, KEY_DEFAULT,
    *RANDOM_KEYS,
]


def write_key(router, key_hex):
    router.write("etc/newton/approve.key", key_hex + "\n")


def selftest_hmac(key_hex, nonce):
    return hmac.new(
        bytes.fromhex(key_hex),
        b"newton-selftest-v1\n" + nonce.encode() + b"\n",
        "sha256",
    ).hexdigest()


def approval_hmac(key_hex, digest):
    return hmac.new(
        bytes.fromhex(key_hex),
        b"newton-approval-v1\n" + digest.encode() + b"\n",
        "sha256",
    ).hexdigest()


def plan_digest_py(device, sid, base, diff, psha, t):
    body = f"newton-plan-v1\n{device}\n{sid}\n{base}\n{diff}\n{psha}\n{t}\n"
    return hashlib.sha256(body.encode()).hexdigest()


def parse_digest(out):
    for line in out.splitlines():
        if line.startswith("digest "):
            return line[len("digest "):]
    return None


# ---- 1. approval-selftest HMAC matches Python ----------------------------

@pytest.mark.parametrize("key_hex", ALL_KEYS,
                         ids=[f"k{i:02d}" for i in range(len(ALL_KEYS))])
@pytest.mark.parametrize("nonce", [NONCE_SHORT, NONCE_LONG], ids=["n16", "n64"])
def test_approval_selftest_hmac_matches_python(router, key_hex, nonce):
    """The router's selftest HMAC equals Python's HMAC-SHA256 over the
    documented selftest domain (3.5f, 5.4). 12 keys x 2 nonces."""
    write_key(router, key_hex)
    res = router.direct("approval-selftest", nonce)
    assert res.rc == 0
    assert res.err == ""
    expected = selftest_hmac(key_hex, nonce)
    assert res.out == f"approval-selftest {nonce} {expected}\n"


@pytest.mark.parametrize("length", [1, 15, 65], ids=["n1", "n15", "n65"])
def test_approval_selftest_nonce_outside_class_refused(router, length):
    """Nonces of lengths outside [16, 64] are refused by `is_nonce`."""
    write_key(router, KEY_DEFAULT)
    nonce = "a" * length
    res = router.direct("approval-selftest", nonce)
    assert (res.rc, res.err, res.out) == (2, f"error bad-arg 1\n", "")


# ---- 2. The selftest domain prefix differs from the approval domain -----

def test_approval_selftest_domain_differs_from_approval(router):
    """The selftest output is NOT the approval token for the same string.

    Computing both in Python must give two distinct HMACs; the program
    must therefore print the selftest value (3.5f) and not the approval
    one (5.4)."""
    write_key(router, KEY_DEFAULT)
    nonce = NONCE_SHORT
    res = router.direct("approval-selftest", nonce)
    assert res.rc == 0
    selftest = selftest_hmac(KEY_DEFAULT, nonce)
    approval = approval_hmac(KEY_DEFAULT, nonce)
    assert selftest != approval
    assert res.out == f"approval-selftest {nonce} {selftest}\n"


# ---- 3. approval-selftest is direct-only and key-shape strict ------------

@pytest.mark.parametrize("role", ["read", "change"], ids=["role-read", "role-change"])
def test_approval_selftest_refused_in_forced_mode(router, role):
    """In forced mode the selftest must be refused (`direct-only`, 3) for
    every role (M43). The key is present and well-formed; the test is
    purely about door enforcement."""
    write_key(router, KEY_DEFAULT)
    res = router.forced(f"approval-selftest {NONCE_SHORT}", role=role)
    assert (res.rc, res.err, res.out) == (3, "error direct-only\n", "")


@pytest.mark.parametrize(
    "key_content,label",
    [
        (None, "missing"),
        ("0" * 63 + "\n", "63-hex"),
        ("0" * 64 + "0\n", "65-hex"),
        (("0" * 32 + "F" * 32) + "\n", "uppercase"),
        (("0" * 32 + "\n") * 2, "two-lines"),
        ("0" * 64 + " \n", "trailing-space"),
        ("z" * 64 + "\n", "non-hex"),
    ],
    ids=["missing", "63-hex", "65-hex", "uppercase", "two-lines",
         "trailing-space", "non-hex"],
)
def test_approval_selftest_key_problems_refused(router, key_content, label):
    """A key missing or malformed in any of the seven documented ways
    must be refused with `error approval-key-missing`, exit 3."""
    if key_content is None:
        (router.root / "etc/newton/approve.key").unlink()
    else:
        router.write("etc/newton/approve.key", key_content)
    res = router.direct("approval-selftest", NONCE_SHORT)
    assert (res.rc, res.err, res.out) == (3, "error approval-key-missing\n", "")


# ---- helpers for apply tests --------------------------------------------

DF_OUT = (
    "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
    "/dev/sda1 1000000 1000 999000 1% /etc\n"
)


def ready_for_arm(router):
    """The guard's `arm` step calls `df` to check disk space. The
    generic fake returns nothing by default, so we feed it a canned
    `df` line that the guard can parse."""
    router.set_fake("df", out=DF_OUT)


def seal_prod_plan(router, t=90, sid=SID, caller="agent-one", probes=b""):
    """A sealed prod plan plus a snapshot of its ingredients."""
    plan = router.fresh_plan(profile="prod", t=t, sid=sid, caller=caller,
                             probes=probes)
    ready_for_arm(router)
    return plan


def nothing_applied(router, sid):
    """All the post-refusal conditions from design 6.2 step 7/8."""
    txn = router.txn(sid)
    assert not (router.root / "etc/newton/pending").exists()
    assert not (router.root / "etc/newton/lkg").exists()
    calls = router.calls_matching("ubus uci-apply")
    assert not any(f" sid={sid}" in c for c in calls)
    return txn


def wrong_token_for_wrong_digest(router, plan, ingredient, nbf, exp):
    """The v2 token for a digest that differs from `plan.digest` in exactly
    one ingredient (3.5f/5.4: every ingredient is part of the digest).

    Used by test 4: the apply recomputes the digest from the live
    state of plan, so a token for a digest that differs in any one
    ingredient must be refused with `bad-approval`. The window (nbf, exp)
    is the same the test passes to apply; the HMAC covers it too.
    """
    other = {
        "device": "lab-r2",
        "sid": SID2,
        "base": "f" * 64,
        "diff": "e" * 64,
        "psha": "d" * 64,
        "t": 91,
    }[ingredient]
    if ingredient == "t":
        wrong_digest = plan_digest_py("lab-r1", plan.sid, plan.base,
                                      plan.diff, plan.psha, other)
    else:
        wrong_digest = plan_digest_py(other if ingredient == "device" else "lab-r1",
                                      other if ingredient == "sid" else plan.sid,
                                      other if ingredient == "base" else plan.base,
                                      other if ingredient == "diff" else plan.diff,
                                      other if ingredient == "psha" else plan.psha,
                                      plan.t)
    msg = f"newton-approval-v2\n{wrong_digest}\n{nbf}\n{exp}\n".encode()
    return hmac.new(bytes.fromhex(KEY_DEFAULT), msg, "sha256").hexdigest()


# ---- 4. Token rules at apply on a prod plan -----------------------------

def test_apply_prod_valid_token_applies_and_arms(router):
    """The exact token from the seal applies the prod plan: stdout is
    `applied <sid> t=<t> guard=<n>` and the guard goes `pending <sid>`."""
    plan = seal_prod_plan(router)
    nbf, exp = router.window()
    token = router.token(plan.digest, nbf, exp)
    res = router.apply(plan.sid, plan.t, token, nbf, exp)
    assert res.rc == 0
    assert res.err == ""
    assert re.fullmatch(
        rf"applied {plan.sid} t={plan.t} guard=\d+\n", res.out
    )
    assert router.guard_status().startswith(f"pending {plan.sid}")


def test_apply_prod_none_needs_approval(router):
    """`none` on a prod plan is refused with `needs-approval profile-prod`."""
    plan = seal_prod_plan(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.err, res.out) == (
        3, "error needs-approval profile-prod\n", ""
    )
    assert not (router.root / "etc/newton/pending").exists()
    assert not (router.root / "etc/newton/lkg").exists()


@pytest.mark.parametrize(
    "ingredient",
    ["device", "sid", "t", "base", "diff", "psha"],
    ids=["device", "sid", "t", "base", "diff", "probes"],
)
def test_apply_prod_wrong_ingredient_token_bad_approval(router, ingredient):
    """For each digest ingredient, a token computed for a digest that
    differs in that one ingredient is refused with `error bad-approval`."""
    plan = seal_prod_plan(router)
    nbf, exp = router.window()
    token = wrong_token_for_wrong_digest(router, plan, ingredient, nbf, exp)
    res = router.apply(plan.sid, plan.t, token, nbf, exp)
    assert (res.rc, res.err, res.out) == (3, "error bad-approval\n", "")
    assert not (router.root / "etc/newton/pending").exists()
    assert not (router.root / "etc/newton/lkg").exists()
    assert not any(f" sid={plan.sid}" in c
                   for c in router.calls_matching("ubus uci-apply"))


@pytest.mark.parametrize(
    "wrong_token,label",
    [
        ("0" * 63, "63-chars"),
        ("0" * 64 + "0", "65-chars"),
        ("F" * 64, "uppercase"),
    ],
    ids=["63-chars", "65-chars", "uppercase"],
)
def test_apply_prod_token_class_outside_is_bad_arg(router, wrong_token, label):
    """A token of the wrong shape (63/65 chars or uppercase) is refused
    by `is_token` with `error bad-arg 3` before apply runs."""
    plan = seal_prod_plan(router)
    res = router.apply(plan.sid, plan.t, wrong_token, 0, 0)
    assert (res.rc, res.err, res.out) == (2, "error bad-arg 3\n", "")
    assert not (router.root / "etc/newton/pending").exists()


def _flip(hex_str, index):
    flipped = "f" if hex_str[index] == "0" else "0"
    return hex_str[:index] + flipped + hex_str[index + 1:]


def test_apply_prod_first_hex_digit_flipped(router):
    """A wrong token whose first hex digit is flipped: a naive
    prefix-of-N-bytes comparison would miss the last bytes (M33)."""
    plan = seal_prod_plan(router)
    nbf, exp = router.window()
    right = router.token(plan.digest, nbf, exp)
    wrong = _flip(right, 0)
    assert wrong != right
    res = router.apply(plan.sid, plan.t, wrong, nbf, exp)
    assert (res.rc, res.err, res.out) == (3, "error bad-approval\n", "")


def test_apply_prod_last_hex_digit_flipped(router):
    """A wrong token whose last hex digit is flipped must be refused
    with `bad-approval`. The check is character-by-character all 64."""
    plan = seal_prod_plan(router)
    nbf, exp = router.window()
    right = router.token(plan.digest, nbf, exp)
    wrong = _flip(right, 63)
    assert wrong != right
    res = router.apply(plan.sid, plan.t, wrong, nbf, exp)
    assert (res.rc, res.err, res.out) == (3, "error bad-approval\n", "")


# ---- 5. The token is bound to the plan digest ---------------------------

def test_apply_token_binds_to_sealed_digest(router):
    """The token computed from `plan.digest` (as printed by seal) is the
    one the apply accepts. This proves the apply recomputes the same
    digest from its ingredients (5.4: "computed by the router at seal
    and again at apply")."""
    plan = seal_prod_plan(router)
    # The seal's `digest` line and the program-internal recomputation
    # must agree, otherwise the token the host derived would be wrong.
    nbf, exp = router.window()
    res = router.apply(plan.sid, plan.t, router.token(plan.digest, nbf, exp), nbf, exp)
    assert res.rc == 0 and res.err == ""
    assert res.out.startswith(f"applied {plan.sid} t={plan.t} guard=")


# ---- 6. Missing profile means prod (M32) --------------------------------

def test_apply_missing_profile_treated_as_prod(router):
    """If `etc/newton/profile` is absent, the profile defaults to prod
    (M32): apply with `none` is `needs-approval profile-prod`, and the
    valid token (whose digest does NOT depend on profile) applies."""
    plan = router.fresh_plan(profile="lab")
    (router.root / "etc/newton/profile").unlink()
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.err, res.out) == (
        3, "error needs-approval profile-prod\n", ""
    )
    ready_for_arm(router)
    nbf, exp = router.window()
    res = router.apply(plan.sid, plan.t, router.token(plan.digest, nbf, exp), nbf, exp)
    assert res.rc == 0 and res.err == ""
    assert res.out.startswith(f"applied {plan.sid} t={plan.t} guard=")


def test_apply_profile_changed_lab_to_prod_needs_token(router):
    """A plan sealed under `lab` that has since had its profile changed
    to `prod` is treated as prod at apply time. The token computed for
    the sealed digest (which does not include profile) still applies."""
    plan = router.fresh_plan(profile="lab")
    router.write("etc/newton/profile", "prod\n")
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.err, res.out) == (
        3, "error needs-approval profile-prod\n", ""
    )
    ready_for_arm(router)
    nbf, exp = router.window()
    res = router.apply(plan.sid, plan.t, router.token(plan.digest, nbf, exp), nbf, exp)
    assert res.rc == 0 and res.err == ""


# ---- 7. Key problems at apply on a prod plan ----------------------------

@pytest.mark.parametrize(
    "key_content,label",
    [
        (None, "missing"),
        ("0" * 63 + "\n", "63-hex"),
        ("z" * 64 + "\n", "non-hex"),
    ],
    ids=["missing", "63-hex", "non-hex"],
)
def test_apply_prod_key_problems_approval_key_missing(router, key_content, label):
    """A missing or malformed key on a prod apply must be refused
    with `error approval-key-missing`, exit 3."""
    plan = seal_prod_plan(router)
    if key_content is None:
        (router.root / "etc/newton/approve.key").unlink()
    else:
        router.write("etc/newton/approve.key", key_content)
    # The token was computed for the original key; the program at
    # apply time reads the (now missing/malformed) key and refuses.
    nbf, exp = router.window()
    token = router.token(plan.digest, nbf, exp, key_hex=KEY_DEFAULT)
    res = router.apply(plan.sid, plan.t, token, nbf, exp)
    assert (res.rc, res.err, res.out) == (3, "error approval-key-missing\n", "")
    assert not (router.root / "etc/newton/pending").exists()


def test_apply_lab_malformed_key_is_irrelevant(router):
    """A lab plan with no leash code does not need approval: a
    malformed key does not block the apply (5.3)."""
    # `none` and a wrong 64-hex token both apply; test the two
    # cases independently so the first apply's state does not
    # block the second plan's stage.
    plan = router.fresh_plan(profile="lab")
    ready_for_arm(router)
    router.write("etc/newton/approve.key", "z" * 64 + "\n")
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert res.rc == 0 and res.err == "", res


def test_apply_lab_malformed_key_wrong_64hex_token_applies(router):
    """A wrong 64-hex token on a lab plan with no leash code also
    applies (5.3). With the v2 window shape check, a 64-hex token requires
    NBF and EXP to be 10-digit; the apply still proceeds because the lab
    plan with no leash code does not call check_approval."""
    plan = router.fresh_plan(profile="lab")
    ready_for_arm(router)
    router.write("etc/newton/approve.key", "z" * 64 + "\n")
    nbf, exp = router.window()
    res = router.apply(plan.sid, plan.t, "0" * 64, nbf, exp)
    assert res.rc == 0 and res.err == "", res


# ---- 8. Lab plan with no leash code ignores the token -------------------

@pytest.mark.parametrize("token", ["none", "0" * 64])
def test_apply_lab_no_leash_applies_any_token(router, token):
    """A lab plan whose change carries no leash code does not check
    the token at all (5.3). The v2 shape check requires none+0,0 or
    64-hex+valid (nbf, exp); a token="none" gets (0, 0); a 64-hex token
    gets the router window."""
    plan = router.fresh_plan(profile="lab")
    ready_for_arm(router)
    if token == "none":
        nbf, exp = 0, 0
    else:
        nbf, exp = router.window()
    res = router.apply(plan.sid, plan.t, token, nbf, exp)
    assert res.rc == 0 and res.err == ""
    assert res.out.startswith(f"applied {plan.sid} t={plan.t} guard=")


def test_apply_lab_no_leash_valid_token_also_applies(router):
    """The valid token is also accepted on a lab plan with no leash code."""
    plan = router.fresh_plan(profile="lab")
    ready_for_arm(router)
    nbf, exp = router.window()
    res = router.apply(plan.sid, plan.t, router.token(plan.digest, nbf, exp), nbf, exp)
    assert res.rc == 0 and res.err == ""


# ---- 9. Lab plan WITH a leash code requires the token -------------------

def test_apply_lab_leash_change_requires_token(router):
    """A lab plan whose change carries a leash code (dropbear Port
    2222 -> `mgmt-config`) must require the token, even on a lab
    profile (5.2, 5.3).

    Built by hand from the dropbear-port scenario in `leash_corpus`:
    the seal reads the staged changes and the staged/committed views
    from the leash uci fake (via `sealed_scenario`), the staged file
    the apply will copy to etc/config/ lives at
    `control/staged/dropbear`, and the harness fake's `ubus call uci
    apply` performs the copy.
    """
    from leash_corpus import SCENARIOS, base_config
    from leash_model import Scenario

    scn_name, ops, expect, profile, zones = next(
        s for s in SCENARIOS if s[0] == "dropbear port"
    )
    assert "mgmt-config" in expect
    scn = Scenario(base_config(), ops, profile=profile, zones=zones)

    router.use_leash_uci()
    result = router.sealed_scenario(scn)
    assert (result.rc, result.err) == (0, "")
    assert any("leash mgmt-config" in l for l in result.out.splitlines())
    assert any("approval required" in l for l in result.out.splitlines())
    digest = parse_digest(result.out)
    assert digest and len(digest) == 64

    # The apply reads the health snapshot the seal set up. The
    # sealed_scenario helper does not create it; do it here.
    health = router.root / "tmp/owrt-safe-apply.lock" / f"{SID}.health"
    health.mkdir(parents=True, exist_ok=True)
    (health / "newton-fw4-loaded").write_text("0\n")
    # The guard's arm step calls `df`; feed it a parseable line.
    ready_for_arm(router)

    # The harness fake's uci-apply copies control/staged/ over
    # etc/config/. Write the staged file the dropbear port scenario
    # produces.
    router.write(
        "control/staged/dropbear",
        b"config dropbear\n\toption PasswordAuth 'on'\n\toption Port '2222'\n",
    )

    # `none` on a leash-coded lab plan needs approval.
    res = router.apply(SID, 90, "none", 0, 0)
    assert (res.rc, res.err, res.out) == (
        3, "error needs-approval mgmt-config\n", ""
    )
    assert not (router.root / "etc/newton/pending").exists()

    # The valid token applies.
    nbf, exp = router.window()
    res = router.apply(SID, 90, router.token(digest, nbf, exp), nbf, exp)
    assert res.rc == 0 and res.err == ""
    assert res.out.startswith(f"applied {SID} t=90 guard=")
    assert router.guard_status().startswith(f"pending {SID}")


# ---- 10. Approval is checked AFTER stage-age/boot/guard, BEFORE arm ----

def test_apply_stale_stage_wins_over_approval(router):
    """A stale stage (set_uptime past 2700 - t - 60) and `none` must
    give `stale-stage`, not `needs-approval`. The stage-age/boot/guard
    checks come before the approval check."""
    plan = seal_prod_plan(router)
    # Default stage_up is 100 (set in fresh_plan). t=90, age_limit =
    # 2700 - 90 - 60 = 2550. Set uptime so 2800 - 100 = 2700 > 2550.
    router.set_uptime(2800)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.err, res.out) == (3, "error stale-stage\n", "")
    assert not (router.root / "etc/newton/pending").exists()
    assert not (router.root / "etc/newton/lkg").exists()


def test_apply_bad_token_with_low_avail_still_bad_approval(router):
    """A bad token on a prod plan is refused with `bad-approval` even
    when `control/avail` is tiny (10). The guard never arms."""
    plan = seal_prod_plan(router)
    router.write("control/avail", "10\n")
    # Any wrong-but-well-formed token triggers the check.
    wrong = "0" * 64
    nbf, exp = router.window()
    res = router.apply(plan.sid, plan.t, wrong, nbf, exp)
    assert (res.rc, res.err, res.out) == (3, "error bad-approval\n", "")
    # Guard was never armed: the apply exits before the arm step.
    assert router.guard_status() == "idle"
    assert not (router.root / "etc/newton/pending").exists()
    assert not (router.root / "etc/newton/lkg").exists()
    assert not any(f" sid={plan.sid}" in c
                   for c in router.calls_matching("ubus uci-apply"))


# ---- 11. v2 token + window ----------------------------
#
# After SW2 the approval token binds NBF and EXP into the HMAC. These
# tests pin the new behaviour (the v2 token accepts a window, refuses
# outside it, refuses a v1 token over the same digest, refuses a v2 token
# minted for a different EXP, refuses bad-shape combinations, refuses
# non-digit date output, and refuses 3-word apply).


def test_apply_v2_token_inside_window_applies_and_arms(router):
    """A v2 token whose (nbf, exp) window contains `now` (the router's
    current wall clock, faked to `1700000000`) and where the window is at
    most 3600 s wide applies: the output is `applied <sid> t=<t> guard=<n>`
    and the guard goes `pending <sid>`."""
    plan = seal_prod_plan(router)
    nbf, exp = 1700000000, 1700003600
    router.set_fake("date", out="1700000000\n")
    token = router.token(plan.digest, nbf, exp)
    res = router.apply(plan.sid, plan.t, token, nbf, exp)
    assert res.rc == 0
    assert res.err == ""
    assert re.fullmatch(
        rf"applied {plan.sid} t={plan.t} guard=\d+\n", res.out
    )
    assert router.guard_status().startswith(f"pending {plan.sid}")


def test_apply_v1_domain_token_over_same_digest_bad_approval(router):
    """A v1-domain token (HMAC over only the digest, no NBF/EXP) is
    refused with `bad-approval` even when the apply passes a valid v2
    window. The window domain and the digest domain differ."""
    plan = seal_prod_plan(router)
    nbf, exp = router.window()
    v1 = approval_hmac(KEY_DEFAULT, plan.digest)
    res = router.apply(plan.sid, plan.t, v1, nbf, exp)
    assert (res.rc, res.err, res.out) == (3, "error bad-approval\n", "")
    assert router.guard_status() == "idle"
    assert not (router.root / "etc/newton/pending").exists()
    assert not any(f" sid={plan.sid}" in c
                   for c in router.calls_matching("ubus uci-apply"))


def test_apply_now_after_exp_refused_approval_window(router):
    """When now > EXP (the approval window has elapsed) the apply is
    refused with `approval-window`. The guard was never armed."""
    plan = seal_prod_plan(router)
    nbf, exp = 1700000000, 1700000600  # 10-minute window
    router.set_fake("date", out="1700000700\n")  # 100 s past EXP
    token = router.token(plan.digest, nbf, exp)
    res = router.apply(plan.sid, plan.t, token, nbf, exp)
    assert (res.rc, res.err, res.out) == (3, "error approval-window\n", "")
    assert router.guard_status() == "idle"
    assert not (router.root / "etc/newton/pending").exists()
    assert not any(f" sid={plan.sid}" in c
                   for c in router.calls_matching("ubus uci-apply"))


@pytest.mark.parametrize(
    "date_text,label",
    [
        ("0\n", "epoch"),
        ("1577836800\n", "2020-01-01"),
        ("NBF_MINUS_301\n", "nbf-minus-301"),
    ],
    ids=["date-zero", "date-2020-01-01", "date-nbf-minus-301"],
)
def test_apply_v2_token_router_clock_far_behind_accepted(router, date_text,
                                                           label):
    """A v2 token whose window is well-formed (EXP > NBF, EXP - NBF <= 3600)
    applies even when the router's wall clock is far behind NBF
    (design decision):
      - `date` outputs `0` (epoch: no RTC, fresh boot, WAN down)
      - `date` outputs `1577836800` (2020-01-01, clock never set)
      - `date` outputs `NBF - 301` (300 s plus one behind NBF)
    The window check looks only at expiry, not at start; replay stays
    bounded by single-use, digest binding and stage-age. The apply
    proceeds and arms, like `test_apply_v2_token_inside_window_applies_and_arms`."""
    plan = seal_prod_plan(router)
    nbf, exp = router.window()
    if label == "nbf-minus-301":
        date_text = f"{nbf - 301}\n"
    router.set_fake("date", out=date_text)
    token = router.token(plan.digest, nbf, exp)
    res = router.apply(plan.sid, plan.t, token, nbf, exp)
    assert res.rc == 0, res
    assert res.err == "", res
    assert re.fullmatch(
        rf"applied {plan.sid} t={plan.t} guard=\d+\n", res.out
    )
    assert router.guard_status().startswith(f"pending {plan.sid}")


def test_apply_v2_token_now_at_exp_accepted(router):
    """When now == EXP the upper bound is inclusive: a v2 token at the
    exact expiry moment still applies and arms."""
    plan = seal_prod_plan(router)
    nbf, exp = 1700000000, 1700000600  # 10-minute window
    router.set_fake("date", out=f"{exp}\n")
    token = router.token(plan.digest, nbf, exp)
    res = router.apply(plan.sid, plan.t, token, nbf, exp)
    assert res.rc == 0, res
    assert res.err == "", res
    assert re.fullmatch(
        rf"applied {plan.sid} t={plan.t} guard=\d+\n", res.out
    )
    assert router.guard_status().startswith(f"pending {plan.sid}")


def test_apply_window_exp_minus_nbf_3601_refused_approval_window(router):
    """When EXP - NBF = 3601 the window is too wide. With the same
    clock rule in play the apply is refused with `approval-window`."""
    plan = seal_prod_plan(router)
    nbf = 1700000000
    exp = nbf + 3601
    router.set_fake("date", out=f"{nbf + 100}\n")
    token = router.token(plan.digest, nbf, exp)
    res = router.apply(plan.sid, plan.t, token, nbf, exp)
    assert (res.rc, res.err, res.out) == (3, "error approval-window\n", "")
    assert router.guard_status() == "idle"


def test_apply_window_exp_equals_nbf_refused_approval_window(router):
    """When EXP == NBF the window is empty; the apply is refused with
    `approval-window`."""
    plan = seal_prod_plan(router)
    nbf = 1700000000
    exp = nbf
    router.set_fake("date", out=f"{nbf}\n")
    token = router.token(plan.digest, nbf, exp)
    res = router.apply(plan.sid, plan.t, token, nbf, exp)
    assert (res.rc, res.err, res.out) == (3, "error approval-window\n", "")
    assert router.guard_status() == "idle"


def test_apply_ex3_edited_exp_repro_bad_approval(router):
    """Repro: a token minted for (NBF, EXP1) but apply sent with
    the same NBF and a later EXP2 (still in window) yields `bad-approval`,
    because the v2 HMAC binds EXP into the message. This is the
    editing-the-file repro: an attacker who appends a later `expires_at`
    cannot extend an approval."""
    plan = seal_prod_plan(router)
    nbf = 1700000000
    exp_minted = nbf + 60
    router.set_fake("date", out=f"{nbf + 30}\n")
    token = router.token(plan.digest, nbf, exp_minted)
    later_exp = exp_minted + 30
    res = router.apply(plan.sid, plan.t, token, nbf, later_exp)
    assert (res.rc, res.err, res.out) == (3, "error bad-approval\n", "")
    assert router.guard_status() == "idle"
    assert not (router.root / "etc/newton/pending").exists()


def test_apply_token_none_zero_zero_needs_approval(router):
    """TOKEN=none NBF=0 EXP=0 on a prod plan: the window shape check
    accepts the combination, then the `none -> needs-approval` branch
    fires with `profile-prod`."""
    plan = seal_prod_plan(router)
    res = router.apply(plan.sid, plan.t, "none", 0, 0)
    assert (res.rc, res.err, res.out) == (
        3, "error needs-approval profile-prod\n", ""
    )
    assert not (router.root / "etc/newton/pending").exists()
    assert not (router.root / "etc/newton/lkg").exists()


def test_apply_token_none_with_nonzero_nbf_bad_request(router):
    """TOKEN=none with non-zero NBF: fails closed at the shape check
    with `bad-request approval-window-shape`. Nothing is armed."""
    plan = seal_prod_plan(router)
    res = router.apply(plan.sid, plan.t, "none", 1700000000, 0)
    assert (res.rc, res.err, res.out) == (
        2, "error bad-request approval-window-shape\n", ""
    )
    assert router.guard_status() == "idle"
    assert not (router.root / "etc/newton/pending").exists()
    assert not any(f" sid={plan.sid}" in c
                   for c in router.calls_matching("ubus uci-apply"))


def test_apply_hex_token_with_nbf_zero_bad_request(router):
    """A 64-hex token with NBF=0 fails the shape check: a 64-hex token
    requires both NBF and EXP to be 10-digit (not 0)."""
    plan = seal_prod_plan(router)
    nbf, exp = router.window()
    token = router.token(plan.digest, nbf, exp)
    res = router.apply(plan.sid, plan.t, token, 0, exp)
    assert (res.rc, res.err, res.out) == (
        2, "error bad-request approval-window-shape\n", ""
    )
    assert router.guard_status() == "idle"
    assert not any(f" sid={plan.sid}" in c
                   for c in router.calls_matching("ubus uci-apply"))


def test_apply_3_word_request_arg_count(router):
    """Three-word apply (SID T TOKEN) is refused with `arg-count` before
    any state is read. The grammar row's argmin is 5 user words; an old
    host sending 3 still fails closed here."""
    res = router.forced(
        "apply 0123456789abcdef0123456789abcdef 60 "
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        timeout=15,
    )
    assert (res.rc, res.err, res.out) == (2, "error arg-count\n", "")
    assert router.guard_status() == "idle"
    assert not any(f" sid=" in c
                   for c in router.calls_matching("ubus uci-apply"))


def test_apply_non_digit_date_approval_window_clock(router):
    """When the `date` output is not all digits (junk / partial /
    empty), the apply is refused with `approval-window clock`. The
    guard was never armed."""
    plan = seal_prod_plan(router)
    nbf, exp = router.window()
    token = router.token(plan.digest, nbf, exp)
    router.set_fake("date", out="not a number\n")
    res = router.apply(plan.sid, plan.t, token, nbf, exp)
    assert (res.rc, res.err, res.out) == (3, "error approval-window clock\n", "")
    assert router.guard_status() == "idle"
    assert not any(f" sid={plan.sid}" in c
                   for c in router.calls_matching("ubus uci-apply"))
