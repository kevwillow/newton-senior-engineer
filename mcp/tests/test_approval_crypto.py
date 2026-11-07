"""Unit tests of the shared approval crypto in newton_mcp.approve (round ap1).

``approval_token`` is pinned against vectors computed once OUTSIDE the
implementation with two independent methods: (1) hashlib/hmac in a fresh
python -c and (2) ``openssl dgst -sha256 -mac HMAC -macopt hexkey:...``
on the exact message bytes; both agreed on the literals below.

SW2 (design Item 2) moved the domain to ``newton-approval-v2`` and bound
the approval window: the message is
``newton-approval-v2\\n<digest>\\n<NBF>\\n<EXP>\\n`` with NBF/EXP the
decimal UNIX seconds of the approval's ``created_at``/``expires_at``.
"""

import pytest

import newton_mcp.approve as approve


K1 = "5f4dcc3b5aa765d61d8327deb882cf99425977a9a7573bb60b4a49796a5e2fd8"
D1 = "d357efe1f4c3b2a19087fe65dcba4321fedcba9876543210f0e1d2c3b4a59687"
NBF1 = 1790000000
EXP1 = 1790001800
T1 = "fed14253835411781c7c5ce44292aaf8b6ab77de1284624c68482e10352b8ec6"
K2 = "00" * 31 + "11"
D2 = "0000000000000000000000000000000000000000000000000000000000000abc"
NBF2 = 1000000000
EXP2 = 1000003600
T2 = "7f68fd34289a4425072772b6ad312608eb143e23529a41d2b4dcb6fe0796dca4"


def _message(digest, not_before, not_after):
    return (
        b"newton-approval-v2\n"
        + digest.encode("ascii")
        + b"\n"
        + str(not_before).encode("ascii")
        + b"\n"
        + str(not_after).encode("ascii")
        + b"\n"
    )


@pytest.mark.parametrize("k,d,nbf,exp,t", [(K1, D1, NBF1, EXP1, T1), (K2, D2, NBF2, EXP2, T2)])
def test_approval_token_matches_pinned_vectors(k, d, nbf, exp, t):
    import hashlib
    import hmac as _hmac

    assert approve.approval_token(k, d, nbf, exp) == t
    # recomputed in the test, not via the implementation under test
    recomputed = _hmac.new(
        bytes.fromhex(k),
        _message(d, nbf, exp),
        hashlib.sha256,
    ).hexdigest()
    assert t == recomputed


def test_approval_token_binds_digest_key_window_and_domain():
    """Every input the router recomputes changes the token (design Item 2).

    The window rows are the fix for this: an approval file whose ``expires_at``
    (and its ``not_after``) are edited cannot produce a token the router
    accepts, because the router recomputes over the values the host sends.
    """
    import hashlib
    import hmac as _hmac

    base = approve.approval_token(K1, D1, NBF1, EXP1)
    assert base == T1
    other_digest = D1[:-1] + ("0" if D1[-1] != "0" else "1")
    assert approve.approval_token(K1, other_digest, NBF1, EXP1) != base
    other_key = K1[:-1] + ("0" if K1[-1] != "0" else "1")
    assert approve.approval_token(other_key, D1, NBF1, EXP1) != base
    # a moved window -- either end -- gives a different token
    assert approve.approval_token(K1, D1, NBF1, EXP1 + 1) != base
    assert approve.approval_token(K1, D1, NBF1 + 1, EXP1) != base
    assert approve.approval_token(K1, D1, NBF1 + 1, EXP1 + 1) != base
    # the v1 domain over the same digest gives a different token: an old
    # token fails bad-approval on the new router and vice versa
    v1_message = b"newton-approval-v1\n" + D1.encode("ascii") + b"\n"
    assert _hmac.new(bytes.fromhex(K1), v1_message, hashlib.sha256).hexdigest() != base
    assert approve.approval_token(K1, D1, NBF1, EXP1) == T1 != v1_message.decode()


@pytest.mark.parametrize(
    "k", ["", "zz" * 32, "AB" * 32, "0" * 63, "0" * 65, 64, None, b"0" * 64]
)
def test_approval_token_refuses_bad_key(k):
    with pytest.raises(ValueError) as exc:
        approve.approval_token(k, D1, NBF1, EXP1)
    assert K1 not in str(exc.value) and T1 not in str(exc.value)


@pytest.mark.parametrize(
    "d", ["", "g" * 64, "A" * 64, "0" * 63, "0" * 65, 64, None, b"0" * 64]
)
def test_approval_token_refuses_bad_digest(d):
    with pytest.raises(ValueError) as exc:
        approve.approval_token(K1, d, NBF1, EXP1)
    assert D1 not in str(exc.value)


# ---- the approval window is 10 decimal UNIX seconds, NBF < EXP --------------


@pytest.mark.parametrize(
    "nbf",
    [
        999999999,          # below the window floor
        10000000000,        # above the window ceiling
        0,
        -1790000000,
        True,               # bool is not an int here
        False,
        1790000000.0,       # float
        "1790000000",       # string
        b"1790000000",
        None,
    ],
)
def test_approval_token_refuses_a_bad_not_before(nbf):
    with pytest.raises(ValueError) as exc:
        approve.approval_token(K1, D1, nbf, EXP1)
    assert K1 not in str(exc.value) and D1 not in str(exc.value)


@pytest.mark.parametrize(
    "exp",
    [999999999, 10000000000, 0, -1790001800, True, False, 1790001800.0, "1790001800", b"1", None],
)
def test_approval_token_refuses_a_bad_not_after(exp):
    with pytest.raises(ValueError) as exc:
        approve.approval_token(K1, D1, NBF1, exp)
    assert K1 not in str(exc.value) and D1 not in str(exc.value)


@pytest.mark.parametrize("exp", [NBF1, NBF1 - 1, NBF1 - 1800])
def test_approval_token_refuses_a_window_that_does_not_move_forward(exp):
    with pytest.raises(ValueError) as exc:
        approve.approval_token(K1, D1, NBF1, exp)
    assert K1 not in str(exc.value) and D1 not in str(exc.value)


def test_approval_token_accepts_the_window_bounds():
    assert approve.approval_token(K1, D1, 1000000000, 1000000001)
    assert approve.approval_token(K1, D1, 9999999998, 9999999999)


def test_approval_token_error_names_no_secret():
    with pytest.raises(ValueError) as exc:
        approve.approval_token(K1, D1[:-1], NBF1, EXP1)
    message = str(exc.value)
    assert K1 not in message and T1 not in message and D1[:-1] not in message


# ---- derive_k input validation ---------------------------------------------


@pytest.mark.parametrize(
    "pp", [b"", bytearray(b""), "not-bytes", None, 42]
)
def test_derive_k_refuses_bad_passphrase(pp):
    with pytest.raises(ValueError):
        approve.derive_k(pp, "quasar")


@pytest.mark.parametrize(
    "dev", ["", "Quasar", "1abc", "-abc", "a" * 33, "a_b", None, 42]
)
def test_derive_k_refuses_bad_device(dev):
    with pytest.raises(ValueError):
        approve.derive_k(b"passphrase", dev)


def test_derive_k_shape():
    k = approve.derive_k(b"made-up-pass", "quasar")
    assert len(k) == 64
    assert all(c in "0123456789abcdef" for c in k)


# ---- read_passphrase_file ---------------------------------------------------


def test_read_passphrase_file_strips_exactly_one_lf(tmp_path):
    f = tmp_path / "pp"
    f.write_bytes(b"secret\n")
    assert approve.read_passphrase_file(f) == b"secret"
    f.write_bytes(b"secret")
    assert approve.read_passphrase_file(f) == b"secret"
    f.write_bytes(b"secret\n\n")
    assert approve.read_passphrase_file(f) == b"secret\n"
    f.write_bytes(b"secret\r\n")
    assert approve.read_passphrase_file(f) == b"secret\r"
    f.write_bytes(b"\n")
    assert approve.read_passphrase_file(f) == b""
