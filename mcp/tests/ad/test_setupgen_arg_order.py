"""newton-ad-setup with its options before the write or approval-key word
says where that word goes, instead of an invalid choice of platform."""

from __future__ import annotations

import pytest

from newton_mcp.ad import setupgen


@pytest.mark.parametrize(
    "argv",
    [
        ["--domain", "lab.example", "write", "windows"],
        ["--domain", "lab.example", "--host", "dc1", "write", "samba", "--ou", "OU=x"],
        ["--device", "lab", "approval-key", "lab"],
    ],
)
def test_the_write_word_after_an_option_names_the_right_order(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    status = setupgen.main(argv)

    assert status == 2
    err = " ".join(capsys.readouterr().err.split())
    assert "invalid choice" not in err
    assert "newton-ad-setup write windows|samba" in err
    assert "newton-ad-setup approval-key NAME" in err


def test_a_device_named_write_after_the_platform_is_not_taken_for_the_word(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The first word is the platform: an option value later on is never
    read as the write word."""
    with pytest.raises(SystemExit):
        setupgen.main(["windows", "--device", "write"])
    assert "write windows|samba" not in capsys.readouterr().err
