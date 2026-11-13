"""The settings items of the document are the fixed list (SPEC-1.3 section 5).

Section 5 says the settings items are exactly the fixed list of section 7,
and that wire.py validates it: an extra, a missing or a repeated key, or
a key of the other collector, is a document Newton refuses.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from newton_mcp.ad import queryset, wire

import docs


COLLECTOR_DIR = (
    Path(__file__).resolve().parents[2] / "newton_mcp" / "ad" / "collector"
)


@pytest.fixture
def loaded() -> queryset.QuerySet:
    return queryset.load()


def parse(document: dict[str, Any], loaded: queryset.QuerySet) -> wire.Document:
    return wire.parse(json.dumps(document).encode("utf-8"), loaded)


def refused(document: dict[str, Any], loaded: queryset.QuerySet) -> str:
    with pytest.raises(wire.WireError) as caught:
        parse(document, loaded)
    return str(caught.value)


@pytest.mark.parametrize("collector", ["windows", "samba"])
def test_the_fixed_list_of_each_collector_parses(
    loaded: queryset.QuerySet, collector: str
) -> None:
    """The whole list, every item unread, is a valid settings section."""
    document = docs.minimal_document(collector=collector)

    parsed = parse(document, loaded)

    keys = docs.SAMBA_SETTINGS if collector == "samba" else docs.WINDOWS_SETTINGS
    assert [item.key for item in parsed.settings.items] == list(keys)


def test_a_missing_setting_is_refused(loaded: queryset.QuerySet) -> None:
    """A list without one key of the fixed list is not the list."""
    document = docs.minimal_document()
    del document["settings"]["items"][3]

    assert "fixed settings list" in refused(document, loaded)


def test_an_extra_setting_is_refused(loaded: queryset.QuerySet) -> None:
    """A key the list does not hold is refused."""
    document = docs.minimal_document()
    document["settings"]["items"].append(
        {
            "source": "registry",
            "key": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Other",
            "status": "ok",
            "value": "1",
        }
    )

    assert "fixed settings list" in refused(document, loaded)


def test_a_repeated_setting_is_refused(loaded: queryset.QuerySet) -> None:
    """Two items of one key replace a key of the list: refused."""
    document = docs.minimal_document()
    items = document["settings"]["items"]
    items[1] = dict(items[0])

    assert "fixed settings list" in refused(document, loaded)


def test_a_setting_of_the_other_collector_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """A Windows document carries the registry list, never the loadparm one."""
    document = docs.minimal_document()
    document["settings"]["items"] = docs.settings_items("samba")

    assert "fixed settings list" in refused(document, loaded)


def test_a_setting_with_the_wrong_source_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """The source of every item is the source of the collector."""
    document = docs.minimal_document()
    document["settings"]["items"][0]["source"] = "loadparm"

    assert "fixed settings list" in refused(document, loaded)


def test_a_read_section_with_no_items_is_refused(
    loaded: queryset.QuerySet,
) -> None:
    """A settings section that says ok carries the whole list."""
    document = docs.minimal_document()
    document["settings"]["items"] = []

    assert "fixed settings list" in refused(document, loaded)


def test_an_unread_section_carries_no_items(loaded: queryset.QuerySet) -> None:
    """A section that was not collected holds no item, as both collectors write it."""
    document = docs.minimal_document()
    document["settings"]["status"] = "not_collected"
    document["settings"]["error_code"] = "not_a_dc"

    assert "fixed settings list" in refused(document, loaded)

    document["settings"]["items"] = []
    assert parse(document, loaded).settings.items == ()


def test_the_lists_of_wire_are_the_lists_of_the_collectors() -> None:
    """wire.py, collector.ps1 and newton-ad-samba name the same keys."""
    ps1 = (COLLECTOR_DIR / "collector.ps1").read_text(encoding="utf-8")
    block = ps1[ps1.index("$script:RegistrySettings = @(") :]
    block = block[: block.index("\n)\n")]
    windows = tuple(
        f"HKLM\\{path}\\{name}"
        for path, name in re.findall(
            r"@\{ path = '([^']+)'; name = '([^']+)' \}", block
        )
    )
    samba_text = (COLLECTOR_DIR / "newton-ad-samba").read_text(encoding="utf-8")
    samba_block = samba_text[samba_text.index("\nSETTINGS = (") :]
    samba_block = samba_block[: samba_block.index("\n)\n")]
    samba = tuple(re.findall(r'^    "([^"]+)",$', samba_block, re.MULTILINE))

    assert len(windows) == 10
    assert len(samba) == 9
    assert wire.SETTINGS_KEYS["windows"] == windows == docs.WINDOWS_SETTINGS
    assert wire.SETTINGS_KEYS["samba"] == samba == docs.SAMBA_SETTINGS
    assert wire.SETTINGS_SOURCE == {"windows": "registry", "samba": "loadparm"}
