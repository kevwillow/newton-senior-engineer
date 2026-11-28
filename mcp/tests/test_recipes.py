"""The recipe file: one format, one loader, one resolver.

A recipe is a reviewed TOML file next to the manifest, so the recipes dir
is ``<the manifest's dir>/recipes``.  No real recipe file is in the tree
yet: every test here writes a fixture recipe into a tmp dir and points
``NEWTON_MANIFEST`` at it.

The rules these tests hold:

* every param kind accepts the values of its own kind and refuses the
  rest, and a refusal names the PARAM and never the value;
* the file itself is refused when it carries an unknown key, a
  placeholder no param declares, a param nothing uses, an id that does
  not match the file name, or an id that is not a recipe id at all;
* ``when`` drops a step and its check when its param is not given;
* the substitution is one pass, so a value can never inject another
  placeholder;
* a broken file is listed with its error, never skipped silently.
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from newton_mcp import recipes as recipes_mod
from newton_mcp.recipes import RecipeError


# ---- fixtures --------------------------------------------------------------


def recipe_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the recipes dir at a tmp dir and return it."""
    profiles = tmp_path / "profiles" / "openwrt"
    recipes = profiles / "recipes"
    recipes.mkdir(parents=True, exist_ok=True)
    manifest = profiles / "manifest.toml"
    manifest.write_text("", encoding="utf-8")
    monkeypatch.setenv("NEWTON_MANIFEST", str(manifest))
    return recipes


def write_recipe(recipes: Path, name: str, body: str) -> Path:
    path = recipes / f"{name}.toml"
    path.write_text(body, encoding="utf-8")
    return path


def kind_recipe(kind: str, extra: str = "") -> str:
    """A recipe with one param of the given kind and one step using it."""
    return (
        'id = "kind-test"\n'
        'title = "Kind test"\n'
        'summary = "A recipe that exercises one param kind."\n'
        'platform = "openwrt"\n'
        'version = 1\n'
        'risk = "LOW: adds one line."\n'
        "\n"
        "[params.value]\n"
        f'kind = "{kind}"\n'
        'help = "the value under test"\n'
        f"{extra}"
        "\n"
        "[[steps]]\n"
        'kind = "uci"\n'
        'text = """\n'
        "set dhcp.skill.value='{value}'\n"
        '"""\n'
    )


#: The kind, a value of that kind, and the extra keys the kind needs.
KINDS: dict[str, tuple[str, str]] = {
    "ipv4": ("192.168.50.10", ""),
    "cidr4": ("192.168.50.1/24", ""),
    "mac": ("aa:bb:cc:dd:ee:ff", ""),
    "hostname": ("laptop", ""),
    "name": ("laptop", ""),
    "iface": ("br-lan", ""),
    "int": ("8080", "min = 1\nmax = 65535\n"),
    "choice": ("tcp", 'values = ["tcp", "udp"]\n'),
    "wifi_ssid": ("Guest", ""),
    "wifi_key": ("correct horse battery", ""),
    "wg_pubkey": (
        base64.b64encode(bytes(range(32))).decode("ascii"),
        "",
    ),
}

#: The bad values every kind refuses: a quote, a newline, a value that is
#: far too long, and an empty value.
COMMON_BAD: tuple[str, ...] = ("'", "\n", "a" * 64, "")

#: The kinds that refuse a brace.  The Wi-Fi name and the passphrase are
#: printable ASCII, so a brace is a value of theirs.
BRACE_KINDS: tuple[str, ...] = tuple(
    kind for kind in sorted(KINDS) if kind not in ("wifi_ssid", "wifi_key")
)

#: The bad values only one kind refuses.
KIND_BAD: dict[str, tuple[str, ...]] = {
    "ipv4": ("192.168.050.10", "192.168.50.10/24", "not-an-ip"),
    "cidr4": ("192.168.50.1", "192.168.50.1/31", "192.168.50.1/7"),
    "mac": ("aa:bb:cc:dd:ee", "aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff:00:11"),
    "hostname": ("Lap-top", "-laptop", "laptop-"),
    "name": ("Laptop", "1laptop", "laptop-x"),
    "iface": ("x" * 16, "br lan", "br/lan"),
    "int": ("08080", "8080.5", "-1", "99999", "0"),
    "choice": ("sctp",),
    "wifi_ssid": ("x" * 33, "a'b", "a\\b"),
    "wifi_key": ("short", "x" * 64, "a'b", "a\\b"),
    "wg_pubkey": (
        base64.b64encode(bytes(range(31))).decode("ascii"),
        base64.b64encode(bytes(range(33))).decode("ascii"),
    ),
}


# ---- the kinds -------------------------------------------------------------


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_a_kind_accepts_its_own_value(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every kind takes the values of its own kind."""
    recipes = recipe_dir(tmp_path, monkeypatch)
    good, extra = KINDS[kind]
    write_recipe(recipes, "kind-test", kind_recipe(kind, extra))

    recipe = recipes_mod.load_recipe("kind-test")
    resolved = recipes_mod.resolve(recipe, {"value": good})

    assert good in resolved["uci_batch"]
    assert "{" not in resolved["uci_batch"]


@pytest.mark.parametrize("kind", sorted(KINDS))
@pytest.mark.parametrize(
    "bad", COMMON_BAD, ids=["quote", "newline", "toolong", "empty"]
)
def test_a_kind_refuses_a_bad_value_by_name(
    kind: str,
    bad: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bad value is refused before anything else happens, the message
    names the param, and the value itself is never echoed."""
    recipes = recipe_dir(tmp_path, monkeypatch)
    _, extra = KINDS[kind]
    write_recipe(recipes, "kind-test", kind_recipe(kind, extra))

    recipe = recipes_mod.load_recipe("kind-test")
    with pytest.raises(RecipeError) as exc:
        recipes_mod.resolve(recipe, {"value": bad})

    message = str(exc.value)
    assert "value" in message, message
    if bad:
        assert bad not in message, message


@pytest.mark.parametrize("kind", BRACE_KINDS)
def test_a_kind_refuses_a_brace(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A brace is a value of the kinds that are not free text: it would
    end the UCI line it is written in."""
    recipes = recipe_dir(tmp_path, monkeypatch)
    _, extra = KINDS[kind]
    write_recipe(recipes, "kind-test", kind_recipe(kind, extra))

    recipe = recipes_mod.load_recipe("kind-test")
    with pytest.raises(RecipeError) as exc:
        recipes_mod.resolve(recipe, {"value": "{"})
    assert "value" in str(exc.value)
    assert "{" not in str(exc.value)


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_a_kind_refuses_the_values_only_it_refuses(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The values of another kind are refused too."""
    recipes = recipe_dir(tmp_path, monkeypatch)
    _, extra = KINDS[kind]
    write_recipe(recipes, "kind-test", kind_recipe(kind, extra))

    recipe = recipes_mod.load_recipe("kind-test")
    for bad in KIND_BAD[kind]:
        with pytest.raises(RecipeError) as exc:
            recipes_mod.resolve(recipe, {"value": bad})
        message = str(exc.value)
        assert "value" in message, message
        assert bad not in message, message


@pytest.mark.parametrize("kind", sorted(recipes_mod.KINDS))
def test_a_refusal_says_the_value_is_not_once(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The refusal of a bad value says "not" once.

    The table of kinds holds the reason of every kind ("not a dotted IPv4
    address"), so the refusal says "the value is not a dotted IPv4 address"
    and never "the value is not not a dotted IPv4 address".
    """
    recipes = recipe_dir(tmp_path, monkeypatch)
    _, extra = KINDS[kind]
    write_recipe(recipes, "kind-test", kind_recipe(kind, extra))

    recipe = recipes_mod.load_recipe("kind-test")
    for bad in KIND_BAD[kind]:
        with pytest.raises(RecipeError) as exc:
            recipes_mod.resolve(recipe, {"value": bad})
        message = str(exc.value)
        assert message.count("the value is not ") == 1, message
        assert "not not" not in message, message


def test_a_value_that_is_not_text_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recipes = recipe_dir(tmp_path, monkeypatch)
    write_recipe(recipes, "kind-test", kind_recipe("ipv4"))

    recipe = recipes_mod.load_recipe("kind-test")
    with pytest.raises(RecipeError) as exc:
        recipes_mod.resolve(recipe, {"value": 42})  # type: ignore[dict-item]
    assert "value" in str(exc.value)


def test_an_extra_value_name_is_refused_by_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recipes = recipe_dir(tmp_path, monkeypatch)
    write_recipe(recipes, "kind-test", kind_recipe("ipv4"))

    recipe = recipes_mod.load_recipe("kind-test")
    with pytest.raises(RecipeError) as exc:
        recipes_mod.resolve(recipe, {"value": "192.168.50.10", "bogus": "x"})
    assert "bogus" in str(exc.value)


def test_a_missing_required_value_is_refused_by_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recipes = recipe_dir(tmp_path, monkeypatch)
    write_recipe(recipes, "kind-test", kind_recipe("ipv4"))

    recipe = recipes_mod.load_recipe("kind-test")
    with pytest.raises(RecipeError) as exc:
        recipes_mod.resolve(recipe, {})
    assert "value" in str(exc.value)


# ---- the default -----------------------------------------------------------


#: A default that holds a quote, by the kind that must refuse it.
QUOTE_DEFAULTS: dict[str, str] = {
    "name": "a'b",
    "wifi_ssid": "a'b",
    "wifi_key": "pass'word",
}


@pytest.mark.parametrize("kind", sorted(QUOTE_DEFAULTS))
def test_a_default_with_a_quote_refuses_the_file(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A default is checked by the kind of its param when the file loads:
    a default that holds a quote refuses the file, and the default is
    never echoed."""
    recipes = recipe_dir(tmp_path, monkeypatch)
    default = QUOTE_DEFAULTS[kind]
    write_recipe(
        recipes,
        "kind-test",
        kind_recipe(kind, KINDS[kind][1] + f'default = "{default}"\n'),
    )

    with pytest.raises(RecipeError) as exc:
        recipes_mod.load_recipe("kind-test")

    message = str(exc.value)
    assert "kind-test" in message, message
    assert "value" in message, message
    assert "'" not in message, message
    assert default not in message, message


def test_a_default_with_a_newline_refuses_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A default that holds a newline would end the UCI line it is
    written in, so the file is refused."""
    recipes = recipe_dir(tmp_path, monkeypatch)
    write_recipe(
        recipes,
        "kind-test",
        kind_recipe("name", 'default = "a\\nb"\n'),
    )

    with pytest.raises(RecipeError) as exc:
        recipes_mod.load_recipe("kind-test")

    message = str(exc.value)
    assert "value" in message, message
    assert "a\nb" not in message, message


def test_an_int_default_outside_the_range_refuses_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An int default outside the min and max refuses the file."""
    recipes = recipe_dir(tmp_path, monkeypatch)
    write_recipe(
        recipes,
        "kind-test",
        kind_recipe("int", 'min = 1\nmax = 65535\ndefault = "70000"\n'),
    )

    with pytest.raises(RecipeError) as exc:
        recipes_mod.load_recipe("kind-test")

    message = str(exc.value)
    assert "value" in message, message
    assert "70000" not in message, message


def test_a_choice_default_outside_the_values_refuses_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A choice default that is not one of the values refuses the file."""
    recipes = recipe_dir(tmp_path, monkeypatch)
    write_recipe(
        recipes,
        "kind-test",
        kind_recipe("choice", 'values = ["tcp", "udp"]\ndefault = "sctp"\n'),
    )

    with pytest.raises(RecipeError) as exc:
        recipes_mod.load_recipe("kind-test")

    message = str(exc.value)
    assert "value" in message, message
    assert "sctp" not in message, message


def test_a_good_default_lands_in_the_batch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A default that is a value of its kind loads, and it lands in the
    batch when the value is not given."""
    recipes = recipe_dir(tmp_path, monkeypatch)
    write_recipe(
        recipes,
        "kind-test",
        kind_recipe("ipv4", 'default = "192.168.1.1"\n'),
    )

    recipe = recipes_mod.load_recipe("kind-test")
    resolved = recipes_mod.resolve(recipe, {})

    assert "set dhcp.skill.value='192.168.1.1'" in resolved["uci_batch"]


def test_a_default_is_stored_normalised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A default is stored the way its kind stores it: a MAC in lower
    case."""
    recipes = recipe_dir(tmp_path, monkeypatch)
    write_recipe(
        recipes,
        "kind-test",
        kind_recipe("mac", 'default = "AA:BB:CC:DD:EE:FF"\n'),
    )

    recipe = recipes_mod.load_recipe("kind-test")
    assert recipe["params"]["value"]["default"] == "aa:bb:cc:dd:ee:ff"

    resolved = recipes_mod.resolve(recipe, {})
    assert "set dhcp.skill.value='aa:bb:cc:dd:ee:ff'" in resolved["uci_batch"]


# ---- the step text ---------------------------------------------------------


def long_step_recipe(lines: int) -> str:
    """A recipe whose one step holds ``lines`` UCI lines."""
    body = "\n".join(
        f"set guest.network{index}.name='line{index}'" for index in range(lines)
    )
    return (
        'id = "kind-test"\n'
        'title = "Kind test"\n'
        'summary = "A recipe with one long step."\n'
        'platform = "openwrt"\n'
        'version = 1\n'
        'risk = "LOW: adds one section."\n'
        "\n"
        "[[steps]]\n"
        'kind = "uci"\n'
        'text = """\n'
        f"{body}\n"
        '"""\n'
    )


def test_a_step_of_forty_lines_loads_and_resolves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A guest network is about twenty UCI lines: a step holds them all."""
    recipes = recipe_dir(tmp_path, monkeypatch)
    write_recipe(recipes, "kind-test", long_step_recipe(40))

    recipe = recipes_mod.load_recipe("kind-test")
    resolved = recipes_mod.resolve(recipe, {})

    assert resolved["uci_batch"].count("set guest.network") == 40


def test_a_step_over_the_cap_refuses_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A step longer than 16384 characters refuses the file."""
    recipes = recipe_dir(tmp_path, monkeypatch)
    write_recipe(recipes, "kind-test", long_step_recipe(1000))

    with pytest.raises(RecipeError) as exc:
        recipes_mod.load_recipe("kind-test")

    message = str(exc.value)
    assert "16384" in message, message
    assert "step 1" in message, message


# ---- the empty value -------------------------------------------------------


def test_an_empty_value_takes_the_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty value for a param that has a default takes that default:
    a default is never dropped by an empty value."""
    recipes = recipe_dir(tmp_path, monkeypatch)
    write_recipe(
        recipes,
        "kind-test",
        kind_recipe("ipv4", 'default = "192.168.1.1"\n'),
    )

    recipe = recipes_mod.load_recipe("kind-test")
    resolved = recipes_mod.resolve(recipe, {"value": ""})

    assert "set dhcp.skill.value='192.168.1.1'" in resolved["uci_batch"]


def test_an_empty_value_with_an_empty_default_drops_the_when_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty value for a param whose default is empty stays "not given":
    the step and the check that need it are dropped."""
    recipes = recipe_dir(tmp_path, monkeypatch)
    write_recipe(
        recipes,
        "kind-test",
        'id = "kind-test"\n'
        'title = "Kind test"\n'
        'summary = "A recipe with an optional step."\n'
        'platform = "openwrt"\n'
        'version = 1\n'
        'risk = "LOW: adds one line."\n'
        "\n"
        "[params.value]\n"
        'kind = "ipv4"\n'
        'help = "the address"\n'
        "\n"
        "[params.net_name]\n"
        'kind = "wifi_ssid"\n'
        'help = "the optional name"\n'
        'default = ""\n'
        "\n"
        "[[steps]]\n"
        'kind = "uci"\n'
        'text = """\n'
        "set dhcp.skill.addr='{value}'\n"
        '"""\n'
        "\n"
        "[[steps]]\n"
        'kind = "uci"\n'
        'when = "net_name"\n'
        'text = """\n'
        "set wireless.skill.ssid='{net_name}'\n"
        '"""\n'
        "\n"
        "[[checks]]\n"
        'when = "net_name"\n'
        'probe = ["uci-equals", "wireless.skill.ssid", "{net_name}"]\n',
    )

    recipe = recipes_mod.load_recipe("kind-test")
    resolved = recipes_mod.resolve(
        recipe, {"value": "192.168.50.10", "net_name": ""}
    )

    assert "wireless.skill.ssid" not in resolved["uci_batch"]
    assert resolved["probes"] == []


def test_a_required_param_given_an_empty_value_is_refused_by_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A param with no default has nothing to fall back on: an empty value
    is refused by the name of the param."""
    recipes = recipe_dir(tmp_path, monkeypatch)
    write_recipe(recipes, "kind-test", kind_recipe("ipv4"))

    recipe = recipes_mod.load_recipe("kind-test")
    with pytest.raises(RecipeError) as exc:
        recipes_mod.resolve(recipe, {"value": ""})

    message = str(exc.value)
    assert "value" in message, message


# ---- the file itself ------------------------------------------------------


def test_an_unknown_key_refuses_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recipes = recipe_dir(tmp_path, monkeypatch)
    write_recipe(
        recipes,
        "kind-test",
        kind_recipe("ipv4") + 'extra_key = "surprise"\n',
    )

    with pytest.raises(RecipeError) as exc:
        recipes_mod.load_recipe("kind-test")
    assert "extra_key" in str(exc.value)


def test_an_unknown_param_key_refuses_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recipes = recipe_dir(tmp_path, monkeypatch)
    write_recipe(
        recipes,
        "kind-test",
        kind_recipe("ipv4").replace(
            'help = "the value under test"\n',
            'help = "the value under test"\nsurprise = 1\n',
        ),
    )

    with pytest.raises(RecipeError) as exc:
        recipes_mod.load_recipe("kind-test")
    assert "surprise" in str(exc.value)


def test_an_undeclared_placeholder_refuses_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recipes = recipe_dir(tmp_path, monkeypatch)
    write_recipe(
        recipes,
        "kind-test",
        kind_recipe("ipv4").replace("{value}", "{value} {nope}"),
    )

    with pytest.raises(RecipeError) as exc:
        recipes_mod.load_recipe("kind-test")
    assert "nope" in str(exc.value)


def test_an_unused_param_refuses_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recipes = recipe_dir(tmp_path, monkeypatch)
    write_recipe(
        recipes,
        "kind-test",
        kind_recipe("ipv4")
        + "\n[params.spare]\n"
        + 'kind = "ipv4"\n'
        + 'help = "nothing uses this"\n',
    )

    with pytest.raises(RecipeError) as exc:
        recipes_mod.load_recipe("kind-test")
    assert "spare" in str(exc.value)


def test_an_id_that_does_not_match_the_file_name_refuses_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recipes = recipe_dir(tmp_path, monkeypatch)
    write_recipe(
        recipes,
        "kind-test",
        kind_recipe("ipv4").replace('id = "kind-test"', 'id = "other-name"'),
    )

    with pytest.raises(RecipeError) as exc:
        recipes_mod.load_recipe("kind-test")
    assert "other-name" in str(exc.value)


@pytest.mark.parametrize("bad_id", ["../x", "X", "with space", "up/case", ""])
def test_a_recipe_id_that_is_not_a_recipe_id_is_refused(
    bad_id: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The id is checked before any path is built, so a name that walks
    out of the recipes dir never reaches the disk."""
    recipes = recipe_dir(tmp_path, monkeypatch)
    write_recipe(recipes, "kind-test", kind_recipe("ipv4"))

    with pytest.raises(RecipeError):
        recipes_mod.load_recipe(bad_id)


def test_a_recipe_that_is_not_valid_toml_refuses_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recipes = recipe_dir(tmp_path, monkeypatch)
    write_recipe(recipes, "kind-test", "id = \n")

    with pytest.raises(RecipeError):
        recipes_mod.load_recipe("kind-test")


def test_a_platform_other_than_openwrt_refuses_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recipes = recipe_dir(tmp_path, monkeypatch)
    write_recipe(
        recipes,
        "kind-test",
        kind_recipe("ipv4").replace('platform = "openwrt"', 'platform = "ad"'),
    )

    with pytest.raises(RecipeError) as exc:
        recipes_mod.load_recipe("kind-test")
    assert "openwrt" in str(exc.value)


def test_the_recipe_carries_the_sha256_of_its_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import hashlib

    recipes = recipe_dir(tmp_path, monkeypatch)
    path = write_recipe(recipes, "kind-test", kind_recipe("ipv4"))

    recipe = recipes_mod.load_recipe("kind-test")
    assert recipe["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()


# ---- when, and the one-pass substitution -----------------------------------


def test_when_drops_the_step_and_the_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A step (and its check) with a ``when`` is used only when that param
    is given."""
    recipes = recipe_dir(tmp_path, monkeypatch)
    write_recipe(
        recipes,
        "kind-test",
        'id = "kind-test"\n'
        'title = "Kind test"\n'
        'summary = "A recipe with an optional step."\n'
        'platform = "openwrt"\n'
        'version = 1\n'
        'risk = "LOW: adds one line."\n'
        "\n"
        "[params.value]\n"
        'kind = "ipv4"\n'
        'help = "the address"\n'
        "\n"
        "[params.net_name]\n"
        'kind = "wifi_ssid"\n'
        'help = "the optional name"\n'
        'default = ""\n'
        "\n"
        "[[steps]]\n"
        'kind = "uci"\n'
        'text = """\n'
        "set dhcp.skill.addr='{value}'\n"
        '"""\n'
        "\n"
        "[[steps]]\n"
        'kind = "uci"\n'
        'when = "net_name"\n'
        'text = """\n'
        "set wireless.skill.ssid='{net_name}'\n"
        '"""\n'
        "\n"
        "[[checks]]\n"
        'probe = ["uci-equals", "dhcp.skill.addr", "{value}"]\n'
        "\n"
        "[[checks]]\n"
        'when = "net_name"\n'
        'probe = ["uci-equals", "wireless.skill.ssid", "{net_name}"]\n',
    )

    recipe = recipes_mod.load_recipe("kind-test")
    without = recipes_mod.resolve(recipe, {"value": "192.168.50.10"})
    assert "wireless.skill.ssid" not in without["uci_batch"]
    assert len(without["probes"]) == 1

    with_name = recipes_mod.resolve(
        recipe, {"value": "192.168.50.10", "net_name": "newton-test"}
    )
    assert "wireless.skill.ssid='newton-test'" in with_name["uci_batch"]
    assert len(with_name["probes"]) == 2


def test_an_empty_value_for_an_optional_param_is_not_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty value is "not given", like the empty default: the step
    that needs the param is dropped, and nothing is refused."""
    recipes = recipe_dir(tmp_path, monkeypatch)
    write_recipe(
        recipes,
        "kind-test",
        'id = "kind-test"\n'
        'title = "Kind test"\n'
        'summary = "A recipe with an optional step."\n'
        'platform = "openwrt"\n'
        'version = 1\n'
        'risk = "LOW: adds one line."\n'
        "\n"
        "[params.value]\n"
        'kind = "ipv4"\n'
        'help = "the address"\n'
        "\n"
        "[params.net_name]\n"
        'kind = "wifi_ssid"\n'
        'help = "the optional name"\n'
        'default = ""\n'
        "\n"
        "[[steps]]\n"
        'kind = "uci"\n'
        'text = """\n'
        "set dhcp.skill.addr='{value}'\n"
        '"""\n'
        "\n"
        "[[steps]]\n"
        'kind = "uci"\n'
        'when = "net_name"\n'
        'text = """\n'
        "set wireless.skill.ssid='{net_name}'\n"
        '"""\n',
    )

    recipe = recipes_mod.load_recipe("kind-test")
    resolved = recipes_mod.resolve(
        recipe, {"value": "192.168.50.10", "net_name": ""}
    )

    assert "wireless.skill.ssid" not in resolved["uci_batch"]
    assert "set dhcp.skill.addr='192.168.50.10'" in resolved["uci_batch"]


def test_a_wifi_key_value_stays_literal_in_the_batch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The substitution is one pass: a value that looks like a
    placeholder stays the text it is."""
    recipes = recipe_dir(tmp_path, monkeypatch)
    write_recipe(
        recipes,
        "kind-test",
        'id = "kind-test"\n'
        'title = "Kind test"\n'
        'summary = "A recipe with a passphrase and a MAC."\n'
        'platform = "openwrt"\n'
        'version = 1\n'
        'risk = "LOW: adds one line."\n'
        "\n"
        "[params.mac]\n"
        'kind = "mac"\n'
        'help = "the device address"\n'
        "\n"
        "[params.net_key]\n"
        'kind = "wifi_key"\n'
        'help = "the passphrase"\n'
        "\n"
        "[[steps]]\n"
        'kind = "uci"\n'
        'text = """\n'
        "set dhcp.skill.mac='{mac}'\n"
        "set wireless.skill.key='{net_key}'\n"
        '"""\n',
    )

    recipe = recipes_mod.load_recipe("kind-test")
    resolved = recipes_mod.resolve(
        recipe, {"mac": "aa:bb:cc:dd:ee:ff", "net_key": "xx{mac}xx"}
    )

    assert "set wireless.skill.key='xx{mac}xx'" in resolved["uci_batch"]
    assert "set dhcp.skill.mac='aa:bb:cc:dd:ee:ff'" in resolved["uci_batch"]
    # the MAC is not substituted into the key: one pass, and no other
    assert resolved["uci_batch"].count("aa:bb:cc:dd:ee:ff") == 1


def test_a_resolved_check_must_pass_the_router_grammar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A check that the router would refuse refuses the recipe."""
    recipes = recipe_dir(tmp_path, monkeypatch)
    write_recipe(
        recipes,
        "kind-test",
        'id = "kind-test"\n'
        'title = "Kind test"\n'
        'summary = "A recipe with a bad check."\n'
        'platform = "openwrt"\n'
        'version = 1\n'
        'risk = "LOW: adds one line."\n'
        "\n"
        "[params.value]\n"
        'kind = "ipv4"\n'
        'help = "the address"\n'
        "\n"
        "[[steps]]\n"
        'kind = "uci"\n'
        'text = """\n'
        "set dhcp.skill.addr='{value}'\n"
        '"""\n'
        "\n"
        "[[checks]]\n"
        'probe = ["uci-equals", "dhcp.skill", "{value}"]\n',
    )

    recipe = recipes_mod.load_recipe("kind-test")
    with pytest.raises(RecipeError):
        recipes_mod.resolve(recipe, {"value": "192.168.50.10"})


# ---- the listing -----------------------------------------------------------


def test_list_recipes_lists_a_broken_file_with_its_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file that does not load is listed with its error, never skipped
    silently."""
    recipes = recipe_dir(tmp_path, monkeypatch)
    write_recipe(recipes, "aaa-good", kind_recipe("ipv4"))
    write_recipe(recipes, "bbb-broken", "id = \n")

    listed = recipes_mod.list_recipes("openwrt")

    broken = [entry for entry in listed if entry["id"] == "bbb-broken"]
    assert len(broken) == 1, listed
    assert broken[0]["error"], broken
    assert [entry["id"] for entry in listed] == ["aaa-good", "bbb-broken"]


def test_list_recipes_sorts_by_id_and_never_hides_a_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The listing is sorted by id, and a file of a platform 1.6.1 does
    not know is listed with its error, never skipped silently."""
    recipes = recipe_dir(tmp_path, monkeypatch)
    write_recipe(recipes, "zzz-last", kind_recipe("ipv4"))
    write_recipe(recipes, "aaa-first", kind_recipe("ipv4"))
    write_recipe(
        recipes,
        "mmm-other",
        kind_recipe("ipv4").replace('platform = "openwrt"', 'platform = "ad"'),
    )

    listed = recipes_mod.list_recipes("openwrt")
    assert [entry["id"] for entry in listed] == [
        "aaa-first",
        "mmm-other",
        "zzz-last",
    ]
    assert "error" in listed[1]


def test_list_recipes_of_an_empty_dir_is_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recipe_dir(tmp_path, monkeypatch)
    assert recipes_mod.list_recipes("openwrt") == []
