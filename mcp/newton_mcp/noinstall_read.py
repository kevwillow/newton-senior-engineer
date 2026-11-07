"""The reads a no-install router can answer over its own web API.

ADR-021 point 2 and the lab measurement (lab-r1, OpenWrt 25.12.5,
2026-10-30): in the no-install mode Newton puts nothing on the router
and asks the router's own web API instead.  A limited rpcd user may
read a fixed set of things through it, and nothing else.  This module
maps the read forms the model may ask for onto those calls.

The rules:

  * the command goes through ``validate_read`` first, so a command the
    installed path refuses is refused here with the same message;
  * every read is one fresh session (30 s), one read call, and then the
    session is left to expire.  No write call is ever made: the
    session wrapper refuses any call that is not on the read list;
  * the rpcd password comes from the device's own password file and
    never appears in a result, an error or a log;
  * a form the web API cannot read is refused by name, in plain words:
    the agent is told what it would need, not given a code.

What is SYNTHESISED (the lab did not measure it):

  * the ``uci show`` text.  The web API answers a config with the
    sections and their options; Newton prints them the way uci prints
    them: a ``config.name=type`` header line, then one
    ``config.name.option='value'`` line per option, the sections in the
    order of their index, a list as ``'a' 'b'``, and a value quoted the
    way uci quotes it (a quote inside a value becomes ``'\\''``).  The
    section name is the name the answer carries (for an anonymous
    section, the router's own ``cfgXXXXXX`` name).
  * the DHCP lease file.  The web API answers with the fields of a
    lease; Newton prints them in dnsmasq's lease-file order
    (``expires mac ip hostname clientid``) with ``*`` for a field the
    answer does not carry.  The lab's router had no leases, so the
    answer's own field names are a guess.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Mapping

from . import credential_file
from . import envelope as _envelope
from .adapters import openwrt_rpcd as rpcd
from .adapters.openwrt_rpcd import RpcdCallFailed, RpcdError
from .server import NewtonError, scrub_read_text, validate_read

if TYPE_CHECKING:  # pragma: no cover - the type only
    from .server import Device


#: The session a read asks for: long enough for one call, short enough
#: that a forgotten session dies on its own.
LOGIN_TIMEOUT_S = 30

#: The configs the stock groups may read.  A config outside this list is
#: refused before the router is asked: the router answers such a config
#: with "permission denied" anyway.
READABLE_CONFIGS: tuple[str, ...] = (
    "dhcp",
    "firewall",
    "luci",
    "network",
    "system",
    "wireless",
)

#: The number of log lines a read asks for when it names none.
DEFAULT_LOG_LINES = 100

#: The rpcd calls a read may make.  Everything else is refused before it
#: reaches the wire: a read never writes, and it never stages, applies
#: or confirms anything.
ALLOWED_CALLS: frozenset[tuple[str, str]] = frozenset(
    {
        ("uci", "get"),
        ("system", "board"),
        ("system", "info"),
        ("network.interface", "dump"),
        ("network.device", "status"),
        ("service", "list"),
        ("log", "read"),
        ("iwinfo", "assoclist"),
        ("iwinfo", "freqlist"),
        ("iwinfo", "txpowerlist"),
        ("iwinfo", "countrylist"),
        ("luci-rpc", "getDHCPLeases"),
        ("file", "exec"),
        ("file", "read"),
    }
)

#: The hint the system reads carry.
SYSTEM_INFO_HINT = "Use `ubus call system info` for the same information."


# ---- the refusal messages --------------------------------------------------


def refusal(form: str, hint: str = "") -> str:
    """The message for a form the web API cannot read.

    The form is named by its verb; the router's own text never appears
    in it.
    """
    message = (
        f"{form} is not available in no-install access; the router's web API "
        "cannot read it. Installed access can."
    )
    if hint:
        message = f"{message} {hint}"
    return message


def config_refusal(config: str) -> str:
    """The message for a config the stock groups may not read."""
    return (
        f"uci show {config} is not readable in no-install access; the router's "
        "web API cannot read that config. Installed access can."
    )


# ---- the plan of one read --------------------------------------------------


@dataclass(frozen=True)
class _Call:
    """One rpcd call."""

    obj: str
    fn: str
    args: dict[str, Any]


@dataclass(frozen=True)
class _Plan:
    """What one read does: the call, and how the answer becomes text."""

    call: _Call
    render: Callable[[Any], tuple[str, str, int]]
    on_error: Callable[[int], tuple[str, str, int]] | None = None


def _generic_error(code: int) -> tuple[str, str, int]:
    return ("", "the router refused the read\n", 1)


def _uci_error(code: int) -> tuple[str, str, int]:
    if code == 4:
        return ("", "uci: Entry not found\n", 1)
    if code == 6:
        return ("", "uci: Permission denied\n", 1)
    return ("", "uci: the router refused the read\n", 1)


def _iwinfo_error(code: int) -> tuple[str, str, int]:
    if code == 4:
        return ("", "No such wireless device\n", 1)
    return ("", "the router refused the read\n", 1)


# ---- the value renderings --------------------------------------------------


def _quote(value: str) -> str:
    """A value as uci prints it: in single quotes, a quote escaped."""
    return "'" + value.replace("'", "'\\''") + "'"


def _scalar(value: Any) -> str:
    """A value as uci keeps it."""
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value)


def _show_value(value: Any) -> str:
    """A value as a uci show line carries it."""
    if isinstance(value, (list, tuple)):
        return " ".join(_quote(_scalar(item)) for item in value)
    return _quote(_scalar(value))


def _bare_value(value: Any) -> str:
    """A value as ``uci get`` prints it: a list space-separated."""
    if isinstance(value, (list, tuple)):
        return " ".join(_scalar(item) for item in value)
    return _scalar(value)


def _sections_in_order(values: Mapping[str, Any]) -> list[tuple[str, Mapping[str, Any]]]:
    """The sections of a config, in the order of their index."""
    items = [
        (key, value)
        for key, value in values.items()
        if isinstance(value, Mapping)
    ]

    def order(item: tuple[str, Mapping[str, Any]]) -> tuple[int, int, str]:
        index = item[1].get(".index")
        if isinstance(index, int) and not isinstance(index, bool):
            return (0, index, item[0])
        return (1, 0, item[0])

    return sorted(items, key=order)


def _option_lines(config: str, name: str, section: Mapping[str, Any]) -> list[str]:
    """The option lines of one section, as uci prints them."""
    lines = []
    for option, value in section.items():
        if option.startswith("."):
            continue
        lines.append(f"{config}.{name}.{option}={_show_value(value)}")
    return lines


def _show_config(config: str, values: Mapping[str, Any]) -> str:
    """The text of ``uci show CONFIG``."""
    lines: list[str] = []
    for key, section in _sections_in_order(values):
        name = section.get(".name")
        if not isinstance(name, str) or not name:
            name = key
        section_type = section.get(".type")
        if not isinstance(section_type, str):
            section_type = ""
        lines.append(f"{config}.{name}={section_type}")
        lines.extend(_option_lines(config, name, section))
    return "\n".join(lines) + "\n" if lines else ""


def _show_section(config: str, requested: str, section: Mapping[str, Any]) -> str:
    """The text of ``uci show CONFIG.SECTION``."""
    name = section.get(".name")
    if not isinstance(name, str) or not name:
        name = requested
    section_type = section.get(".type")
    if not isinstance(section_type, str):
        section_type = ""
    lines = [f"{config}.{name}={section_type}"]
    lines.extend(_option_lines(config, name, section))
    return "\n".join(lines) + "\n"


def _render_json(answer: Any) -> tuple[str, str, int]:
    """A ubus answer as ``ubus call`` prints it."""
    return (json.dumps(answer, indent="\t") + "\n", "", 0)


def _render_interface(name: str) -> Callable[[Any], tuple[str, str, int]]:
    """The renderer for ``ubus call network.interface.NAME status``."""

    def render(answer: Any) -> tuple[str, str, int]:
        entries = answer.get("interface") if isinstance(answer, Mapping) else None
        if isinstance(entries, (list, tuple)):
            for entry in entries:
                if isinstance(entry, Mapping) and entry.get("interface") == name:
                    return _render_json(entry)
        return ("", "Command failed: Not found\n", 4)

    return render


def _render_leases(answer: Any) -> tuple[str, str, int]:
    """The lease file's lines, built from the web API's answer."""
    leases = answer.get("dhcp_leases") if isinstance(answer, Mapping) else None
    lines: list[str] = []
    if isinstance(leases, (list, tuple)):
        for lease in leases:
            if not isinstance(lease, Mapping):
                continue
            fields = []
            for field in ("expires", "mac", "ip", "hostname", "clientid"):
                value = lease.get(field)
                if value is None or value == "":
                    fields.append("*")
                else:
                    fields.append(str(value))
            lines.append(" ".join(fields))
    return ("\n".join(lines) + "\n" if lines else "", "", 0)


def _render_exec(answer: Any) -> tuple[str, str, int]:
    """The answer of ``file exec``: its exit code and its output."""
    if not isinstance(answer, Mapping):
        return ("", "the answer could not be read\n", 1)
    code = answer.get("code")
    if isinstance(code, bool) or not isinstance(code, int):
        return ("", "the answer could not be read\n", 1)
    stdout = answer.get("stdout")
    if not isinstance(stdout, str):
        stdout = ""
    return (stdout, "", code)


# ---- the forms -------------------------------------------------------------


def _split_uci_path(path: str) -> tuple[str, str, str | None]:
    """A uci path as (config, section, option)."""
    parts = path.split(".")
    if len(parts) >= 3:
        return parts[0], parts[1], parts[2]
    if len(parts) == 2:
        return parts[0], parts[1], None
    return parts[0], "", None


def _plan_uci(tokens: list[str]) -> _Plan:
    """The uci forms."""
    verb = tokens[1]
    if verb in ("export", "changes"):
        raise NewtonError(refusal(f"uci {verb}"))
    path = tokens[2] if len(tokens) > 2 else None
    if path is None:
        raise NewtonError(
            "uci show without a config is not available in no-install access; "
            "name a config to read. Installed access can."
        )
    config, section, option = _split_uci_path(path)
    if config not in READABLE_CONFIGS:
        raise NewtonError(config_refusal(config))
    args: dict[str, Any] = {"config": config}
    if section:
        args["section"] = section
    if option:
        args["option"] = option
    call = _Call("uci", "get", args)
    if verb == "get":
        if not option:
            # ``uci get`` of a whole section has no bare value to print;
            # ``uci show`` of the same section does.
            raise NewtonError(refusal("uci get of a section"))
        return _Plan(call, _render_uci_get_option(), _uci_error)
    if option:
        return _Plan(call, _render_uci_show_option(config, section, option), _uci_error)
    if section:
        return _Plan(call, _render_uci_show_section(config, section), _uci_error)
    return _Plan(call, _render_uci_show_config(config), _uci_error)


def _values_of(answer: Any) -> Mapping[str, Any]:
    if isinstance(answer, Mapping):
        values = answer.get("values")
        if isinstance(values, Mapping):
            return values
    return {}


def _uci_not_found() -> tuple[str, str, int]:
    """What uci prints when the entry is not there."""
    return ("", "uci: Entry not found\n", 1)


def _render_uci_show_config(config: str) -> Callable[[Any], tuple[str, str, int]]:
    def render(answer: Any) -> tuple[str, str, int]:
        values = _values_of(answer)
        if not values:
            return _uci_not_found()
        return (_show_config(config, values), "", 0)

    return render


def _render_uci_show_section(
    config: str, requested: str
) -> Callable[[Any], tuple[str, str, int]]:
    def render(answer: Any) -> tuple[str, str, int]:
        values = _values_of(answer)
        if not values:
            return _uci_not_found()
        return (_show_section(config, requested, values), "", 0)

    return render


def _render_uci_show_option(
    config: str, section: str, option: str
) -> Callable[[Any], tuple[str, str, int]]:
    def render(answer: Any) -> tuple[str, str, int]:
        if not isinstance(answer, Mapping) or "value" not in answer:
            return _uci_not_found()
        return (f"{config}.{section}.{option}={_show_value(answer['value'])}\n", "", 0)

    return render


def _render_uci_get_option() -> Callable[[Any], tuple[str, str, int]]:
    def render(answer: Any) -> tuple[str, str, int]:
        if not isinstance(answer, Mapping) or "value" not in answer:
            return _uci_not_found()
        return (_bare_value(answer["value"]) + "\n", "", 0)

    return render


def _plan_ubus(tokens: list[str]) -> _Plan:
    """The ubus forms."""
    if tokens[1] == "list":
        raise NewtonError(refusal("ubus list"))
    obj, method = tokens[2], tokens[3]
    if obj == "system" and method in ("board", "info"):
        return _Plan(_Call("system", method, {}), _render_json)
    if obj == "network.interface" and method == "dump":
        return _Plan(_Call("network.interface", "dump", {}), _render_json)
    if obj == "network.device" and method == "status":
        return _Plan(_Call("network.device", "status", {}), _render_json)
    if obj == "network.wireless" and method == "status":
        raise NewtonError(refusal("ubus call network.wireless status"))
    if obj.startswith("network.interface.") and method == "status":
        name = obj[len("network.interface.") :]
        return _Plan(_Call("network.interface", "dump", {}), _render_interface(name))
    raise NewtonError(refusal(f"ubus call {obj} {method}"))


def _plan_logread(tokens: list[str]) -> _Plan:
    """The logread forms."""
    lines = DEFAULT_LOG_LINES
    pattern: str | None = None
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == "-l" and index + 1 < len(tokens):
            lines = int(tokens[index + 1])
            index += 2
            continue
        if token == "-e" and index + 1 < len(tokens):
            pattern = tokens[index + 1]
            index += 2
            continue
        index += 1
    return _Plan(
        _Call("log", "read", {"lines": lines, "stream": False}),
        _render_log(pattern),
    )


def _render_log(pattern: str | None) -> Callable[[Any], tuple[str, str, int]]:
    def render(answer: Any) -> tuple[str, str, int]:
        entries = answer.get("log") if isinstance(answer, Mapping) else None
        lines: list[str] = []
        if isinstance(entries, (list, tuple)):
            for entry in entries:
                message = entry.get("msg") if isinstance(entry, Mapping) else None
                if not isinstance(message, str):
                    continue
                if pattern is not None and pattern not in message:
                    continue
                lines.append(message)
        return ("\n".join(lines) + "\n" if lines else "", "", 0)

    return render


def _plan_cat(tokens: list[str]) -> _Plan:
    """The cat forms."""
    path = tokens[1]
    if path == "/tmp/dhcp.leases":
        return _Plan(_Call("luci-rpc", "getDHCPLeases", {}), _render_leases)
    if path in ("/proc/uptime", "/proc/loadavg", "/proc/meminfo"):
        raise NewtonError(refusal(f"cat {path}", SYSTEM_INFO_HINT))
    raise NewtonError(refusal(f"cat {path}"))


def _plan_iwinfo(tokens: list[str]) -> _Plan:
    """The iwinfo forms."""
    if len(tokens) == 1:
        raise NewtonError(refusal("iwinfo"))
    iface = tokens[1]
    if len(tokens) == 2:
        raise NewtonError(refusal(f"iwinfo {iface} info"))
    word = tokens[2]
    if word not in ("assoclist", "freqlist", "txpowerlist", "countrylist"):
        raise NewtonError(refusal(f"iwinfo {iface} {word}"))
    return _Plan(
        _Call("iwinfo", word, {"device": iface}),
        _render_json,
        _iwinfo_error,
    )


def _plan_ping(tokens: list[str]) -> _Plan:
    """The ping form."""
    count, host = tokens[2], tokens[3]
    return _Plan(
        _Call("file", "exec", {"command": "/bin/ping", "params": ["-c", count, "-W", "2", host]}),
        _render_exec,
    )


def _plan_traceroute(tokens: list[str]) -> _Plan:
    """The traceroute form."""
    host = tokens[1]
    return _Plan(
        _Call("file", "exec", {"command": "/bin/traceroute", "params": ["-w", "2", host]}),
        _render_exec,
    )


def _plan_nslookup(tokens: list[str]) -> _Plan:
    """The nslookup forms."""
    params = [tokens[1]]
    if len(tokens) > 2:
        params.append(tokens[2])
    return _Plan(
        _Call("file", "exec", {"command": "/usr/bin/nslookup", "params": params}),
        _render_exec,
    )


def _refuse_plan(form: str, hint: str = "") -> Callable[[list[str]], _Plan]:
    def plan(_tokens: list[str]) -> _Plan:
        raise NewtonError(refusal(form, hint))

    return plan


_HANDLERS: dict[str, Callable[[list[str]], _Plan]] = {
    "uci": _plan_uci,
    "ubus": _plan_ubus,
    "logread": _plan_logread,
    "cat": _plan_cat,
    "iwinfo": _plan_iwinfo,
    "ping": _plan_ping,
    "traceroute": _plan_traceroute,
    "nslookup": _plan_nslookup,
    "uptime": _refuse_plan("uptime", SYSTEM_INFO_HINT),
    "free": _refuse_plan("free", SYSTEM_INFO_HINT),
    "nft": _refuse_plan("nft"),
    "fw4": _refuse_plan("fw4"),
    "ip": _refuse_plan("ip"),
    "ifstatus": _refuse_plan("ifstatus"),
    "netstat": _refuse_plan("netstat"),
    "df": _refuse_plan("df"),
    "uname": _refuse_plan("uname"),
    "apk": _refuse_plan("apk"),
    "wifi": _refuse_plan("wifi status"),
    "wifiscan": _refuse_plan("wifiscan"),
}


# ---- the session -----------------------------------------------------------


class _Session:
    """One rpcd session, with only the read calls allowed."""

    def __init__(self, client: Any, session: Any) -> None:
        self._client = client
        self._session = session

    def call(
        self,
        obj: str,
        fn: str,
        args: Mapping[str, Any] | None = None,
    ) -> Any:
        if (obj, fn) not in ALLOWED_CALLS:
            raise NewtonError("this read may not make that call")
        return self._client.call(self._session, obj, fn, dict(args or {}))


def default_client_factory(device: "Device") -> Any:
    """The real client: a pinned HTTPS JSON-RPC client for the router."""
    return rpcd.RpcdClient(device.https_host, device.https_port, device.https_spki)


# ---- the password ----------------------------------------------------------


def _password(device: "Device") -> str:
    """The rpcd password, from the device's own password file.

    The password never appears in a message: every failure below says
    what went wrong with the FILE, not what is in it.
    """
    path = getattr(device, "rpcd_password_file", None)
    if path is None:
        raise NewtonError("the device has no rpcd password file")
    file_path = Path(path).expanduser()
    problem = credential_file.check(file_path, what="rpcd_password_file")
    if problem is not None:
        raise NewtonError(f"the rpcd password file cannot be used: {problem}")
    try:
        raw = file_path.read_bytes()
    except OSError:
        raise NewtonError("the rpcd password file cannot be read") from None
    try:
        password = raw.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError:
        raise NewtonError("the rpcd password file is not text") from None
    if not password:
        raise NewtonError("the rpcd password file is empty")
    return password


# ---- the read --------------------------------------------------------------


def _plan_for(tokens: list[str]) -> _Plan:
    handler = _HANDLERS.get(tokens[0])
    if handler is None:
        raise NewtonError(refusal(tokens[0]))
    return handler(tokens)


def read_noinstall(
    device: "Device",
    command: str,
    client_factory: Callable[["Device"], Any] = default_client_factory,
) -> dict[str, Any]:
    """One read on a no-install router, over the router's own web API.

    The result has the shape the installed path returns: the exit code,
    the output and the error in untrusted-device-data envelopes, and the
    truncated flag.
    """
    tokens = validate_read(command)
    plan = _plan_for(tokens)
    password = _password(device)
    client = client_factory(device)
    try:
        opened = client.login(rpcd.RPCD_USER, password, LOGIN_TIMEOUT_S)
    except rpcd.RpcdCallFailed:
        raise NewtonError("the router refused the login") from None
    except RpcdError:
        raise NewtonError("the router could not be reached") from None
    session = _Session(client, opened)
    try:
        answer = session.call(plan.call.obj, plan.call.fn, plan.call.args)
    except RpcdCallFailed as exc:
        handler = plan.on_error or _generic_error
        stdout, stderr, exit_code = handler(exc.code)
    except RpcdError:
        stdout, stderr, exit_code = ("", "the router could not be reached\n", 1)
    else:
        stdout, stderr, exit_code = plan.render(answer)
    source = f"{device.name}:{command}"
    out_text, err_text, truncated = scrub_read_text(tokens, stdout, stderr)
    return {
        "exit_code": exit_code,
        "stdout": _envelope.envelope(source, out_text),
        "stderr": _envelope.envelope(source, err_text),
        "truncated": truncated,
    }
