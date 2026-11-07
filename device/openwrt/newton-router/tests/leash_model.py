#!/usr/bin/env python3
"""test-side uci simulator and an independent model of design 5.2; copied from a reference check.

A scenario is a committed config (dict of configs -> list of Sec) and a list of operations; the simulator produces
  (a) the `uci changes` lines, (b) the staged and committed `uci show` views of the touched sections, (c) the expected set of leash
codes computed by the model from the STRUCTURED data (not from the text).

Two ways uci can name an existing anonymous section in `uci changes` are simulated:
  mode "index": `@zone[1]` (the committed index; the staged lookup of that token then follows the STAGED indexes, as real uci would)
  mode "id":    `cfg03dc81` (the internal id); `uci show` prints `@zone[1]` for it
"""
import copy
import re

KNOWN = {"dhcp", "dropbear", "firewall", "luci", "network", "rpcd", "system", "uhttpd", "upnpd", "wireless", "https-dns-proxy", "newton_wanhealth"}
MGMT_CONFIGS = {"dropbear", "rpcd", "uhttpd"}

_uid = [0]


class Sec:
    def __init__(self, typ, _name=None, **opts):
        self.type = typ
        self.name = _name         # section name; None for anonymous (an option called `name` goes in opts)
        self.opts = dict(opts)
        self.uid = None

    def copy(self):
        s = Sec(self.type, self.name)
        s.opts = copy.deepcopy(self.opts)
        s.uid = self.uid
        return s


def printed_names(secs):
    """the name `uci show` prints for each section: the section name, or @type[idx] for anonymous ones"""
    counts = {}
    out = []
    for s in secs:
        if s.name:
            out.append(s.name)
        else:
            i = counts.get(s.type, 0)
            counts[s.type] = i + 1
            out.append(f"@{s.type}[{i}]")
    return out


def quote(v):
    return "'" + str(v).replace("'", "'\\''") + "'"


def show_lines(cfg, printed, sec):
    lines = [f"{cfg}.{printed}={sec.type}"]
    for k, v in sec.opts.items():
        if isinstance(v, list):
            lines.append(f"{cfg}.{printed}.{k}=" + " ".join(quote(x) for x in v))
        else:
            lines.append(f"{cfg}.{printed}.{k}={quote(v)}")
    return lines


def as_list(v):
    if v is None:
        return []
    if isinstance(v, list):
        return list(v)
    return str(v).split()


def slash_exempt(v):
    v = str(v)
    if "/" not in v:
        return True
    if re.fullmatch(r"[0-9A-Fa-f.:]+/[0-9]{1,3}", v):
        return True
    if re.match(r"https?://", v):
        return True
    if re.fullmatch(r"[0-9]+/(second|minute|hour|day)", v):
        return True
    return False


class Scenario:
    def __init__(self, committed, ops, profile="lab", zones=None, mode="index"):
        self.committed = {c: [s.copy() for s in secs] for c, secs in committed.items()}
        for c, secs in self.committed.items():
            for i, s in enumerate(secs):
                s.uid = "cfg%06x" % ((hash((c, s.type, i)) & 0xFFFFFF) if False else (0x03dc81 + 0x1000 * list(self.committed).index(c) + 7 * i))
        self.ops = ops
        self.profile = profile
        self.zones = zones or {"mgmt-interface": "lan", "mgmt-zone": "lan", "wan-zone": ["wan"]}
        self.mode = mode

    # ---- token used in `uci changes` for a section of the COMMITTED config ----------------------------------------------
    def ctoken(self, cfg, sec):
        if sec.name:
            return sec.name
        if self.mode == "id":
            return sec.uid
        return printed_names(self.committed[cfg])[self.committed[cfg].index(sec)] if sec in self.committed[cfg] else None

    def resolve(self, cfg, ref):
        """a scenario reference (@type[idx] w.r.t. the committed config, or a name) -> committed Sec"""
        secs = self.committed.get(cfg, [])
        for s, p in zip(secs, printed_names(secs)):
            if p == ref:
                return s
        return None

    # ---- simulator --------------------------------------------------------------------------------------------------
    def build(self):
        staged = {c: [s.copy() for s in secs] for c, secs in self.committed.items()}
        changes = []
        events = []   # structured events; section identity by uid or new name
        touched = []  # (cfg, query token)

        def st_find(cfg, uid_or_name):
            for s in staged.get(cfg, []):
                if (s.uid and s.uid == uid_or_name) or (s.name and s.name == uid_or_name and not s.uid) or (s.uid is None and s.name == uid_or_name):
                    return s
            return None

        for op in self.ops:
            kind = op[0]
            if kind == "raw":
                changes.append(op[1])
                events.append(("raw", op[1]))
                continue
            cfg = op[1]
            staged.setdefault(cfg, [])
            if kind == "newsec":
                sec, name = op[2].copy(), op[3]
                sec.name = name
                sec.uid = None
                staged[cfg].append(sec)
                changes.append(f"{cfg}.{name}={sec.type}")
                for k, v in sec.opts.items():
                    if isinstance(v, list):
                        for x in v:
                            changes.append(f"{cfg}.{name}.{k}+={quote(x)}")
                    else:
                        changes.append(f"{cfg}.{name}.{k}={quote(v)}")
                events.append(("newsec", cfg, sec, name))
                touched.append((cfg, name))
                continue
            ref = op[2]
            csec = self.resolve(cfg, ref)
            assert csec is not None, (op, "reference not in the committed config")
            tok = self.ctoken(cfg, csec)
            via_new = op[-1] == "new"   # emit the line under the section's CURRENT (renamed) staged name
            ident = csec.uid if csec.uid else csec.name
            ssec = None
            for s in staged[cfg]:
                if s.uid == csec.uid and s.type == csec.type and (s.name == csec.name or s.name is None or csec.name is None or True):
                    ssec = s
                    break
            assert ssec is not None, (op, "section already gone from the staged config")
            if via_new and ssec.name:
                tok = ssec.name
            if kind == "set":
                opt, val = op[3], op[4]
                ssec.opts[opt] = val
                changes.append(f"{cfg}.{tok}.{opt}={quote(val)}")
                events.append(("set", cfg, csec, opt, val))
            elif kind == "delopt":
                opt = op[3]
                ssec.opts.pop(opt, None)
                changes.append(f"-{cfg}.{tok}.{opt}")
                events.append(("delopt", cfg, csec, opt))
            elif kind == "addlist":
                opt, val = op[3], op[4]
                cur = as_list(ssec.opts.get(opt))
                cur.append(val)
                ssec.opts[opt] = cur
                changes.append(f"{cfg}.{tok}.{opt}+={quote(val)}")
                events.append(("addlist", cfg, csec, opt, val))
            elif kind == "dellist":
                opt, val = op[3], op[4]
                cur = [x for x in as_list(ssec.opts.get(opt)) if x != val]
                if cur:
                    ssec.opts[opt] = cur
                else:
                    ssec.opts.pop(opt, None)
                changes.append(f"{cfg}.{tok}.{opt}-={quote(val)}")
                events.append(("dellist", cfg, csec, opt, val))
            elif kind == "delsec":
                staged[cfg] = [s for s in staged[cfg] if s is not ssec]
                changes.append(f"-{cfg}.{tok}")
                events.append(("delsec", cfg, csec))
            elif kind == "renamesec":
                new = op[3]
                ssec.name = new
                changes.append(f"@{cfg}.{tok}={new}")
                events.append(("renamesec", cfg, csec, new))
                touched.append((cfg, new))
            elif kind == "renameopt":
                opt, newopt = op[3], op[4]
                val = ssec.opts.pop(opt)
                ssec.opts[newopt] = val
                changes.append(f"@{cfg}.{tok}.{opt}={newopt}")
                events.append(("renameopt", cfg, csec, opt, newopt))
            elif kind == "reorder":
                changes.append(f"^{cfg}.{tok}={op[3]}")
                events.append(("reorder", cfg, csec, op[3]))
            else:
                raise ValueError(kind)
            touched.append((cfg, tok))
        # views: for every touched (cfg, token) the program asks both views by that token
        staged_view, committed_view = {}, {}
        for cfg, tok in dict.fromkeys(touched):
            # committed lookup by token
            csecs = self.committed.get(cfg, [])
            cp = printed_names(csecs)
            for s, p in zip(csecs, cp):
                if self.ctoken(cfg, s) == tok:
                    committed_view[f"{cfg}.{tok}"] = show_lines(cfg, p, s)
            # staged lookup by token: id mode follows the id, index mode follows the STAGED index
            ssecs = staged.get(cfg, [])
            sp = printed_names(ssecs)
            for s, p in zip(ssecs, sp):
                if self.mode == "id":
                    hit = (s.uid == tok) or (s.name == tok and s.name)
                else:
                    hit = (p == tok) or (s.name == tok and s.name)
                if hit:
                    staged_view[f"{cfg}.{tok}"] = show_lines(cfg, p, s)
        full_fw = []
        fw = self.committed.get("firewall", [])
        for s, p in zip(fw, printed_names(fw)):
            full_fw += show_lines("firewall", p, s)
        return dict(changes=changes, staged=staged_view, committed=committed_view, full_firewall=full_fw, events=events, staged_cfg=staged)

    # ---- the model (design 5.2), written over the structured data ----------------------------------------------------
    def expected(self):
        b = self.build()
        zones = self.zones
        mgmt_if, mgmt_zone = zones["mgmt-interface"], zones["mgmt-zone"]
        wan_zones = set(zones["wan-zone"])
        codes = set()
        if self.profile == "prod":
            codes.add("profile-prod")
        staged = b["staged_cfg"]

        # group events by the committed section (or the new section name)
        groups = {}
        order = []
        for ev in b["events"]:
            if ev[0] == "raw":
                codes.add("unparsed-change")
                continue
            cfg = ev[1]
            if ev[0] == "newsec":
                key = (cfg, "new:" + ev[3])
            else:
                key = (cfg, ev[2].uid or ev[2].name)
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(ev)
        for cfg in {k[0] for k in groups}:
            if cfg in MGMT_CONFIGS:
                codes.add("mgmt-config")
            if cfg == "ucitrack":
                codes.add("exec-config")
            if cfg not in KNOWN:
                codes.add("unknown-package")
        for key in order:
            cfg = key[0]
            evs = groups[key]
            first = evs[0]
            if first[0] == "newsec":
                cs = None
                ss = first[2]
            else:
                cs = first[2]
                ss = None
                for s in staged.get(cfg, []):
                    if s.uid == cs.uid:
                        ss = s
            typ = (ss.type if ss else None) or (cs.type if cs else None)
            is_new = ss is not None and cs is None
            is_deleted = cs is not None and ss is None

            def sval(o):
                return ss.opts.get(o) if ss else None

            def cval(o):
                return cs.opts.get(o) if cs else None

            opts_changed = []  # (option, kind, value)
            section_level = []
            for ev in evs:
                k = ev[0]
                if k == "newsec":
                    section_level.append(k)
                    for o, v in ev[2].opts.items():
                        for x in (v if isinstance(v, list) else [v]):
                            opts_changed.append((o, "set", x))
                elif k in ("set", "addlist"):
                    opts_changed.append((ev[3], "set", ev[4]))
                elif k == "dellist":
                    opts_changed.append((ev[3], "dellist", ev[4]))
                elif k == "delopt":
                    opts_changed.append((ev[3], "del", cval(ev[3])))
                elif k == "renameopt":
                    opts_changed.append((ev[3], "del", cval(ev[3])))
                    opts_changed.append((ev[4], "set", sval(ev[4])))
                elif k in ("delsec", "renamesec", "reorder"):
                    section_level.append(k)
            for (o, kind, v) in opts_changed:
                if (cfg == "dhcp" and o in ("dhcpscript", "leasetrigger")) or (cfg == "system" and o == "log_file") or (cfg == "network" and o == "pppd_options"):
                    codes.add("exec-option")
                if v is not None and not slash_exempt(v):
                    codes.add("path-option")
                if cfg == "upnpd" and o in ("enabled", "enable_upnp", "enable_natpmp") and kind == "set" and str(v) == "1":
                    codes.add("upnp-on")
            if is_deleted:
                for o, v in cs.opts.items():
                    for x in (v if isinstance(v, list) else [v]):
                        if not slash_exempt(x):
                            codes.add("path-option")
            if cfg == "system" and typ == "timeserver" and ss is not None and str(sval("enable_server")) == "1" and not as_list(sval("interface")):
                codes.add("ntp-server-open")
            staged_name = ss.name if ss and ss.name else None
            committed_name = cs.name if cs and cs.name else None
            if cfg == "network":
                if typ is None:
                    codes.add("section-unidentified")
                if typ == "interface" and mgmt_if in (staged_name, committed_name):
                    codes.add("mgmt-interface")
                if typ in ("device", "bridge-vlan"):
                    codes.add("bridge-member")
                if typ in ("route", "route6") and (sval("interface") == mgmt_if or cval("interface") == mgmt_if):
                    codes.add("mgmt-route")
            if cfg != "firewall":
                continue
            if typ is None:
                codes.add("section-unidentified")
                continue
            names = [n for n in (sval("name"), cval("name")) if n]
            if typ == "zone":
                nets = as_list(sval("network")) + as_list(cval("network"))
                if not names:
                    codes.add("section-unidentified")
                is_mgmt = mgmt_zone in names or mgmt_if in nets
                is_wan = any(n in wan_zones for n in names)
                if is_mgmt:
                    codes.add("mgmt-zone")
                if is_wan:
                    exempt_all = not section_level
                    for (o, kind, v) in opts_changed:
                        ok = (o in ("input", "forward") and kind == "set" and str(v).upper() in ("DROP", "REJECT")) or \
                             (o in ("output", "log", "log_limit", "mtu_fix", "masq", "masq6") and kind == "set")
                        if not ok:
                            exempt_all = False
                    if not exempt_all:
                        codes.add("wan-zone")
                if not is_mgmt and not is_wan:
                    fire = False
                    for (o, kind, v) in opts_changed:
                        if o in ("input", "forward") and ((kind == "set" and str(v).upper() == "ACCEPT") or kind == "del"):
                            fire = True
                        if o in ("device", "subnet", "family", "extra", "extra_src", "extra_dest") and kind == "set":
                            fire = True
                    if is_new and ss is not None and ("input" not in ss.opts or "forward" not in ss.opts):
                        fire = True
                    wan_nets = set()
                    for s in self.committed.get("firewall", []):
                        if s.type == "zone" and s.opts.get("name") in wan_zones:
                            wan_nets |= set(as_list(s.opts.get("network")))
                    if (set(as_list(sval("network"))) - set(as_list(cval("network")))) & ({"wan", "wan6"} | wan_nets):
                        fire = True
                    if fire:
                        codes.add("zone-exposure")
            elif typ == "forwarding":
                srcs = [x for x in (sval("src"), cval("src")) if x]
                dests = [x for x in (sval("dest"), cval("dest")) if x]
                if mgmt_zone in srcs or mgmt_zone in dests:
                    codes.add("forwarding-mgmt")
                if any(s in wan_zones or s == "*" for s in srcs):
                    codes.add("wan-forwarding")
            elif typ == "redirect":
                srcs = [x for x in (sval("src"), cval("src")) if x]
                if not srcs or any(s in wan_zones or s == "*" for s in srcs):
                    codes.add("wan-redirect")
            elif typ == "rule":
                srcs = [x for x in (sval("src"), cval("src")) if x]
                if any(s in wan_zones or s == "*" for s in srcs):
                    target = cval("target") if is_deleted else sval("target")
                    fire = target is None or str(target).upper() == "ACCEPT"
                    for ev in evs:
                        if ev[0] in ("delsec", "reorder"):
                            fire = True
                        if ev[0] == "set" and ev[3] == "enabled" and str(ev[4]) == "0":
                            fire = True
                    if fire:
                        codes.add("wan-rule")
            elif typ == "defaults":
                for (o, kind, v) in opts_changed:
                    if o in ("input", "forward") and kind == "set" and str(v).upper() == "ACCEPT":
                        codes.add("defaults-accept")
            elif typ == "include":
                codes.add("exec-include")
            else:
                codes.add("firewall-type")
        return codes
