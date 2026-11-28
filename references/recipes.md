# Recipes (1.6.1)

Read this when the owner asks for one of the common router jobs by name: a guest network, a fixed address, a port forward, a local name, DNS servers, a tunnel, a slow link.

A recipe is a reviewed file shipped with Newton, `profiles/openwrt/recipes/<id>.toml`, next to the manifest: a header, typed parameters, the steps that write the change, the checks that prove it, the packages it needs and the risk the approval text carries. It is not a device profile, no tool writes one, and it never adds a network rule (only the owner writes those, with `newton-rules`; a recipe may suggest one).

Two tools:
- `newton_list_recipes(device)` lists the recipes of the device's platform, each parameter with its kind, its help and its default, and each step with its UCI lines and their placeholders (a step with a `when` is used only when that param is given). It reads the host's own files and never contacts the device; a recipe file that does not load is listed with its error, never skipped.
- `newton_plan_recipe(device, recipe, values, timeout_s, explanation, owner_confirmed_in_chat)` plans one recipe by name. The `values` fill the parameters, the `explanation` is the same object as any other plan (`intent`, `steps` one per change line, `expect`, `risk`), and `owner_confirmed_in_chat` follows the same rule as for `newton_plan_change`.

The flow is the change protocol's: list the recipes, read the router for the values the recipe asks for (`newton_read`), explain the change to the owner and wait for their yes, plan it, let the owner approve it out of band (`newton-approve`), apply it with `newton_apply_change` (with `hold=true`, the owner tests it and you confirm it with `newton_confirm_change`). Every value is checked by the kind of its parameter before any device call. On an installed router the plan goes through the same path as `newton_plan_change`: the seal, the checks of the touched settings, the recipe's own checks, the network rules, the approval gate, the undo.

The seven recipes, one line each:
- `guest-network`: a separate network for guests or IoT devices, on a wired port, a Wi-Fi name or both; parameters `purpose` (guest or iot), `addr`, `port`, `radio`, `net_ssid`, `net_key`, `isolate`.
- `dhcp-reservation`: one device always gets the same IPv4 address; parameters `name`, `host`, `mac`, `ip`.
- `port-forward`: a service inside your network answers on a port of the outside interface; parameters `name`, `proto`, `outside_port`, `inside_ip`, `inside_port`.
- `dns-host`: one local name answers with one IPv4 address; parameters `name`, `host`, `ip`.
- `dns-upstream`: the router forwards every DNS question to the servers you name (version 2); parameters `server1`, `server2`.
- `wireguard`: one peer reaches your network through a tunnel on the internet side; parameters `addr`, `port`, `peer`, `peer_key`, `peer_ip`.
- `bufferbloat`: shapes the traffic of the WAN device to the speeds you give; parameters `device`, `down`, `up`.

Refusals, each before anything is staged:
- a package the recipe needs is missing: the plan is refused with the `apk add` line for the owner. Newton installs no package.
- a path the recipe needs is not set: the plan is refused with the owner's own command.
- a value is refused by the kind of its parameter: the refusal names the parameter and never the value.

Known limits:
- on a router Newton cannot install on (no-install mode) the plan takes that mode's own path, which carries neither the recipe's own checks nor its risk line, and reads no package and no set path (the plan says `preconditions_unchecked`). There Newton applies `dhcp-reservation` and `dns-host` itself; `port-forward`, `dns-upstream` and a wired `guest-network` become an owner script; a `guest-network` with Wi-Fi and `wireguard` are refused, because a script never carries a key; `bufferbloat` is refused, because that mode cannot read the `sqm` config.
- `bufferbloat` writes the `sqm` config, which is not in the list of configs Newton knows, so its plan on an installed router carries an `unknown-package` reason.
- the WireGuard private key is made on the router by the owner's own command (`owner_command` in the recipe). Newton never makes it.
- `port-forward` does not check that the inside address is on the LAN.
- the guest network's DHCP range starts at host 100 and holds 150 addresses, which fits a `/24` or a larger network: give it one of those (a smaller network was not tested).
- give the guest network a wired port, a Wi-Fi name, or both: with neither, the plan builds a network nothing can join.
- the guest network's wired port must be one no other bridge uses, like a VLAN device (`eth3.30`). On most routers the LAN ports (`lan1` to `lan4`) are in `br-lan` already, and the recipe does not take a port out of `br-lan`: take it out first, or use a VLAN device.
- the recipes are OpenWrt only; the Active Directory recipes are 1.6.2.
