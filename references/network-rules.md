# Network rules (1.6.0)

Read this when a plan's device has network rules (the owner's `rules.toml`, written with `newton-rules`).

The device's own rules (the owner's `rules.toml`, written with `newton-rules`) join every plan of an
installed OpenWrt router. Each rule becomes a sealed client check, run from the registered inside vantage of the rule's
zone; the kinds are `dns`, `dhcp`, `internet`, `blocked` (the router, the internet, or one address and port) and `reach`
(one address and port). The owner sees them in the approval text, under "Your network rules checked on this
change:", one line per rule with the rule's sentence and its label. You cannot add one, drop one or edit one: the rules
join the plan after your explanation is checked, and an explanation that carries a rule's own mark is refused. A rule that
fails means no confirm: the router rolls the change back at its deadline. A rule that cannot run refuses the
plan before anything is staged (no vantage for the zone, a broken `rules.toml`, a device whose mode cannot run them, or a
target the vantage may not probe); the reads still work. The rules' claims do not count against your eight claims, and a
plan with client checks defaults `timeout_s` to 150; a smaller value is refused.
