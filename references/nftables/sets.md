---
source: https://wiki.nftables.org/wiki-nftables/index.php/Sets
retrieved: 2026-10-03
license: GNU Free Documentation License 1.3 or later (GFDL), (c) nftables wiki contributors
note: converted from MediaWiki source to markdown; content otherwise unmodified
---

*nftables* comes with a built-in generic set infrastructure that allows you to use **any** supported selector to build sets. This infrastructure makes possible the representation of maps and  verdict maps.

The set elements are internally represented using performance data structures such as hashtables and red-black trees.

# Anonymous sets

Anonymous sets are those that are:

- Bound to a rule, if the rule is removed, that set is released too.
- They have no specific name, the kernel internally allocates an identifier.
- They cannot be updated. So you cannot add and delete elements from it once it is bound to a rule.

The following example shows how to create a simple set.

```
% nft add rule ip filter output tcp dport { 22, 23 } counter
```

This rule above catches all traffic going to TCP ports 22 and 23, in case of matching the counters are updated.

Eric Leblond in his Why you will love nftables (https://home.regit.org/2014/01/why-you-will-love-nftables/) article shows a very simple example to compare iptables with nftables:

```
ip6tables -A INPUT -p tcp -m multiport --dports 23,80,443 -j ACCEPT
ip6tables -A INPUT -p icmpv6 --icmpv6-type neighbor-solicitation -j ACCEPT
ip6tables -A INPUT -p icmpv6 --icmpv6-type echo-request -j ACCEPT
ip6tables -A INPUT -p icmpv6 --icmpv6-type router-advertisement -j ACCEPT
ip6tables -A INPUT -p icmpv6 --icmpv6-type neighbor-advertisement -j ACCEPT
```

Which can be expressed in *nftables* with a couple of rules that provide a set:

```
% nft add rule ip6 filter input tcp dport {telnet, http, https} accept
% nft add rule ip6 filter input icmpv6 type { nd-neighbor-solicit, echo-request, nd-router-advert, nd-neighbor-advert } accept
```

# Named sets

You can use *nft add set* to create a named set. For example:

```
% nft add set ip filter blackhole { type ipv4_addr\; comment \"drop all packets from these hosts\" \; }
```

creates a set named *blackhole*. Set names must be 16 characters or less. The optional set *comment* attribute requires at least nftables 0.9.7 and kernel 5.10. The *type* keyword indicates the data type of elements to be stored in the set. In this case *blackhole* stores IPv4 addresses, which you can add using *nft add element*:

```
% nft add element ip filter blackhole { 192.168.3.4 }
% nft add element ip filter blackhole { 192.168.1.4, 192.168.1.5 }
```

You can use named sets from rules, as for example:

```
% nft add rule ip filter input ip saddr @blackhole drop
% nft add rule ip filter output ip daddr != @blackhole accept
```

Named sets can be updated anytime.

## nftables.conf syntax

When working with nftables.conf, you can define sets in a number of ways. You can then reference those sets later on using `$VARIABLE_NAME` notation.

Here are some examples showing sets defined in one line, spanning multiple lines, and sets referencing other sets. The set is then used in a rule to allow incoming traffic from certain IP ranges.

```
define SIMPLE_SET = { 192.168.1.1, 192.168.1.2 }

define CDN_EDGE = {
    192.168.1.1,
    192.168.1.2,
    192.168.1.3,
    10.0.0.0/8
}

define CDN_MONITORS = {
    192.168.1.10,
    192.168.1.20
}

define CDN = {
    $CDN_EDGE,
    $CDN_MONITORS
}

# Allow HTTP(S) from approved IP ranges only
tcp dport { http, https } ip saddr $CDN accept
udp dport { http, https } ip saddr $CDN accept
```

# Named sets specifications

Sets specifications are:

- **type** or **typeof**, is obligatory and determines the data type of the set elements.

Supported data types if using the **type** keyword are:
  - *ipv4_addr*: IPv4 address
  - *ipv6_addr*: IPv6 address.
  - *ether_addr*: Ethernet address.
  - *inet_proto*: Inet protocol type.
  - *inet_service*: Internet service (read tcp port for example)
  - *mark*: Mark type.
  - *ifname*: Network interface name (eth0, eth1..)

The **typeof** keyword is available since **0.9.4** and allows you to use a high level expression, then let nftables resolve the base type for you:
```
table inet mytable {
	set s1 {
		typeof osf name
		elements = { "Linux" }
	}
	set s2 {
		typeof vlan id
		elements = { 2, 3, 103 }
	}
	set s3 {
		typeof ip daddr
		elements = { 1.1.1.1 }
	}
}
```

- **timeout**, it determines how long an element stays in the set. The time string respects the format: *"v<sub>1</sub>dv<sub>2</sub>hv<sub>3</sub>mv<sub>4</sub>s"*:

```
% nft add table ip filter
% nft add set ip filter ports {type inet_service \; timeout 3h45s \;}
```

These commands create a table named *filter* and add a set named *ports* to it, where elements are deleted after 3 hours and 45 seconds of being added.

- **flags**, the available flags are:
  - *constant* - set content may not change while bound
  - *interval* - set contains intervals
  - *timeout* - elements can be added with a timeout

Multiple flags should be separated by comma:

```
% nft add set ip filter flags_set {type ipv4_addr\; flags constant, interval\;}
```

- **gc-interval**, stands for garbage collection interval, can only be used if *timeout* or *flags timeout* are active. The interval follows the same format of *timeouts* time string *"v<sub>1</sub>dv<sub>2</sub>hv<sub>3</sub>mv<sub>4</sub>s"*.

- **elements**, initialize the set with some elements in it:

```
% nft add set ip filter daddrs {type ipv4_addr \; flags timeout \; elements={192.168.1.1 timeout 10s, 192.168.1.2 timeout 30s} \;}
```

This command creates a set name *daddrs* with elements *192.168.1.1*, which stays in it for 10s, and *192.168.1.2*, which stays for 30s.

- **size**, limits the maximum number of elements of the set. To create a set with maximum 2 elements type:

```
% nft add set ip filter saddrs {type ipv4_addr \; size 2 \;}
```

- **policy**, determines set selection policy. Available values are:
  - *performance* [default]
  - *memory*

- **counter**, (available since version **0.9.5**) which enables a counter per element:
```
table inet mytable {
	set s {
		typeof ip saddr
		counter
		elements = { 1.1.1.1 counter packets 0 bytes 0, 1.1.1.2 counter packets 0 bytes 0,
			     1.1.1.3 counter packets 0 bytes 0, 1.1.1.4 counter packets 0 bytes 0 }
	}
}
```

- **auto-merge**, to automatic merge adjacent/overlapping set elements. This is only valid for interval sets.

For example, this origin set configuration will collapse the elements into the CIDR:
```
table inet mytable {
	set myset {
		typeof ip saddr
        flags interval
        auto-merge
		elements = { 10.0.0.1,
                     10.0.0.2,
                     10.0.0.3,
			         10.0.0.0/8,
        }
	}
}
```

Resulting in this when you list back the ruleset, because the CIDR already contains the individual elements:

```
table inet mytable {
	set myset {
		typeof ip saddr
        flags interval
        auto-merge
		elements = { 10.0.0.0/8,
        }
	}
}
```

Also, note that not using **auto-merge** will make such ruleset fail to load with something like:

```
/etc/nftables/ruleset.nft:38:21-29: Error: conflicting intervals specified
                    10.0.0.1 ,
             ~~~~~~~^^^^^^^^^
```

# Listing named sets

You can list the content of a named set via:

```
% nft list set ip filter myset
```

# Query for element membership in a set

You can also check if an element exists in the set from its key:

```
% nft get element ip filter myset { 1.1.1.1 }
```

The example above checks if the IPv4 address 1.1.1.1 exists in the *myset* set.
