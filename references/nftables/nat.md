---
source: https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT)
retrieved: 2026-10-03
license: GNU Free Documentation License 1.3 or later (GFDL), (c) nftables wiki contributors
note: converted from MediaWiki source to markdown; content otherwise unmodified
---

The *nat* chain type allows you to perform NAT (https://en.wikipedia.org/wiki/Network_address_translation). This chain type comes with special semantics:

- The first packet of a flow is used to look up for a matching rule which sets up the NAT binding for this flow. This also manipulates this first packet accordingly.
- No rule lookup happens for follow up packets in the flow: the NAT engine uses the NAT binding information already set up by the first packet to perform the packet manipulation.

Adding a NAT rule to a filter type chain will result in an error.

# Stateful NAT

The stateful NAT involves the nf_conntrack kernel engine to match/set packet stateful information and will engage according to the state of connections.
This is the most common way of performing NAT and the approach we recommend you to follow.

Be aware that **with kernel versions before 4.18, you have to register the prerouting/postrouting chains even if you have no rules there** since these chain will invoke the NAT engine for the packets coming in the reply direction. The remaining documentation in this article assumes a newer kernel which doesn't require this inconvenience anymore.

## Source NAT

If you want to source NAT the traffic that leaves from your local area network to the Internet, you can create a new table *nat* with the postrouting chain:

```
% nft add table nat
% nft 'add chain nat postrouting { type nat hook postrouting priority 100 ; }'
```

Then, add the following rule:

```
% nft add rule nat postrouting ip saddr 192.168.1.0/24 oif eth0 snat to 1.2.3.4
```

This matches for all traffic from the 192.168.1.0/24 network to the interface *eth0*. The IPv4 address 1.2.3.4 is used as source for the packets that match this rule.

### NAT pooling

It is possible to specify source NAT pooling:

```
% nft add rule inet nat postrouting snat ip to 10.0.0.2/31
% nft add rule inet nat postrouting snat ip to 10.0.0.4-10.0.0.127
```

With transport protocol source port mapping:

```
% nft add rule inet nat postrouting ip protocol tcp snat ip to 10.0.0.1-10.0.0.100:3000-4000
```

## Destination NAT

You need to add the following table and chain configuration:

```
% nft add table nat
% nft 'add chain nat prerouting { type nat hook prerouting priority -100; }'
```

Then, you can add the following rule:

```
% nft 'add rule nat prerouting iif eth0 tcp dport { 80, 443 } dnat to 192.168.1.120'
```

This redirects the incoming traffic for TCP ports 80 and 443 to 192.168.1.120.

## Masquerading

NOTE: *masquerade* is available starting with Linux Kernel 3.18.

Masquerade is a special case of SNAT, where the source address is automagically set to the address of the output interface. For example:

```
% nft add rule nat postrouting masquerade
```

Note that *masquerade* only makes sense from postrouting chain of NAT type.

## Redirect

NOTE: *redirect* is available starting with Linux Kernel 3.19.

By using redirect, packets will be forwarded to local machine. Is a special case of DNAT where the destination is the current machine.

```
% nft add rule nat prerouting redirect
```

This example redirects 22/tcp traffic to 2222/tcp:

```
% nft add rule nat prerouting tcp dport 22 redirect to 2222
```

This example redirects outgoing 53/tcp traffic to a local proxy listening on port 10053/tcp:

```
% nft add rule nat output tcp dport 853 redirect to 10053
```

Note that: *redirect* only makes sense in prerouting and output chains of NAT type.

## NAT flags

Since Linux kernel 3.18, you can combine the following flags with your NAT statements:

- random: randomize source port mapping.
- fully-random: full port randomization.
- persistent: gives a client the same source-/destination-address for each connection.

For example:

```
% nft add rule nat postrouting masquerade random,persistent
% nft add rule nat postrouting ip saddr 192.168.1.0/24 oif eth0 snat to 1.2.3.4 fully-random
```

## Inet family NAT

Since Linux kernel 5.2, there is support for performing stateful NAT in *inet* family chains. Syntax and semantics are equivalent to *ip*/*ip6* families; the only exception being if IP addresses are specified, a prefix of either *ip* or *ip6* to clarify the address family is required:

```
% nft add rule inet nat prerouting dnat ip to 10.0.0.2
% nft add rule inet nat prerouting dnat ip6 to feed::c0fe
```

## Incompatibilities

You cannot use iptables and nft to perform NAT at the same time before kernel 4.18. So make sure that the *iptable_nat* module is unloaded:

```
% rmmod iptable_nat
```

With later kernels, it is possible to use iptables and nftables nat at the same time.
The nat chains are consulted according to their priorities, the first matching rule
that adds a nat mapping (dnat, snat, masquerade) is the one that will be used for the connection.

# Stateless NAT

This type of NAT just modifies each packet according to your rules without any other state/connection tracking. This is valid for 1:1 mappings and is faster than stateful NAT. However, it's easy to shoot yourself in the foot. If your environment doesn't require this approach, better stick to stateful NAT.

You have to disable connection tracking for modified packets. This can be accomplished by incorporating the **notrack** keyword into the rule. Doing so attaches a template connection tracking entry to the packet that instructs the conntrack core not to initialize a new entry in the conntrack table. The use of a hook at - or below - a priority level of **raw** is required. Otherwise, **notrack** will not be dealt with prior to the consultation of the conntrack table.

The ruleset below demonstrates how to rewrite both the destination IP and port for each packet (also covering IPv6). Note that the rules presented affect *all* TCP packets arriving at *all* interfaces and are intended only for demonstrative purposes.

```
table inet raw {
	chain prerouting {
		type filter hook prerouting priority raw; policy accept;
		ip protocol tcp ip  daddr set 192.168.1.100 tcp dport set 10 notrack
		ip6 nexthdr tcp ip6 daddr set fe00::1       tcp dport set 10 notrack
	}
}
```

Be sure to check our documentation regarding mangling packets and setting packet connection tracking metainformation.

To use this feature you require nftables >=0.7 and linux kernel >= 4.9.

# See also

-  Example: multiple NATs using nftables maps
