---
source: https://wiki.nftables.org/wiki-nftables/index.php/Scripting
retrieved: 2026-10-03
license: GNU Free Documentation License 1.3 or later (GFDL), (c) nftables wiki contributors
note: converted from MediaWiki source to markdown; content otherwise unmodified
---

Many people like to maintain their ruleset in shell scripts, this allows them to add comments and arrange rules in more human-friendly way. This is problematic though since shell scripts break atomicity when applying the ruleset, thus, the filtering policy is applied in an inconsistent way during the ruleset loading time.

Fortunately, nftables provides a native scripting environment to address these concerns which basically allows you to include other ruleset files, define variables and add comments. You have to restore the content of this native script through the *nft -f my-ruleset.file* command.

To create a nftables script, you have to add the following header to your script file:

```
#!/usr/sbin/nft -f
```

# Adding comments

You can add comments to your file using the '#' character. Everything after the '#' will be ignored.

```
#!/usr/sbin/nft -f

#
# table declaration
#
add table filter

#
# chain declaration
#
add chain filter input { type filter hook input priority 0; policy drop; }

#
# rule declaration
#
add rule filter input ct state established,related counter accept
```

# Including files

Other files can be included by using the include statement. The directories to be searched for include files can be specified using the **-I/--includepath** option. You can override this behavior either by prepending ‘./’ to your path to force inclusion of
files located in the current working directory (i.e. relative path) or / for file location expressed as an absolute path.

If **-I/--includepath** is not specified, then nft relies on the default directory that is specified at compile time. You can retrieve this default directory via **-h/--help** option.

Include statements support the usual shell wildcard symbols (\*,?,[]). Having no matches for an include statement is not an error, if wildcard symbols are used in the include statement.

This allows having potentially empty include directories for statements like include "/etc/firewall/rules/".
The wildcard matches are loaded in alphabetical order.

**NOTE:** Files beginning with dot (.) are not matched by include statements.

```
#!/usr/sbin/nft -f

# include a single file using the default search path
include "ipv4-nat.ruleset"

# include all files ending in *.nft in the default search path
include "*.nft"

# include all files in a given directory using an absolute path
include "/etc/nftables/*"
```

# Defining variables

You can use the *define* keyword to define variables, the following example shows a very simple ruleset to account the traffic that comes from 8.8.8.8 (the popular Google DNS server):

```
#!/usr/sbin/nft -f

define google_dns = 8.8.8.8

add table filter
add chain filter input { type filter hook input priority 0; }
add rule filter input ip saddr $google_dns counter
```

You can also define a variable for sets:

```
#!/usr/sbin/nft -f

define ntp_servers = { 84.77.40.132, 176.31.53.99, 81.19.96.148, 138.100.62.8 }

add table filter
add chain filter input { type filter hook input priority 0; }
add rule filter input ip saddr $ntp_servers counter
```

Don't forget that brackets have special semantics when used from rules, since they indicate that this variable represents a set. Therefore, avoid things like:

```
define google_dns = { 8.8.8.8 }
```

It is simply overkill to define a set that only stores one single element, instead use the singleton definition:

```
define google_dns = 8.8.8.8
```

# File formats

*nft -f <filename>* accepts 2 formats, the first is the format seen in the output of *nft list table*. The second is using the same syntax of calling the *nft* binary several times, but in an atomic fashion.

Example of nftables output format:

```
#!/usr/sbin/nft -f

define ntp_servers = { 84.77.40.132, 176.31.53.99, 81.19.96.148, 138.100.62.8 }

#flush table nat
table ip nat {
	chain prerouting {
		type filter hook prerouting priority 0; policy accept;
                ip saddr $ntp_servers counter
	}

	chain postrouting {
		type filter hook postrouting priority 100; policy accept;
	}
}
```

Example of scripted config format:

```
#!/usr/sbin/nft -f

define ntp_servers = { 84.77.40.132, 176.31.53.99, 81.19.96.148, 138.100.62.8 }

add table filter
add chain filter input { type filter hook input priority 0; }
add rule filter input ip saddr $ntp_servers counter
```

You can freely translate between the two formats, as the syntax is mostly the same (only the organization differs).
Depending on your use case, you may want to use one format or other when building your firewall.

# Building an *nft* file from scripts
Though not necessarily recommended, you can use your choice of scripting language to build a single text file in a format accepted by *nft* (see previous section), and then load the firewall configuration atomically with *nft -f <your_file_in_nft_format>*. You may want to use this method if you are coordinating your *nft* configuration with that of other subsystems that use different file formats and command-line tools.

# Using nftables from Python
The same functionality provided by the *nft* command-line utility is available from within Python programs via the high-level library libnftables. Please see the following for more information and examples:
- How to use nftables from Python (https://ral-arturo.org/2020/11/22/python-nftables-tutorial.html), Arturo Borrero, 2020-11-22;
- python nftables tutorial (https://github.com/aborrero/python-nftables-tutorial) code examples to accompany the above.

# See also

This related information is very useful when dealing with nftables scripts:

- Atomic rule replacement
- Operations at ruleset level
