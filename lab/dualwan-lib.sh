#!/usr/bin/env bash
# lab/dualwan-lib.sh -- sourced (`. lab/dualwan-lib.sh`) by the dualwan
# scenarios' [[effect]] and [[post]] commands. The lab runner hands a local
# command (device = "local") the same env it uses for every other local step:
# LAB_SSH_KEY and LAB_SSH_PROXY, so each helper ssh's lab-r1 / lab-isp /
# lab-client through the same runner ssh path the other steps use (mgmt_ssh
# and mgmt_ssh_newton show the flags we follow). lab-client / lab-isp are
# probed over a per-call fresh ssh connection: the helpers quote every
# argument and never assemble shell strings from untrusted data.
#
# Helpers:
#   isp   CMD...         run CMD on lab-isp (root@10.109.0.10) over ssh
#   client CMD...        run CMD on lab-client ($LAB_CLIENT_USER@10.109.0.50) over ssh
#   counts               print "<eth2> <eth3>" packet counters from
#                         `nft list counter inet nwcount` on lab-isp
#   nwsend               one ping from lab-client to 198.51.100.9 with
#                         -s 200 and a fresh pid-derived id, so the health
#                         tool's 56-byte probes are not counted but ours are
#   nwcut_on / nwcut_off make / remove the `inet nwcut` table on lab-isp
#                         (input + forward chains at -100; eth2 admits udp
#                         67/68 only, everything else IPv4 is dropped)
#   nwdown_on / nwdown_off `ifdown ispa` / `ifup ispa` on lab-isp
#   wait_via WANT [SECS] -- loop sleep 1, send nwsend, read counts, return
#                         0 and print `via=A seconds=N` / `via=B seconds=N`
#                         for the first sample whose wanted side only rose;
#                         return 1 and print `timeout` after SECS (default 60)

set -u

DW_LAB_ISP_HOST=10.109.0.10
DW_LAB_ISP_USER=root
DW_LAB_CLIENT_HOST=10.109.0.50
# The lab-client's user name: the runner's local env carries it (the lab file
# holds it), so no user name is written down here.
DW_LAB_CLIENT_USER=${DW_LAB_CLIENT_USER:-${LAB_CLIENT_USER:-labuser}}
DW_TARGET=198.51.100.9

# _dw_ssh USER HOST CMD... -- one argv-list ssh invocation, never a shell string.
_dw_ssh() {
    local user=$1 host=$2
    shift 2
    timeout 40 ssh -i "$LAB_SSH_KEY" \
        -o BatchMode=yes \
        -o IdentitiesOnly=yes \
        -o UserKnownHostsFile=/dev/null \
        -o StrictHostKeyChecking=no \
        -o LogLevel=ERROR \
        -o ConnectTimeout=8 \
        -o "ProxyCommand=$LAB_SSH_PROXY" \
        "${user}@${host}" "$@"
}

isp() {
    _dw_ssh "$DW_LAB_ISP_USER" "$DW_LAB_ISP_HOST" "$@"
}

client() {
    _dw_ssh "$DW_LAB_CLIENT_USER" "$DW_LAB_CLIENT_HOST" "$@"
}

# counts -- print "<eth2-counter> <eth3-counter>" from nft. Falls back to
# 0 0 if the table has no rules (the runner uses these as deltas so the
# absolute zero on a fresh run is still a valid baseline).
counts() {
    local out a b
    out=$(isp nft list table inet nwcount 2>/dev/null) || { printf '0 0\n'; return 0; }
    a=$(printf '%s\n' "$out" | awk '/nw-eth2/ {for (i = 1; i < NF; i++) if ($i == "packets") { print $(i + 1); exit }}')
    b=$(printf '%s\n' "$out" | awk '/nw-eth3/ {for (i = 1; i < NF; i++) if ($i == "packets") { print $(i + 1); exit }}')
    case "$a" in ''|*[!0-9]*) a=0 ;; esac
    case "$b" in ''|*[!0-9]*) b=0 ;; esac
    printf '%s %s\n' "$a" "$b"
}

# nwsend -- one fresh connection from lab-client to the probe target. Each
# call shells out a brand-new `ping` process, so the kernel gives it a fresh
# socket id; -s 200 sets the payload size so the health tool's 56-byte probes
# do not match our counter rule (which filters on length 228 = 200 + 28).
nwsend() {
    client ping -c 1 -W 2 -s 200 "$DW_TARGET"
}

# nwcut_on / nwcut_off -- the lab-isp nft cut. Priority -100 sits BEFORE
# fw4 (priority 0) so it sees the packet first; eth2 (ispa) accepts udp
# 67/68 only, every other IPv4 packet is dropped (link stays up so DHCP
# and ARP keep working on both sides; udp 67/68 keeps the routers' DHCP
# lease from expiring during the cut). The script is piped to `nft -f -` on
# lab-isp via stdin (ssh forwards stdin to the remote shell) so the brace
# groups and the { 67, 68 } set literal reach nft intact -- ssh concatenates
# args with spaces, and the remote shell would otherwise treat `;` as a
# statement separator.
nwcut_on() {
    isp nft -f - <<'DW_NFT'
add table inet nwcut
add chain inet nwcut input { type filter hook input priority -100 ; policy accept ; }
add chain inet nwcut forward { type filter hook forward priority -100 ; policy accept ; }
add rule inet nwcut input iifname "eth2" ip protocol udp udp dport { 67, 68 } accept
add rule inet nwcut input iifname "eth2" ip protocol udp drop
add rule inet nwcut input iifname "eth2" ip protocol icmp drop
add rule inet nwcut input iifname "eth2" drop
add rule inet nwcut forward iifname "eth2" drop
add rule inet nwcut forward oifname "eth2" drop
DW_NFT
}

nwcut_off() {
    isp nft delete table inet nwcut
}

# nwdown_on / nwdown_off -- bring ispa down / back up on lab-isp. The nft
# cut is the realistic fault; ifdown is the second fault mode dw-05 tests.
nwdown_on() {
    isp ifdown ispa
}

nwdown_off() {
    isp ifup ispa
}

# wait_via WANT [SECONDS] -- loop sleep 1, send nwsend, read counts, return
# 0 on the FIRST one where the wanted side rose and the other side did not;
# return 1 and print `timeout` if SECONDS (default 60) pass without one.
wait_via() {
    local want=$1
    local secs=${2:-60}
    case "$want" in A|B) ;; *) printf 'timeout\n'; return 1 ;; esac
    local a0 b0 a b t0 now
    read -r a0 b0 < <(counts)
    t0=$(date +%s)
    while now=$(date +%s) && [ $((now - t0)) -lt "$secs" ]; do
        sleep 1
        nwsend
        read -r a b < <(counts)
        case "$want" in
            A)
                if [ "$a" -gt "$a0" ] && [ "$b" -eq "$b0" ]; then
                    now=$(date +%s)
                    printf 'via=A seconds=%d\n' $((now - t0))
                    return 0
                fi
                ;;
            B)
                if [ "$b" -gt "$b0" ] && [ "$a" -eq "$a0" ]; then
                    now=$(date +%s)
                    printf 'via=B seconds=%d\n' $((now - t0))
                    return 0
                fi
                ;;
        esac
        a0=$a
        b0=$b
    done
    printf 'timeout\n'
    return 1
}
# wh_budget N INTERVAL TIMEOUT TARGETS -- print
# N*(INTERVAL+TARGETS*TIMEOUT)+INTERVAL. POSIX-sh integer arithmetic; no
# `local`, no `[[`, no process substitution. The dualwan scenarios
# (dw-01, dw-02, dw-05) copy WH_INTERVAL, WH_TIMEOUT, WH_DOWN_AFTER,
# WH_UP_AFTER and WH_TARGETS from their own UCI batch by hand at the top
# of the effect cmd; the lab test
# `test_dualwan_scenario_effect_sets_wh_vars_from_batch` fails if they
# differ. Defaults (interval=5, timeout=2, down_after=3, targets=1) give
# 26 s; defaults with 2 targets give 32 s; the lab settings
# (interval=3, timeout=1, down_after=3, targets=1) give 15 s for
# failover and (up_after=2) give 11 s for failback.
wh_budget() {
    echo $(( $1 * ($2 + $4 * $3) + $2 ))
}
