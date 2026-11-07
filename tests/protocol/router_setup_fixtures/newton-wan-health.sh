#!/bin/sh
# Newton WAN health-check daemon: dual-WAN failover without mwan3.
# Probes every configured WAN, demotes or restores its default route at
# runtime, and keeps mutable state under /var/run only.  Hard rules:
# argv only, strict validation of every UCI/ubus value before use, and
# never any write to UCI or to pinned config paths.

STATE_DIR=${NEWTON_WAN_HEALTH_STATE:-/var/run/newton-wan-health}

log_msg() {
    logger -t newton-wan-health "$1"
}

uci_get() {
    uci -q get "$1" 2>/dev/null
}

valid_number() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "${#1}" -le 9 ] && [ "$1" -ge "$2" ] && [ "$1" -le "$3" ]
}

valid_iface_name() {
    case "$1" in
        [A-Za-z]*) ;;
        *) return 1 ;;
    esac
    case "$1" in
        *[!A-Za-z0-9_]*) return 1 ;;
    esac
    [ "${#1}" -le 32 ]
}

valid_device() {
    case "$1" in
        ''|-*|*[!A-Za-z0-9_.-]*) return 1 ;;
    esac
    [ "${#1}" -le 15 ]
}

valid_octet() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
        0) return 0 ;;
        0*) return 1 ;;
    esac
    [ "${#1}" -le 3 ] && [ "$1" -le 255 ]
}

valid_ipv4() {
    vip="$1"
    case "$vip" in
        *..*|.*|*.) return 1 ;;
        *.*.*.*) ;;
        *) return 1 ;;
    esac
    vip_a=${vip%%.*}
    vip_r=${vip#*.}
    vip_b=${vip_r%%.*}
    vip_r=${vip_r#*.}
    vip_c=${vip_r%%.*}
    vip_d=${vip_r#*.}
    [ "$vip_a.$vip_b.$vip_c.$vip_d" = "$vip" ] || return 1
    valid_octet "$vip_a" && valid_octet "$vip_b" \
        && valid_octet "$vip_c" && valid_octet "$vip_d"
}

valid_metric() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "${#1}" -le 8 ]
}

load_number() {
    ln_key="$1"
    ln_def="$2"
    ln_min="$3"
    ln_max="$4"
    ln_raw="$(uci_get "newton_wanhealth.main.$ln_key")"
    if valid_number "$ln_raw" "$ln_min" "$ln_max"; then
        printf '%s\n' "$ln_raw"
    else
        log_msg "invalid $ln_key; using default $ln_def"
        printf '%s\n' "$ln_def"
    fi
}

load_config() {
    INTERVAL="$(load_number interval 5 1 300)"
    TIMEOUT="$(load_number timeout 2 1 10)"
    DOWN_AFTER="$(load_number down_after 3 1 20)"
    UP_AFTER="$(load_number up_after 3 1 20)"

    TARGETS_VALID=
    raw_targets="$(uci_get newton_wanhealth.main.target)"
    set -f
    # shellcheck disable=SC2086
    for cfg_target in $raw_targets; do
        if valid_ipv4 "$cfg_target"; then
            TARGETS_VALID="$TARGETS_VALID $cfg_target"
        else
            log_msg "invalid target; skipping"
        fi
    done

    IFACES_VALID=
    raw_ifaces="$(uci_get newton_wanhealth.main.iface)"
    # shellcheck disable=SC2086
    for cfg_iface in $raw_ifaces; do
        if valid_iface_name "$cfg_iface"; then
            IFACES_VALID="$IFACES_VALID $cfg_iface"
        else
            log_msg "invalid iface; skipping"
        fi
    done
    set +f
}

write_state() {
    st_file="$STATE_DIR/$1.state"
    # State files are sourced later: never write a value that was not validated.
    case "$2$3$4$5$6$7$8" in
        *[!A-Za-z0-9_.-]*) set -- "$1" "" "" "" "$5" "$6" "$7" "$8" ;;
    esac
    printf 's_dev=%s\ns_gw=%s\ns_metric=%s\ns_fail=%s\ns_good=%s\ns_mark=%s\ns_active=%s\n' \
        "$2" "$3" "$4" "$5" "$6" "$7" "$8" > "${st_file}.tmp" \
        && mv "${st_file}.tmp" "$st_file"
}

route_present() {
    ip route list 2>/dev/null | {
        rp_found=0
        while IFS= read -r rp_line; do
            [ "$rp_line" = "default via $1 dev $2 metric $3" ] && rp_found=1
        done
        [ "$rp_found" = 1 ]
    }
}

demote_wan() {
    dm_high=$(( $3 + 1000 ))
    route_present "$1" "$2" "$dm_high" \
        || ip route add default via "$1" dev "$2" metric "$dm_high" >/dev/null 2>&1
    route_present "$1" "$2" "$3" \
        && ip route del default via "$1" dev "$2" metric "$3" >/dev/null 2>&1
}

restore_wan() {
    if ! route_present "$1" "$2" "$3"; then
        ip route add default via "$1" dev "$2" metric "$3" >/dev/null 2>&1
    fi
    rw_high=$(( $3 + 1000 ))
    route_present "$1" "$2" "$rw_high" \
        && ip route del default via "$1" dev "$2" metric "$rw_high" >/dev/null 2>&1
}

probe_iface() {
    pi_dev="$1"
    pi_target=
    pi_healthy=0
    # shellcheck disable=SC2086
    for pi_target in $TARGETS_VALID; do
        if ping -I "$pi_dev" -c 1 -W "$TIMEOUT" "$pi_target" >/dev/null 2>&1; then
            pi_healthy=1
            break
        fi
    done
    [ "$pi_healthy" = "1" ]
}

do_round() {
    # shellcheck disable=SC2086
    for iface in $IFACES_VALID; do
        st_file="$STATE_DIR/$iface.state"
        s_dev=
        s_gw=
        s_metric=
        s_fail=0
        s_good=0
        s_mark=up
        s_active=0
        if [ -f "$st_file" ]; then
            # shellcheck disable=SC1090
            . "$st_file"
        fi

        status="$(ubus call "network.interface.$iface" status 2>/dev/null)" || continue
        up_val="$(printf '%s' "$status" | jsonfilter -e '@.up' 2>/dev/null)"
        if [ "$up_val" != "true" ]; then
            write_state "$iface" "$s_dev" "$s_gw" "$s_metric" \
                "$s_fail" "$s_good" "$s_mark" 0
            continue
        fi
        s_dev="$(printf '%s' "$status" | jsonfilter -e '@.l3_device' 2>/dev/null)"
        if ! valid_device "$s_dev"; then
            log_msg "invalid ubus device; skipping interface"
            write_state "$iface" "$s_dev" "$s_gw" "$s_metric" \
                "$s_fail" "$s_good" "$s_mark" 0
            continue
        fi
        s_gw="$(printf '%s' "$status" \
            | jsonfilter -e '@.route[@.target="0.0.0.0"].nexthop' 2>/dev/null)"
        if ! valid_ipv4 "$s_gw"; then
            log_msg "invalid ubus gateway; skipping interface"
            write_state "$iface" "$s_dev" "$s_gw" "$s_metric" \
                "$s_fail" "$s_good" "$s_mark" 0
            continue
        fi
        s_metric="$(printf '%s' "$status" | jsonfilter -e '@.metric' 2>/dev/null)"
        if ! valid_metric "$s_metric"; then
            log_msg "invalid ubus metric; skipping interface"
            write_state "$iface" "$s_dev" "$s_gw" "$s_metric" \
                "$s_fail" "$s_good" "$s_mark" 0
            continue
        fi

        if probe_iface "$s_dev"; then
            s_good=$(( s_good + 1 ))
            s_fail=0
            if [ "$s_mark" = "down" ] && [ "$s_good" -ge "$UP_AFTER" ]; then
                log_msg "$iface up ($s_dev) after $s_good good rounds"
                s_mark=up
                s_good=0
            fi
        else
            s_fail=$(( s_fail + 1 ))
            s_good=0
            if [ "$s_mark" = "up" ] && [ "$s_fail" -ge "$DOWN_AFTER" ]; then
                log_msg "$iface down ($s_dev) after $s_fail failed rounds"
                s_mark=down
                s_fail=0
            fi
        fi
        write_state "$iface" "$s_dev" "$s_gw" "$s_metric" \
            "$s_fail" "$s_good" "$s_mark" 1
    done

    ad_tracked=0
    ad_alldown=1
    for st_file in "$STATE_DIR"/*.state; do
        [ -f "$st_file" ] || continue
        # shellcheck disable=SC1090
        . "$st_file"
        ad_tracked=1
        [ "$s_mark" = "down" ] || ad_alldown=0
    done

    if [ "$ad_tracked" = 1 ] && [ "$ad_alldown" = 1 ]; then
        if [ ! -f "$STATE_DIR/all_down.flag" ]; then
            log_msg "all configured WAN interfaces are down; leaving routes unchanged"
            : > "$STATE_DIR/all_down.flag"
        fi
        return 0
    fi
    rm -f "$STATE_DIR/all_down.flag"

    for st_file in "$STATE_DIR"/*.state; do
        [ -f "$st_file" ] || continue
        # shellcheck disable=SC1090
        . "$st_file"
        [ "$s_active" = "1" ] || continue
        valid_device "$s_dev" && valid_ipv4 "$s_gw" && valid_metric "$s_metric" \
            || continue
        if [ "$s_mark" = "down" ]; then
            demote_wan "$s_gw" "$s_dev" "$s_metric"
        else
            restore_wan "$s_gw" "$s_dev" "$s_metric"
        fi
    done
}

restore_all() {
    [ -d "$STATE_DIR" ] || return 0
    for st_file in "$STATE_DIR"/*.state; do
        [ -f "$st_file" ] || continue
        # shellcheck disable=SC1090
        . "$st_file"
        if valid_device "$s_dev" && valid_ipv4 "$s_gw" && valid_metric "$s_metric" \
            && [ "$s_mark" = "down" ]; then
            restore_wan "$s_gw" "$s_dev" "$s_metric"
        fi
        rm -f "$st_file"
    done
    rm -f "$STATE_DIR/all_down.flag"
}

idle_loop() {
    if [ "$MODE" = "run" ]; then
        trap 'exit 0' TERM INT
        while :; do
            sleep "$INTERVAL"
        done
    fi
    sleep "$INTERVAL"
    exit 0
}

mkdir -p "$STATE_DIR" 2>/dev/null || :
MODE="${1:-run}"

case "$MODE" in
    restore)
        restore_all
        exit 0
        ;;
    run|once) ;;
    *)
        printf '%s\n' "usage: newton-wan-health [run|once|restore]" >&2
        exit 2
        ;;
esac

load_config
log_msg "started"

if [ -z "$TARGETS_VALID" ]; then
    log_msg "no valid targets configured; idling"
    idle_loop
fi
if [ -z "$IFACES_VALID" ]; then
    log_msg "no valid interfaces configured; idling"
    idle_loop
fi

if [ "$MODE" = "run" ]; then
    trap 'restore_all; exit 0' TERM INT
    while :; do
        do_round
        sleep "$INTERVAL"
    done
else
    do_round
fi
exit 0
