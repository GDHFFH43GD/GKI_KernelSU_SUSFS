#!/system/bin/sh
# ==============================================================================
# In-Kernel Tether Optimizer, Wire-Speed VPN Forwarder & TTL Shield
# Designed for Motorola Moto G85 5G (malmo_gn) / Android GKI 6.1
# ==============================================================================

LOG_TAG="TetherOptimizer"
log_info() {
    echo "[$LOG_TAG] $*"
    log -t "$LOG_TAG" "$*" 2>/dev/null || true
}

log_info "Initializing Tether Optimizer & Wire-Speed VPN Forwarder..."

# 1. Enable Core Kernel Packet Forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null

# 2. High-Performance Congestion Control & Queue Disciplines
echo "bbr" > /proc/sys/net/ipv4/tcp_congestion_control 2>/dev/null || true
echo "fq" > /proc/sys/net/core/default_qdisc 2>/dev/null || true
echo 3 > /proc/sys/net/ipv4/tcp_fastopen 2>/dev/null || true
echo 0 > /proc/sys/net/ipv4/tcp_ecn 2>/dev/null || true
echo 8192 > /proc/sys/net/core/netdev_max_backlog 2>/dev/null || true
echo 262144 > /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || true

# 3. Reset Android Tethering Restrictions & Bypass Entitlement Checks
resetprop tether_dun_required 0 2>/dev/null || true
resetprop net.tethering.noprovisioning true 2>/dev/null || true
resetprop tether_entitlement_check_state 0 2>/dev/null || true
settings put global tether_dun_required 0 2>/dev/null || true
settings put global tether_entitlement_check_state 0 2>/dev/null || true

# Disable tethering hardware offload so in-kernel netfilter rules process all hotspot traffic
settings put global tether_offload_disabled 1 2>/dev/null || true

# 4. Wire-Speed In-Kernel TTL / Hop-Limit Rewriting (Carrier Tethering Masking)
# Normalizes all forwarded & outgoing packets to phone-native TTL (64)
echo 64 > /proc/sys/net/ipv4/ip_default_ttl 2>/dev/null || true
echo 64 > /proc/sys/net/ipv6/conf/all/hop_limit 2>/dev/null || true

apply_ttl_rules() {
    # IPv4 TTL set to 64
    iptables -t mangle -C POSTROUTING -j TTL --ttl-set 64 2>/dev/null || \
      iptables -t mangle -A POSTROUTING -j TTL --ttl-set 64 2>/dev/null || true

    # IPv6 Hop Limit set to 64
    ip6tables -t mangle -C POSTROUTING -j HL --hl-set 64 2>/dev/null || \
      ip6tables -t mangle -A POSTROUTING -j HL --hl-set 64 2>/dev/null || true

    # Dynamic TCP MSS Clamping to PMTU (Prevents packet drops/fragmentation on LTE/5G)
    iptables -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
      iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
    ip6tables -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
      ip6tables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
}
apply_ttl_rules

log_info "Wire-speed TTL=64 and TCPMSS clamping rules applied."

# 5. Background Monitor for Instant Direct VPN Sharing over Hotspot
# When VPN connects (tun+, wg+), directly forward hotspot traffic to VPN interface
(
    LAST_VPN=""
    while true; do
        # Detect active VPN interface
        CURR_VPN=""
        for iface in $(ip -o link show | awk -F': ' '{print $2}'); do
            case "$iface" in
                tun*|wg*|wireguard*|ppp*)
                    # Verify interface is UP
                    if ip link show "$iface" 2>/dev/null | grep -q "UP"; then
                        CURR_VPN="$iface"
                        break
                    fi
                    ;;
            esac
        done

        if [ -n "$CURR_VPN" ] && [ "$CURR_VPN" != "$LAST_VPN" ]; then
            log_info "Active VPN detected: $CURR_VPN. Directing hotspot traffic through VPN..."

            # Enable NAT masquerade on the VPN interface
            iptables -t nat -C POSTROUTING -o "$CURR_VPN" -j MASQUERADE 2>/dev/null || \
              iptables -t nat -I POSTROUTING -o "$CURR_VPN" -j MASQUERADE 2>/dev/null || true
            ip6tables -t nat -C POSTROUTING -o "$CURR_VPN" -j MASQUERADE 2>/dev/null || \
              ip6tables -t nat -I POSTROUTING -o "$CURR_VPN" -j MASQUERADE 2>/dev/null || true

            # Allow forwarding between tether interfaces and VPN
            iptables -C FORWARD -o "$CURR_VPN" -j ACCEPT 2>/dev/null || \
              iptables -I FORWARD -o "$CURR_VPN" -j ACCEPT 2>/dev/null || true
            iptables -C FORWARD -i "$CURR_VPN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
              iptables -I FORWARD -i "$CURR_VPN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

            ip6tables -C FORWARD -o "$CURR_VPN" -j ACCEPT 2>/dev/null || \
              ip6tables -I FORWARD -o "$CURR_VPN" -j ACCEPT 2>/dev/null || true
            ip6tables -C FORWARD -i "$CURR_VPN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
              ip6tables -I FORWARD -i "$CURR_VPN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

            LAST_VPN="$CURR_VPN"
            log_info "Hotspot is now sharing VPN tunnel ($CURR_VPN) at wire speed."

        elif [ -z "$CURR_VPN" ] && [ -n "$LAST_VPN" ]; then
            log_info "VPN tunnel ($LAST_VPN) disconnected. Reverting to direct cellular upstream..."
            iptables -t nat -D POSTROUTING -o "$LAST_VPN" -j MASQUERADE 2>/dev/null || true
            iptables -D FORWARD -o "$LAST_VPN" -j ACCEPT 2>/dev/null || true
            iptables -D FORWARD -i "$LAST_VPN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

            ip6tables -t nat -D POSTROUTING -o "$LAST_VPN" -j MASQUERADE 2>/dev/null || true
            ip6tables -D FORWARD -o "$LAST_VPN" -j ACCEPT 2>/dev/null || true
            ip6tables -D FORWARD -i "$LAST_VPN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

            LAST_VPN=""
        fi

        # Periodically ensure TTL and TCPMSS rules stay active
        apply_ttl_rules

        sleep 4
    done
) &

log_info "Tether Optimizer service started successfully."
