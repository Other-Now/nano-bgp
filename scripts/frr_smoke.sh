#!/bin/bash
# Smallest possible check that FRR runs here: one bgpd, one vtysh query.
set -u
ip link set lo up
cat > /run/nbgp/smoke.conf <<'C'
router bgp 65001
 bgp router-id 1.1.1.1
 no bgp ebgp-requires-policy
 neighbor 127.0.0.2 remote-as 65002
C
timeout 5 bgpd -u root -g root -f /run/nbgp/smoke.conf -i /run/nbgp/smoke.pid \
    --vty_socket /run/nbgp -Z --log stdout &
sleep 2
timeout 3 vtysh --vty_socket /run/nbgp -c "show bgp summary json" </dev/null
wait
