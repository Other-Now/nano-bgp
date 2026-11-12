#!/bin/bash
# Run a command inside a private network + mount namespace.
#
#   scripts/run.sh python3 -m pytest tests/
#
# As root (CI): unshare --net --mount.
# As a normal user (no sudo): adds --user --map-root-user, so we are "root"
# only over namespaces we created. Nothing touches the host's network.
#
# FRR_ROOT: optional root of unpacked FRR .debs (see scripts/deps.sh) for a box
# where the frr package cannot be installed. If unset, FRR is taken from /usr.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

if [[ "${1:-}" != "--inside" ]]; then
    if [[ $(id -u) -eq 0 ]]; then
        exec unshare --net --mount "$0" --inside "$@"
    else
        exec unshare --user --map-root-user --net --mount "$0" --inside "$@"
    fi
fi
shift

# Private /run so `ip netns add` and FRR's sockets stay inside this namespace.
mount -t tmpfs none /run
mkdir -p /run/netns /run/nbgp

# FRR wants /etc/frr/vtysh.conf, an "frrvty" group and an "frr" user. Without
# root on the host we cannot write /etc, so (in this mount namespace only)
# replace /etc with a tmpfs of symlinks to the real entries plus our own
# group/passwd/frr. A plain --bind of /etc is refused (locked submounts);
# --rbind works.
mkdir -p /run/etc-orig /run/etc-farm
mount --rbind /etc /run/etc-orig
for e in /run/etc-orig/*; do
    ln -s "$e" "/run/etc-farm/$(basename "$e")"
done
rm -f /run/etc-farm/group /run/etc-farm/passwd /run/etc-farm/frr
cp /run/etc-orig/group /run/etc-farm/group
cp /run/etc-orig/passwd /run/etc-farm/passwd
grep -q '^frrvty:' /run/etc-farm/group || echo "frrvty:x:0:" >> /run/etc-farm/group
grep -q '^frr:' /run/etc-farm/group || echo "frr:x:0:" >> /run/etc-farm/group
grep -q '^frr:' /run/etc-farm/passwd || echo "frr:x:0:0::/run/nbgp:/bin/false" >> /run/etc-farm/passwd
mkdir -p /run/etc-farm/frr
printf 'no service integrated-vtysh-config\nusername root nopassword\n' > /run/etc-farm/frr/vtysh.conf
mount --rbind /run/etc-farm /etc

if [[ -n "${FRR_ROOT:-}" ]]; then
    export PATH="$FRR_ROOT/usr/lib/frr:$FRR_ROOT/usr/bin:$PATH"
    export LD_LIBRARY_PATH="$FRR_ROOT/usr/lib/x86_64-linux-gnu/frr:$FRR_ROOT/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
else
    export PATH="/usr/lib/frr:$PATH"
fi

exec "$@"
