#!/bin/bash
# Fetch FRR without root: download the Ubuntu 24.04 .debs and unpack them.
#
#   scripts/deps.sh ~/bgp-deps      then   FRR_ROOT=~/bgp-deps/root scripts/run.sh ...
#
# On a box where you can `sudo apt-get install frr`, skip this and leave FRR_ROOT unset.
set -euo pipefail
dest="${1:-$HOME/bgp-deps}"
mkdir -p "$dest/debs" "$dest/root"
cd "$dest/debs"
apt-get download frr libyang2t64
for d in *.deb; do dpkg -x "$d" "$dest/root"; done
echo "FRR unpacked: FRR_ROOT=$dest/root"
