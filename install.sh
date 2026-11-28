#!/bin/sh
# Build the daemon and install it, the control script and the service.
#   ./install.sh            (asks sudo for the install step)
set -eu
cd "$(dirname "$0")"
cargo build --release
cargo build --release --manifest-path payd/Cargo.toml -p fips-exit-payd
# The group the payment service is in, to which the daemon opens its socket.
getent group fips-exit >/dev/null || sudo groupadd --system fips-exit
sudo install -m 755 target/release/fips-exitd /usr/local/sbin/fips-exitd
sudo install -m 755 payd/target/release/fips-exit-payd /usr/local/sbin/fips-exit-payd
sudo install -m 755 fips-exit /usr/local/sbin/fips-exit
sudo install -m 644 fips-exit.service /etc/systemd/system/fips-exit.service
sudo install -m 644 fips-exit-advert.service /etc/systemd/system/fips-exit-advert.service
sudo install -m 644 fips-exit-advert.timer /etc/systemd/system/fips-exit-advert.timer
sudo install -m 644 fips-exit-payd.service /etc/systemd/system/fips-exit-payd.service
sudo systemctl daemon-reload
echo "installed. Start with: sudo systemctl enable --now fips-exit"
echo "To be found on Nostr: ADVERT_RELAYS in /etc/fips-exit/config, then"
echo "  sudo systemctl enable --now fips-exit-advert.timer"
echo "To sell access (ACCESS=paid and PRICE_MSAT_PER_GB in the config):"
echo "  sudo systemctl enable --now fips-exit-payd"
