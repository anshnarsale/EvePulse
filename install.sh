#!/usr/bin/env bash
set -e
sudo apt update
sudo apt install -y suricata
echo
echo "Installed Suricata."
echo "Check: sudo suricata --build-info"
