#!/usr/bin/env bash
# mine-gpu.sh — friendly entry point for Linux GPU miners.
#
# Drop next to irium-miner-gpu and run: ./mine-gpu.sh
# First run prompts for your Irium wallet address and saves it to
# mine-config.txt. Subsequent runs read from there. Connects to the
# official Irium pool at pool.irium.org:3335 in SOLO payout mode.
# Auto-restarts on crash with a 5s cool-down. Ctrl+C to stop.

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MINER_BIN="${SCRIPT_DIR}/irium-miner-gpu"
CONFIG_FILE="${SCRIPT_DIR}/mine-config.txt"
POOL_URL="stratum+tcp://pool.irium.org:3335"

if [ ! -x "${MINER_BIN}" ]; then
    if [ -f "${MINER_BIN}" ]; then
        chmod +x "${MINER_BIN}" 2>/dev/null || true
    fi
fi

if [ ! -f "${MINER_BIN}" ]; then
    echo
    echo "ERROR: irium-miner-gpu not found in this folder."
    echo "       expected at: ${MINER_BIN}"
    echo
    exit 1
fi

WALLET=""
if [ -f "${CONFIG_FILE}" ]; then
    WALLET="$(head -n 1 "${CONFIG_FILE}" | tr -d '[:space:]')"
fi

if [ -z "${WALLET}" ]; then
    echo
    echo "----------------------------------------------------------------"
    echo "                   Welcome to Irium GPU Mining"
    echo "----------------------------------------------------------------"
    echo
    echo "You will mine SHA-256d shares against the Irium official pool"
    echo "(pool.irium.org). When one of your shares meets the network"
    echo "target, the FULL block reward goes to YOUR Irium address."
    echo "There is no pool fee."
    echo
    read -rp "Enter your Irium wallet address (P or Q prefix): " WALLET
    WALLET="$(printf '%s' "${WALLET}" | tr -d '[:space:]')"
    if [ -z "${WALLET}" ]; then
        echo "No address entered. Aborting."
        exit 1
    fi
    printf '%s\n' "${WALLET}" > "${CONFIG_FILE}"
    echo "Saved to ${CONFIG_FILE} — delete it to re-enter the address."
fi

echo
echo "----------------------------------------------------------------"
echo "                    Starting Irium GPU Miner"
echo "----------------------------------------------------------------"
echo "  Pool:    ${POOL_URL}"
echo "  Wallet:  ${WALLET}"
echo "  Worker:  ${WALLET}.rig1"
echo
echo "  Auto-restart on crash. Press Ctrl+C to stop."
echo "----------------------------------------------------------------"
echo

while true; do
    echo "[$(date +%T)] launching irium-miner-gpu..."
    "${MINER_BIN}" --wallet "${WALLET}" --pool "${POOL_URL}" --intensity 50 || true
    echo "[$(date +%T)] miner exited. restarting in 5s (Ctrl+C to stop)..."
    sleep 5
done
