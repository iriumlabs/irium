#!/usr/bin/env bash
# mine-cpu-mac.sh — friendly entry point for macOS CPU miners.
#
# Drop next to irium-miner and run: ./mine-cpu-mac.sh
# First run handles the macOS Gatekeeper quarantine attribute, prompts
# for your Irium wallet address, and saves it to mine-config.txt for
# next time.
#
# The bundled irium-miner is SOLO-mode only, so this connects to a
# local iriumd at http://127.0.0.1:38300 — start iriumd yourself or
# run the Irium Core desktop app first. For pool CPU mining install
# cpuminer-opt and point it at stratum+tcp://pool.irium.org:3335.
# Auto-restarts on crash with a 5s cool-down. Ctrl+C to stop.
#
# If macOS blocks the script: run
#   xattr -d com.apple.quarantine mine-cpu-mac.sh irium-miner
# OR right-click mine-cpu-mac.sh in Finder → Open → Open Anyway.

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MINER_BIN="${SCRIPT_DIR}/irium-miner"
CONFIG_FILE="${SCRIPT_DIR}/mine-config.txt"
RPC_URL="http://127.0.0.1:38300"

if [ -f "${MINER_BIN}" ]; then
    xattr -d com.apple.quarantine "${MINER_BIN}" 2>/dev/null || true
    chmod +x "${MINER_BIN}" 2>/dev/null || true
fi

if [ ! -f "${MINER_BIN}" ]; then
    echo
    echo "ERROR: irium-miner not found in this folder."
    echo "       expected at: ${MINER_BIN}"
    echo
    exit 1
fi

if [ ! -x "${MINER_BIN}" ]; then
    echo
    echo "ERROR: irium-miner is not executable."
    echo "       run: chmod +x \"${MINER_BIN}\""
    echo "       then re-run this script."
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
    echo "                 Welcome to Irium CPU Mining (macOS)"
    echo "----------------------------------------------------------------"
    echo
    echo "You will mine SHA-256d blocks against your LOCAL iriumd node"
    echo "(solo mode). When you find a block, the FULL reward goes to"
    echo "your address. Make sure iriumd is running before you start."
    echo "For steady payouts on a CPU, use the GPU miner with"
    echo "mine-gpu-mac.sh against the official pool instead."
    echo
    echo "Note: macOS may show a Gatekeeper warning for unsigned binaries."
    echo "If you see one, this script tried to remove the quarantine"
    echo "attribute automatically. If it still fails, run:"
    echo "    xattr -d com.apple.quarantine irium-miner"
    echo "or right-click the binary in Finder → Open → Open Anyway."
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
echo "                 Starting Irium CPU Miner (macOS)"
echo "----------------------------------------------------------------"
echo "  RPC:     ${RPC_URL}   (make sure iriumd is running)"
echo "  Wallet:  ${WALLET}"
echo
echo "  Auto-restart on crash. Press Ctrl+C to stop."
echo "----------------------------------------------------------------"
echo

export IRIUM_MINER_ADDRESS="${WALLET}"
export IRIUM_NODE_RPC="${RPC_URL}"

while true; do
    echo "[$(date +%T)] launching irium-miner..."
    "${MINER_BIN}" || true
    echo "[$(date +%T)] miner exited. restarting in 5s (Ctrl+C to stop)..."
    sleep 5
done
