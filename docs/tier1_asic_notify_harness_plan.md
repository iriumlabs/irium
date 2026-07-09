# Tier 1 ASIC-notify validation harness — tailored to the ACTUAL live fleet

Read-only live-pool query (2026-07-09, last 7 days, all stratum services). NO code
touched, NO gate changed, NO service restarted — journalctl/systemctl/ps only.

## The live fleet (complete inventory)

| user_agent                     | subscribes/7d | buffer class | firmware source |
|--------------------------------|---------------|--------------|-----------------|
| bitaxe/BM1370/v2.14.1          | 663           | small (true) | OPEN (ESP-Miner) |
| NMAxeGamma/v3.0.21             | 623           | small (true) | OPEN (NerdMiner/NerdAxe) |
| NerdQAxe++/BM1370/v1.0.37      | 610           | small (true) | OPEN (ESP-Miner fork) |
| bitaxe/BM1370/v2.12.2          | 10            | small (true) | OPEN (ESP-Miner, older) |

Closed-firmware (Whatsminer/Antminer/BTMiner/cgminer): NONE. Large-buffer clients:
NONE. 100% of the fleet is open-source, ESP32/BM1370, small-buffer firmware.

## Why this is decisive

The single biggest unknown in the generic plan — closed firmware whose parser and
buffer size we cannot obtain — DOES NOT EXIST in this fleet. Every device runs
open-source firmware whose exact stratum receive loop, line buffer size, and cJSON
parse we can read and compile. That means Tier 1 (software) can exercise the REAL
parser code with the REAL buffer constants for 100% of the fleet — not an
approximation. Tier 2 (one physical Bitaxe) becomes a cheap final confirmation of
runtime/heap behavior, not the only way to cover an unemulatable class.

## Firmware sources to vendor (the exact three codebases)

1. ESP-Miner (Bitaxe), tags v2.14.1 and v2.12.2 — github bitaxeorg/ESP-Miner.
   Stratum receive + parse: `main/stratum_task.c` (TCP recv loop, line assembly)
   and `main/stratum_api.c` (`STRATUM_V1_receive_jsonrpc_line` / cJSON_Parse). The
   line buffer size + growth policy is the overflow-determining constant.
2. NerdQAxe++ v1.0.37 — github shufps/esp-miner-nerdqaxeplus (ESP-Miner fork).
   Same file layout; confirm whether the buffer size diverges from upstream.
3. NMAxeGamma v3.0.21 — the NerdMiner/NerdAxe "NMAxe" firmware. Locate its stratum
   client (NerdMinerV2-derived); identify its recv buffer + JSON parse path.

For each: extract (a) the exact receive-buffer size (bytes), (b) how it reads from
the socket (fixed buffer vs realloc growth vs line-at-a-time), (c) the cJSON parse
call. These three facts per firmware are the whole ballgame.

## The harness (four checks)

Prereq: an ISOLATED test pool — a separate irium-stratum instance on a non-prod
port, backed by an isolated testnet node, serving a MAINNET-SCALE template. The
notify size is data-dependent, so the template MUST carry a realistic transaction
count + header-relay carriers so the merkle-branch list and total notify body match
live mainnet size (a bare devnet template is a false-green trap). Capture a real
mainnet template's tx set (read-only) to drive it.

- C1. Size gate (S1) — the check that would have blocked all three deploys.
  For each of the 4 UAs, generate the exact `mining.notify` JSON body the reshaped
  path would send at mainnet scale, measure its byte length, and assert
  `len <= 0.8 * firmware_buffer_size`. Report the margin. The reshaped multi-role
  coinbase at mainnet tx volume is exactly what pushed this past the ~4-8 KB buffer.

- C2. Real-parser gate (S2) — real code, real buffer.
  Compile each firmware's real receive-loop + cJSON parse (native host build) and
  feed it the captured notify line. Assert: the line read completes with no
  truncation/overflow at the buffer boundary, and cJSON_Parse returns non-null.
  This tests the ACTUAL firmware parser, not a simulation.

- C3. Reassembly gate — correctness, not just non-crash.
  From the parsed params, reassemble `coinbase = cb1 + extranonce1 + extranonce2 +
  cb2`, compute the merkle root from the coinbase hash + branches, and assert it
  equals the pool's own reconstruct_canonical_merkle_root for the same job. Confirms
  the firmware would mine the correct header (not just parse the notify).

- C4. Socket-framing fidelity (at least one firmware, recommended).
  Run one firmware (Bitaxe v2.14.1, the largest class) in Wokwi or QEMU-ESP32 with
  the real RTOS TCP stack, connect it to the isolated pool, and confirm it sustains
  subscribe -> notify -> shares without RST across job changes. This catches
  socket-level chunked-read truncation that a native parser build can miss.

- C5. Regression baseline.
  Assert the current caa085a4 small self-pay notify passes C1-C3 for all 4 UAs
  (positive control), so the harness is calibrated to distinguish "fine" (today)
  from "overflow" (reshaped at mainnet scale).

## Honest residual after Tier 1

Because the fleet is 100% open-source, Tier 1 covers parser + buffer + reassembly
for every device with real code. The only residuals are runtime effects a short
emulation can miss: ESP32 heap fragmentation / memory exhaustion under sustained
multi-hour load, and thermal/timing behavior. A single physical Bitaxe Gamma
(BM1370, ~$150-250, the v2.14.x firmware that is the largest class) run against the
isolated pool for ~1 hour closes those. There is NO closed-firmware residual — the
thing that made this "needs real hardware" in the generic case is absent here.

## Recommendation (tailored)

1. Tier 1 as above (~1-2 days), all software, no purchase, covers 100% of the fleet
   with real parser code. C1 alone is the deterministic gate that would have caught
   every prior failure.
2. Tier 2: one Bitaxe Gamma (BM1370) for a ~1 hour real-hardware confirmation of
   runtime/heap behavior. Cheap and exactly representative (largest live class).
3. No closed-firmware device is needed unless a Whatsminer/Antminer later joins the
   fleet — monitor subscribe user-agents; if a closed-firmware small_buffer client
   appears, re-open this with a real device of that class.

None of this touches the gate, the coinbase code, or activation timing.
