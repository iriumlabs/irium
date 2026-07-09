# Tier 1 ASIC-notify harness — results (C1 size, C2 real-parser, C5 control)

Test/validation only. No production code, gate, or coinbase touched. Harness runs
each real firmware's exact stratum line-accumulation loop (transcribed from the
vendored firmware source) and parses the assembled line with the REAL cJSON
library, fed REAL captured mining.notify bytes.

## Firmware analyzed (vendored real source)

| fleet user_agent            | repo / tag                                   | receive-buffer strategy |
|-----------------------------|----------------------------------------------|-------------------------|
| bitaxe/BM1370/v2.14.1        | bitaxeorg/ESP-Miner @ v2.14.1                | GROWING realloc (1024 init, +1024 increments), restart on realloc-fail |
| bitaxe/BM1370/v2.12.2        | bitaxeorg/ESP-Miner @ v2.12.2                | same growing-realloc logic |
| NerdQAxe++/BM1370/v1.0.37    | shufps/esp-miner-nerdqaxeplus @ v1.0.37      | FIXED 16384-byte buffer (BIG_BUFFER_SIZE) |
| NMAxeGamma/v3.0.21           | not locatable on standard GitHub paths       | UNKNOWN (see caveat) |

cJSON: DaveGamble/cJSON (the exact library ESP-IDF/ESP-Miner use).

## Measured notify sizes (real live data, all pools, 7 days)

- Merkle branches are EMPTY on Irium (coinbase-only blocks) -> notify size is
  dominated entirely by the coinbase hex.
- self-pay coinbase (today, small-buffer sessions): ~95 bytes -> notify ~371 B.
- multi-role coinbase (live): 2100-2512 bytes -> notify ~4.7-5 KB. MAX over 7d = 2460 B.
- worst-case modelled (multi-role + ~3x unstripped carriers): coinbase ~4.4 KB -> notify ~9.1 KB.

## Results (real firmware accumulation + real cJSON)

| notify body            | size   | Bitaxe (grow-realloc)                       | NerdQAxe++ (16 KB fixed)       |
|------------------------|--------|---------------------------------------------|--------------------------------|
| self-pay (C5 control)  | 371 B  | peak 1 KB, 0 reallocs, parse OK, params=9   | fits, parse OK, params=9       |
| real live multi-role   | 4699 B | peak 5 KB, 4 reallocs, NO overflow, parse OK| fits, NO overflow, parse OK     |
| worst-case (+3x carr.) | 9113 B | peak 9 KB, 8 reallocs, NO overflow, parse OK| 9 KB < 16 KB, NO overflow, OK   |

Every case PASSES: no buffer overflow, no restart/flush, and the REAL cJSON parses
the assembled line and extracts method=mining.notify with all 9 params, on both
firmware buffer strategies, INCLUDING the ~9 KB worst case.

## The important finding (honest)

The "reshaped notify overflows a 4-8 KB fixed buffer" hypothesis — including the
pool's own is_small_buffer_firmware comment ("4-8 KB JSON buffers") — is REFUTED
for the current firmware the fleet actually runs:

- Bitaxe firmware does NOT have a fixed 4-8 KB buffer. It GROWS via realloc to
  whatever the line needs, bounded only by ESP32 free heap (typically >=100 KB on
  BM1370 boards). A 9 KB notify grows the buffer to ~9 KB and parses fine.
- NerdQAxe++ has a 16 KB fixed buffer, so a 9 KB notify fits with margin.

So a single-notify size overflow is NOT the mechanism that broke production three
times. The reshaped multi-role coinbase notify, even at a worst-case ~9 KB, parses
correctly on every real firmware class analyzed.

## What this does NOT rule out (limits of C1/C2/C5)

The single-notify harness does not exercise:

1. SUSTAINED-LOAD heap behavior. Bitaxe grows + reallocs the buffer every line;
   over thousands of notifies, heap fragmentation or a transient low-heap moment
   (WiFi/mining/display buffers contending) could make ONE realloc fail ->
   esp_restart() -> disconnect. This is the most likely remaining size-adjacent
   suspect and matches the live symptom (miners disconnecting, candidate collapse
   over 2-3 minutes). It needs a long device/emulation run (C4), not a single-shot.
2. Socket-level chunked framing under the real RTOS TCP stack (C4).
3. NON-size suspects the earlier live diagnosis already raised and this now makes
   PRIMARY: (a) forcing the multi-role coinbase onto ASIC sessions that the working
   binary serves a self-pay coinbase (a routing/semantic change, not a size change);
   (b) the failed-deploy binary diverging ~1.5 MB from the working caa085a4 binary
   (untracked behavior the rig never saw).

## Revised recommendation

- C1/C2/C5 are GREEN: size + real-parser + control all pass, even worst-case. The
  size-overflow theory is refuted, so the size gate is NOT the blocker it was
  assumed to be.
- Re-prioritize the investigation to the two suspects this elevates: (1)
  sustained-load ESP32 heap stability (belongs in C4: run one Bitaxe Gamma or a
  QEMU-ESP32 image against an isolated pool for hours and watch free-heap +
  reconnects), and (2) the routing/binary divergence from the earlier diagnosis
  (a code/behavior diff, testable offline without hardware).
- A real Bitaxe Gamma is still the right Tier-2 device, but its job shifts from
  "does the notify overflow" (answered: no) to "does the firmware stay heap-stable
  under sustained reshaped-notify load over hours."

## NMAxe caveat

NMAxeGamma v3.0.21 source was not locatable on standard GitHub paths, so it was
not compiled. It is an ESP32/BM1370 device; at the measured 5 KB (and 9 KB worst
case) any plausible ESP32 stratum buffer (1 KB-growing through 16 KB-fixed) handles
it. Its residual is the same sustained-load heap question, resolvable with one
physical NMAxe or its firmware source if obtained.

## Reproduce

Vendor: ESP-Miner @v2.14.1/@v2.12.2, esp-miner-nerdqaxeplus @v1.0.37, DaveGamble/cJSON.
`python3 build_notify.py` (reconstructs notify bodies from a captured [notify] log
line) then `gcc -O2 -o fw_harness fw_harness.c cjson/cJSON.c -I cjson` and run
against notify_selfpay.bin / notify_real.bin / notify_worst.bin.
