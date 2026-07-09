# Closing the real-ASIC notify validation gap: investigation + recommendation

Investigation only. No consensus/coinbase/gate changes. Goal: define exactly what
would give genuine confidence in the reshaped-coinbase `mining.notify` path, what
can vs cannot be done in software, and precisely what hardware/setup Ibrahim would
need to provide.

## The failure is already root-caused (not a mystery)

This is the single most important finding: the three prior live breaks were
DIAGNOSED with live evidence, not left unexplained. The mechanism:

- Small-buffer ASIC firmware allocates a FIXED JSON receive buffer (~4-8 KB). The
  pool already knows this: `is_small_buffer_firmware()` (stratum.rs ~2131) string-
  matches user-agents (whatsminer, btminer, nerdqaxe, bitaxe, esp-miner, bm1370,
  nmaxegamma) and its doc comment states plainly: "mining.notify bodies hit ~10 KB;
  small-buffer firmware silently overflows its parser and RSTs the TCP connection."
- The reshaped path called `native_rewardable_notify_split` UNCONDITIONALLY (no
  `is_small_buffer_firmware` check), forcing the ~2360-byte, 7-output multi-role
  coinbase into the notify of miners that normally receive a ~103-byte, 1-output
  self-pay coinbase. The larger coinbase pushed the total notify body past the
  4-8 KB buffer -> parser overflow -> TCP RST -> candidate production collapsed
  12 -> 0 within ~2-3 minutes. Live evidence: NerdQAxe++ BM1370 sessions.
- cpuminer (the rig) uses a dynamic/large JSON buffer, so it NEVER overflowed ->
  false green, all three times.

Two corollaries that shape validation:

1. The notify body size is DATA-DEPENDENT: total = coinbase (cb1+cb2) + N merkle
   branches (64B each) + header-relay carriers + JSON envelope. A bare devnet
   template has few transactions and small carriers, so its notify is well under
   the buffer even WITH the multi-role coinbase. That is a second false-green trap:
   the rig was small not just because of cpuminer's buffer, but because the devnet
   template was tiny. Any real validation MUST reproduce a MAINNET-SCALE template
   (realistic tx count + carriers) so the notify body reaches the ~10 KB that
   actually overflowed.

2. On mainnet the on-chain multi-role coinbase is reconstructed at SUBMIT time
   (submit_block_extended), and ASIC sessions mine a SMALL self-pay coinbase for
   PoW/shares. So the correct design keeps the ASIC notify SMALL and never needs to
   push the multi-role coinbase over the wire. The break happened precisely because
   a change violated that. Validation is therefore really two questions:
   (a) does the (activated) path keep each firmware class's notify body under its
       buffer, and (b) does real firmware still mine + submit correctly.

## What "real validation" must actually confirm

For EACH firmware class the live pool serves:

- N1. The `mining.notify` body the activated path would send stays strictly under
  that firmware's JSON receive-buffer limit, at MAINNET-SCALE template size
  (worst-case tx count + carriers + the reshaped coinbase). No overflow, no RST.
- N2. The real firmware subscribes, receives the notify, rolls extranonce2,
  reconstructs `coinbase = cb1 + extranonce1 + extranonce2 + cb2`, computes the
  merkle root, builds the header, and submits VALID shares at the set difficulty.
- N3. On a win, submit_block_extended reconstructs the canonical coinbase and the
  node accepts. (This part already has offline byte-proofs; N1/N2 are the gap.)

What would have caught the three failures: N1 alone. A single measurement — "for a
NerdQAxe++/Whatsminer user-agent, at mainnet template scale, is the notify body <
its buffer?" — would have returned "no, ~10 KB > ~8 KB" and blocked all three. The
rig never asked this because (i) cpuminer's UA isn't small-buffer so the small-
buffer code path never ran, and (ii) the devnet template was too small to overflow.

## Can software substitute? Honest assessment

Partially — and more than you'd expect, BECAUSE the failure is a known size
overflow rather than a mystery. Two software tiers, in increasing trust:

- S1. Notify-size measurement (high value, catches the known failure). Replay each
  supported firmware's `mining.subscribe` user-agent against an isolated pool
  serving a MAINNET-SCALE template with the reshaped coinbase; measure the exact
  notify body bytes; assert `< buffer_limit` for that class. This is not an
  approximation — it measures the real wire bytes. It would have caught all three
  breaks. Cheap, no hardware. It is a SCREEN, not full proof: it tells you whether
  the parser overflows, not whether the chip mines correctly.

- S2. Real open-source firmware parser in the loop (trustworthy for OPEN firmware
  only). ESP-Miner (Bitaxe) and NerdQAxe firmware are open-source C. Their stratum
  line reader + cJSON parse, with the ACTUAL firmware receive-buffer constant, can
  be compiled natively (or run in QEMU-ESP32 / Wokwi) and fed the captured notify
  bytes. This exercises the REAL parser and REAL buffer size — genuinely trustworthy
  for the Bitaxe/NerdQAxe/ESP-Miner classes. It confirms parse-success-vs-overflow
  and can also run the firmware's coinbase-reassembly + merkle code to check N2's
  math without a chip.

Where software is NOT enough (and would be another false-green if trusted alone):

- Closed firmware (Whatsminer/BTMiner; Antminer/cgminer-derived). You cannot obtain
  the parser or the exact buffer size. Vendor buffers differ and are undocumented.
  If the live fleet includes a closed-firmware class (the pool's own
  is_small_buffer_firmware list includes whatsminer/btminer), only a REAL device of
  that class — or keeping that class's notify provably small (S1) so the buffer is
  never approached — closes it.
- Socket-level framing. Real firmware reads the TCP stream with its own chunking /
  line-buffering / buffer-reuse behavior that a native parser harness may not
  reproduce. A real device confirms the actual on-wire socket behavior.

Net: S1 + S2 would have caught all three prior failures and are a hard, honest
gate — but they do NOT fully substitute for one real device of the CLOSED-firmware
class the fleet actually runs. They convert "unknown" into "known for open firmware;
size-bounded for closed firmware."

## If real hardware is required: exactly what to provide

Step 0 (do first, costs nothing): pull the actual `mining.subscribe` user-agents
from the live pool's subscribe logs so we know precisely which firmware classes to
validate and their real proportions. The memory names NerdQAxe++ (BM1370, open),
Bitaxe (open), and Whatsminer/BTMiner (closed) — confirm against current logs.

Then, per class present in the fleet:

- Open class (Bitaxe / NerdQAxe): provide ONE device running STOCK unmodified
  firmware. A Bitaxe Gamma (BM1370, ~$150-250) or a NerdQAxe++ (~$400) is
  sufficient and is the same firmware family that broke. This is the recommended
  minimum hardware.
- Closed class (Whatsminer / Antminer), only if the fleet runs it: either provide
  one such device (expensive; a Whatsminer M-series or an Antminer), OR rely on S1
  keeping that class's notify provably small (preferred — no purchase).

Setup:

- Stand up an ISOLATED test pool: a separate irium-stratum instance on a non-
  production port, backed by an isolated testnet/devnet node, serving a MAINNET-
  SCALE template (synthesize/replay realistic tx count + carriers so the notify
  reaches ~10 KB). No mainnet, no live-pool contact.
- Network: point the device's stratum URL (stratum+tcp://<host>:<port>) at that
  isolated endpoint. The device needs L3 reachability — same LAN, or a single
  firewalled port forwarded to the test host. Set difficulty low so shares arrive
  in seconds.

Time, once hardware is on the network and the isolated pool is up:

- Subscribe + first notify + first accepted share: minutes.
- Meaningful run (sustained share production, no RST/disconnect, at least one
  win-path submit_block_extended acceptance, over ~1 hour at mainnet-scale notify):
  1-2 hours of wall-clock. The real bottleneck is procuring/shipping the device and
  standing up the isolated pool, not the test duration.

## Recommendation

1. Step 0 now: extract current live-pool subscribe user-agents (read-only) to fix
   the exact firmware target list. This is the one input that determines everything
   else. I can run this against the live pool only with your explicit go-ahead; it
   is read-only.
2. Tier 1 (software, ~1 day, no purchase): build a notify-size measurement + open-
   firmware-parser harness (S1 + S2) at MAINNET template scale. This is a hard gate
   that would have caught all three prior failures and needs no hardware. It stays
   test-only; it does not touch the gate or coinbase.
3. Tier 2 (the real close): you provide ONE open-firmware device — a Bitaxe Gamma
   (BM1370, ~$150-250) is the cheapest faithful option and matches the firmware
   family that broke — pointed at an isolated test pool serving a mainnet-scale
   template. Confirm N1-N3 on real firmware. For any closed-firmware class the fleet
   runs, either add one such device or enforce S1's size bound so its notify never
   approaches the buffer.

The single most impactful thing you can do: (a) tell me the current fleet's firmware
user-agents (or let me read them read-only), and (b) order one Bitaxe Gamma. With
those two, Tiers 1 and 2 close the gap; nothing after this point can be responsibly
decided without them.
