#!/usr/bin/env python3
# C1 helper: reconstruct the EXACT mining.notify JSON body the pool sends, from a
# real captured [notify] log line, so the C parser harness is fed real wire bytes.
# Emits: notify_real.bin (as captured) and prints the body length.
import re, sys, json

line = open('/tmp/fw/real_notify_line.txt').read()
def grab(k):
    m = re.search(k + r'=([0-9a-f]*)', line)
    return m.group(1) if m else ''
job = grab('job'); prev = grab('prevhash'); cb1 = grab('coinbase1')
cb2 = grab('coinbase2'); nbits = grab('nbits'); ntime = grab('ntime')
br = grab('branches')
branches = [br[i:i+64] for i in range(0, len(br), 64)] if br else []
# Exact pool format (stratum.rs send_notify): version hard-coded "00000001".
msg = {"id": None, "method": "mining.notify",
       "params": [job, prev, cb1, cb2, branches, "00000001", nbits, ntime, True]}
body = json.dumps(msg, separators=(',', ':')) + "\n"
open('/tmp/fw/notify_real.bin', 'w').write(body)
print("REAL multi-role notify: coinbase_bytes=%d body_bytes=%d branches=%d"
      % ((len(cb1)+len(cb2))//2, len(body), len(branches)))

# C5 positive control: the small self-pay notify (tiny coinbase) that works today.
cb2_small = "ffffffff0100f2052a010000001976a914c661ae6d61c6c310a1a9772f2909e6f3ff47387d88ac00000000"
msg_s = {"id": None, "method": "mining.notify",
         "params": [job, prev, cb1, cb2_small, [], "00000001", nbits, ntime, True]}
body_s = json.dumps(msg_s, separators=(',', ':')) + "\n"
open('/tmp/fw/notify_selfpay.bin', 'w').write(body_s)
print("SELF-PAY (today, control) notify: body_bytes=%d" % len(body_s))

# C1 worst-case stress: multi-role coinbase PLUS maximal header carriers. The 3
# prior breaks correlated with carriers NOT stripped. Model the worst case by
# padding cb2 with an extra maximal BTC+LTC+DOGE carrier blob (~3x a single ~2KB
# carrier) to probe the firmware limit boundary, not just the current live size.
carrier_blob = cb2[len(cb2)//2:]  # ~half of a real cb2 is carrier data
cb2_worst = cb2 + carrier_blob * 2  # multi-role + ~3x carriers (unstripped worst case)
msg_w = {"id": None, "method": "mining.notify",
         "params": [job, prev, cb1, cb2_worst, branches, "00000001", nbits, ntime, True]}
body_w = json.dumps(msg_w, separators=(',', ':')) + "\n"
open('/tmp/fw/notify_worst.bin', 'w').write(body_w)
print("WORST-CASE (multi-role + ~3x carriers, unstripped) notify: coinbase_bytes=%d body_bytes=%d"
      % (len(cb2_worst)//2, len(body_w)))
