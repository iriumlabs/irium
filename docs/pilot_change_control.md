# Pilot Change Control

## Authority model
- Code master: `irium-vps`
- Deploy authority: designated operators only
- Branch change approval: pilot lead + infra lead

## Commit pinning rules
- Pilot hosts run pinned commit from `testing-codes-before-merging`.
- No ad-hoc host-local code edits.
- No `/tmp` runtime binaries.

## Update process
1. Commit/push on `irium-vps`.
2. Pull pinned commit on pilot hosts.
3. Restart pilot services.
4. Run verification script.
5. Announce update with commit hash.

## Freeze rules during active pilot window
- No non-critical changes during active participant swaps.
- Sev1/Sev2 fixes only, with explicit operator announcement.

## Restart permissions
- Only approved operators may restart pilot services.
