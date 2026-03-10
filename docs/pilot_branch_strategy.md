# Pilot Branch Strategy

## Recommendation
Use `testing-codes-before-merging` as the official pilot branch until pilot completion criteria are met.

## Why
Pros:
- isolates pilot-only operational churn from `main`
- faster rollback by pinning/repinning pilot hosts to known pilot commit
- avoids accidental coupling with unrelated mainline changes

Cons:
- branch maintenance overhead
- requires explicit merge discipline after pilot freeze

## Alternative (after pilot freeze)
Merge pilot-ready state into `main` and switch pilot hosts to track `main`.

## Commands

### Option A (recommended now): keep pilot on `testing-codes-before-merging`
```bash
cd /home/irium/irium-phase3
git checkout testing-codes-before-merging
git pull --ff-only origin testing-codes-before-merging
git push origin testing-codes-before-merging
```

### Option B (later): move pilot tracking to `main`
```bash
cd /home/irium/irium-phase3
git checkout main
git pull --ff-only origin main
git merge --ff-only testing-codes-before-merging
git push origin main
```

Do not switch pilot hosts to `main` until freeze criteria and rollback plan are approved.
