# Real Dataset Status

This release contains reproducible download/import/training code, but no fabricated benchmark numbers.

The build environment used to assemble this archive had outbound DNS/network access disabled, so real public datasets could not be downloaded during packaging. On Kali Linux with network access, run `scripts/fetch_real_datasets.sh` for the UCI SMS corpus and follow `docs/DATASETS.md` for UNSW-NB15 and PhishTank acquisition. Training reports are generated only after those real files are present.

Competition rule: do not submit placeholder or synthetic metrics as real results.
