# Datasets (Layers 2 and 3)

| Source | What it is | License | In git? |
|---|---|---|---|
| `backend/app/layers/fixtures/layer2_match_scores.csv` | 200 SYNTHETIC face-matcher scores (100 genuine, 100 impostor; 4 scenarios incl. "look-alike" impostors). Floats only. No images or biometric data. | Project license (generated here by `backend/scripts/gen_layers23_fixtures.py`, seed 20261015) | Yes (11,530 bytes) |
| `backend/app/layers/fixtures/layer3_pad_cases.csv` | 120 SYNTHETIC liveness challenge-response cases (60 genuine, 60 attacks: wrong response, stale replay, client-asserted liveness). Text tokens prefixed `SPECIMEN-`. No media. | Same as above | Yes (9,289 bytes) |

Regenerate with `cd backend && python scripts/gen_layers23_fixtures.py` (deterministic).

## Public datasets: none used

Public face-verification and PAD datasets that we know of (LFW, CelebA-Spoof, CASIA-FASD, Replay-Attack, OULU-NPU, SiW, etc.) contain
images of real people, which this project's data rule forbids. Fully synthetic face sets
(e.g. DigiFace-1M, SFHQ) would also need a face-embedding model plus a matcher. Their licenses
(often non-commercial or unclear) were not reviewed and approved for this project, so no such
dataset was adopted. For the same reason, there is no download script or checksum manifest yet.
If an approved dataset is added later, keep it out of git and add a fetch script with SHA-256
checksums plus a row in this table.

## Why there are no rendered ID documents here

Layers 2 and 3 take matcher scores and liveness decisions, not document images. Document
validation is Layer 1, and the README rules out counterfeit-document generators. So no
SPECIMEN ID images were rendered for this change.
