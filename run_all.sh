#!/usr/bin/env bash
set -euo pipefail
echo "[1] Extract blobs..."
python3 extract_spaced_blob.py SalPhaseIon.md --out artifacts/blob_salphase.b64 --minlen 100 || true
python3 extract_spaced_blob.py SalPhaseIon.md --out artifacts/blob_big.b64 --minlen 400 || true
echo "[2] Mine tokens (v2)..."
python3 mine_unused_tokens_v2.py
echo "[3] Deep mining (polybius/tap/vic)..."
python3 polybius_tap_vic.py
echo "[4] Build pwlist (top seeds + mined)"
( echo matrixsumlist; echo thispassword; echo lastwordsbeforearchichoice; echo enter; cat candidates_from_unused_v2.txt candidates_polybius_tap_vic.txt 2>/dev/null || true ) | awk 'NF' | awk '!x[$0]++' | head -n 2000 > pwlist.txt
echo "pwlist saved, count:" $(wc -l pwlist.txt)
echo "[5] Run sweeper (stop on first plausible)"
python3 salphaseion_sweeper.py --blob artifacts/blob_salphase.b64 --seeds-file pwlist.txt --max-candidates 2000 --stop-on-first --top-derive-limit 500 || true
echo "[6] If no hit, run batch (md5+derived top500)"
bash batch_test_pw.sh artifacts/blob_salphase.b64 pwlist.txt || true
echo "Finished run_all"
