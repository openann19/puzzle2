# SalPhaseIon Phase – Password Candidates Catalog

Date: 2025-08-16 06:48

## Decoded Elements so far
| Word/Phrase | Source decoding | SHA-256 hex |
|-------------|-----------------|-------------|
| matrixsumlist | binary abba mapping | e7546e3076294907ed2a0ecaa9c33062f6e602b7c74c5aa5cc865df0ff345507 |
| enter | binary abba mapping (hint “enter”) | e08d706b3e4ce964b632746cf568913cb93f1ed36476fbb0494b80ed17c5975c |
| lastwordsbeforearchichoice | a-i,o digit→decimal→hex→ASCII | 77094e7a1591fb81379f1582cf88db5aa6ab8e77176a4d8428a1ff5decfd102d |
| thispassword | a-i,o digit→decimal→hex→ASCII | 74c1d7592daf4f89b0a7ba5e368bb59cc9e19c6a4ebb7f33cd8ccf8f3edacac0 |

These four base words plus their SHA-256 digests (8 total strings) form the primary passphrase set for brute attempts. Variants generated automatically:

* Lower/UPPER/TitleCase.
* Appended `\n` and `\r\n` (simulating an "Enter").
* SHA-256 of every variant.
* Optional concatenations and underscore joins between any two of the first 100 base words when `--combos` is enabled.

## Key-Derivation / Salt Modes Tested

* OpenSSL MD5 (`evp_bytes_to_key` 1-round)
* OpenSSL SHA-256 (`evp_bytes_to_key` 1-round)
* PBKDF2-SHA-256 with 1 000 and 10 000 iterations
* Salt options: header-embedded, literal text `matrixsumlist`, SHA-256(first 8 bytes) of that word, and no salt.

Logging for every attempt is appended to `salphaseion_attempts.log` in JSON-lines format, e.g.
```json
{"pw":"matrixsumlist","mode":"md5","salt":"header","ok":false}
```

## Current Status
No variant has yet produced readable plaintext. Next actions:
1. Expand candidate list with more words extracted from `SalPhaseIon.md` (VIC/grid/Polybius etc.).
2. Increase `--max` limit gradually or disable it during off-peak hours.
3. Explore `-nosalt` OpenSSL mode explicitly (already covered by `salt=none`).
4. If still unsuccessful, brute degenerated "unused" digit sequence for additional clues.
