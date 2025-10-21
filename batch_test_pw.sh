#!/usr/bin/env bash
# batch_test_pw.sh <blob.b64> <pwlist.txt>
BLOB="$1"; PWF="$2"; OUTDIR=artifacts
mkdir -p "$OUTDIR"
SHEX=$(printf "matrixsumlist" | sha256sum | awk '{print substr($1,1,16)}')
i=0
while IFS= read -r pw || [ -n "$pw" ]; do
  i=$((i+1))
  for variant in "$pw" "$(printf "%s\n" "$pw")" "$(printf "%s\r\n" "$pw")" "$(echo "$pw" | tr '[:lower:]' '[:upper:]')"; do
    for mode in md5 sha256 pbkdf2; do
      for iter in 0 1000 10000; do
        if [ "$mode" != "pbkdf2" ] && [ "$iter" -ne 0 ]; then continue; fi
        for salt in embedded nosalt; do
          OUT="$OUTDIR/out_${i}_${mode}_${iter}_${salt}.bin"
          ARGS=(enc -aes-256-cbc -d -a -in "$BLOB")
          [ "$salt" = "nosalt" ] && ARGS+=(-nosalt)
          [ "$mode" = "md5" ] && ARGS+=(-md md5)
          [ "$mode" = "sha256" ] && [ "$iter" -eq 0 ] && ARGS+=(-md sha256)
          [ "$mode" = "pbkdf2" ] && ARGS+=(-pbkdf2 -md sha256 -iter "$iter")
          ARGS+=(-pass "pass:${variant}")
          if openssl "${ARGS[@]}" > "$OUT" 2>/dev/null; then
            pr=$(python - <<PY
b=open("$OUT","rb").read()
print(sum(1 for c in b.decode("latin1") if c.isprintable())/max(1,len(b)))
PY
)
            if (( $(echo "$pr >= 0.50" | bc -l) )); then
              echo "POSSIBLE HIT pw=$pw mode=$mode iter=$iter salt=$salt out=$OUT printable=$pr"
            fi
          else
            rm -f "$OUT"
          fi
        done
        # derived-salt for top 500 only (adjust by i)
        if [ "$i" -le 500 ]; then
          OUTD="$OUTDIR/out_${i}_${mode}_${iter}_derived.bin"
          ARGS=(enc -aes-256-cbc -d -a -in "$BLOB" -S "$SHEX")
          [ "$mode" = "md5" ] && ARGS+=(-md md5)
          [ "$mode" = "sha256" ] && [ "$iter" -eq 0 ] && ARGS+=(-md sha256)
          [ "$mode" = "pbkdf2" ] && ARGS+=(-pbkdf2 -md sha256 -iter "$iter")
          ARGS+=(-pass "pass:${variant}")
          if openssl "${ARGS[@]}" > "$OUTD" 2>/dev/null; then
            pr=$(python - <<PY
b=open("$OUTD","rb").read()
print(sum(1 for c in b.decode("latin1") if c.isprintable())/max(1,len(b)))
PY
)
            if (( $(echo "$pr >= 0.50" | bc -l) )); then
              echo "POSSIBLE HIT (derived) pw=$pw mode=$mode iter=$iter out=$OUTD printable=$pr"
            fi
          else
            rm -f "$OUTD"
          fi
        fi
      done
    done
  done
done < "$PWF"
