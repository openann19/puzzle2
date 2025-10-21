#!/bin/bash
BLOB=$1
CANDIDATES=$2
SALT="$(echo -n "the seed is planted" | md5sum | cut -d' ' -f1)"

while read -r password; do
  echo "Trying: $password"
  openssl enc -aes-256-cbc -d -a -in "$BLOB" \
    -pass pass:"$password" \
    -pbkdf2 -iter 1048576 -md sha256 \
    -S "$SALT" -out decrypted.bin 2>/dev/null
  
  if [ $? -eq 0 ]; then
    echo -e "\nSUCCESS! Password: $password"
    echo "Decrypted content:"
    cat decrypted.bin
    exit 0
  fi
done < "$CANDIDATES"

echo "No valid password found"
exit 1
