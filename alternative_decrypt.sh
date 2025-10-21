#!/bin/bash
BLOB="cosmic_duality_blob.b64"

# Try different salt combinations with 10,000 iterations
salts=(
    "$(echo -n 'the seed is planted' | md5sum | cut -d' ' -f1)"
    "$(echo -n 'matrixsumlist' | md5sum | cut -d' ' -f1)"
    "$(echo -n 'lastwordsbeforearchichoice' | md5sum | cut -d' ' -f1)"
    "$(echo -n 'CosmicDuality' | md5sum | cut -d' ' -f1)"
    "$(echo -n 'SalPhaseIon' | md5sum | cut -d' ' -f1)"
)

passwords=(
    "CosmicDuality"
    "lastwordsbeforearchichoice"
    "fourfirsthintisyourlastcommand"
    "averyspecialdessert"
    "matrixsumlistlastwordsbeforearchichoice"
    "lastwordsbeforearchichoicematrixsumlist"
    "CosmicDualitylastwordsbeforearchichoice"
    "lastwordsbeforearchichoiceCosmicDuality"
)

for salt in "${salts[@]}"; do
    for password in "${passwords[@]}"; do
        echo "Trying salt: $salt, password: $password"
        openssl enc -aes-256-cbc -d -a -in "$BLOB" \
            -pass pass:"$password" \
            -pbkdf2 -iter 10000 -md sha256 \
            -S "$salt" -out decrypted.bin 2>/dev/null
        
        if [ $? -eq 0 ] && [ -s decrypted.bin ]; then
            echo -e "\nSUCCESS! Salt: $salt, Password: $password"
            echo "Decrypted content:"
            cat decrypted.bin
            exit 0
        fi
    done
done

echo "No valid combination found"
exit 1
