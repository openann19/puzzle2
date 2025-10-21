#!/bin/bash
BLOB="cosmic_duality_blob.b64"
CANDIDATES="comprehensive_all_passwords.txt"

# All possible salt sources from the puzzle chain
salt_sources=(
    "the seed is planted"
    "matrixsumlist"
    "lastwordsbeforearchichoice"
    "CosmicDuality"
    "SalPhaseIon"
    "thispassword"
    "causality"
    "THEMATRIXHASYOU"
    "theflowerblossomsthroughwhatseemstobeaconcretesurface"
    "fourfirsthintisyourlastcommand"
    "averyspecialdessert"
)

# Test different iteration counts
iterations=(10000 1048576 100000 1000000)

echo "Testing $(wc -l < $CANDIDATES) passwords with $(echo ${#salt_sources[@]}) salts and $(echo ${#iterations[@]}) iteration counts..."
echo "Total combinations: $(($(wc -l < $CANDIDATES) * ${#salt_sources[@]} * ${#iterations[@]}))"

for iter in "${iterations[@]}"; do
    for salt_source in "${salt_sources[@]}"; do
        salt=$(echo -n "$salt_source" | md5sum | cut -d' ' -f1)
        echo "Testing with iterations: $iter, salt source: '$salt_source' (salt: $salt)"
        
        while read -r password; do
            [[ -z "$password" ]] && continue
            
            openssl enc -aes-256-cbc -d -a -in "$BLOB" \
                -pass pass:"$password" \
                -pbkdf2 -iter "$iter" -md sha256 \
                -S "$salt" -out decrypted.bin 2>/dev/null
            
            if [ $? -eq 0 ] && [ -s decrypted.bin ]; then
                echo -e "\n🎉 SUCCESS! 🎉"
                echo "Salt source: '$salt_source'"
                echo "Salt: $salt"
                echo "Iterations: $iter"
                echo "Password: $password"
                echo -e "\nDecrypted content:"
                cat decrypted.bin
                echo -e "\n\nHex dump:"
                hexdump -C decrypted.bin | head -10
                exit 0
            fi
        done < "$CANDIDATES"
    done
done

echo "No valid combination found with any tested parameters"
exit 1
