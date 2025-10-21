#!/bin/bash
BLOB="cosmic_duality_blob.b64"

# All discovered salt sources
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
    "jacquefrescogiveitjustonesecond"
    "heisenbergsuncertaintyprinciple"
    "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple"
)

# All discovered passwords (including raw and SHA256 hashes)
passwords=(
    # Raw passwords from all phases
    "causality"
    "SafenetLunaHSM"
    "11110"
    "0x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854"
    "B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1"
    "causalitySafenetLunaHSM111100x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1"
    "THEMATRIXHASYOU"
    "matrixsumlist"
    "lastwordsbeforearchichoice"
    "thispassword"
    "SalPhaseIon"
    "fourfirsthintisyourlastcommand"
    "averyspecialdessert"
    "CosmicDuality"
    "theseedisplanted"
    "theflowerblossomsthroughwhatseemstobeaconcretesurface"
    "jacquefrescogiveitjustonesecond"
    "heisenbergsuncertaintyprinciple"
    "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple"
    
    # Known SHA256 hashes from puzzle
    "1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5"
    "250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c"
    "eb3efb5151e6255994711fe8f2264427ceeebf88109e1d7fad5b0a8b6d07e5bf"
    
    # Combinations from SalPhaseIon phase
    "matrixsumlistlastwordsbeforearchichoice"
    "lastwordsbeforearchichoicematrixsumlist"
    "SalPhaseIonmatrixsumlist"
    "matrixsumlistSalPhaseIon"
    "CosmicDualitylastwordsbeforearchichoice"
    "lastwordsbeforearchichoiceCosmicDuality"
    "fourfirsthintisyourlastcommandaveryspecialdessert"
    "averyspecialdessertfourfirsthintisyourlastcommand"
    "CosmicDualityfourfirsthintisyourlastcommand"
    "fourfirsthintisyourlastcommandCosmicDuality"
    "averyspecialdessertCosmicDuality"
    "CosmicDualityaveryspecialdessert"
    
    # Full chain combinations
    "theflowerblossomsthroughwhatseemstobeaconcretesurfacecausalityTHEMATRIXHASYOUSalPhaseIonmatrixsumlistlastwordsbeforearchichoicethispasswordfourfirsthintisyourlastcommandaveryspecialdessertCosmicDualitytheseedisplanted"
    "causalityTHEMATRIXHASYOUSalPhaseIonmatrixsumlistlastwordsbeforearchichoicethispasswordfourfirsthintisyourlastcommandaveryspecialdessertCosmicDuality"
    "THEMATRIXHASYOUSalPhaseIonmatrixsumlistlastwordsbeforearchichoicethispasswordfourfirsthintisyourlastcommandaveryspecialdessert"
    "SalPhaseIonmatrixsumlistlastwordsbeforearchichoicethispasswordfourfirsthintisyourlastcommandaveryspecialdessert"
    "matrixsumlistlastwordsbeforearchichoicethispasswordfourfirsthintisyourlastcommandaveryspecialdessert"
)

# Test different iteration counts
iterations=(10000 1048576 100000 1000000 50000 500000)

echo "Testing ${#passwords[@]} passwords with ${#salt_sources[@]} salts and ${#iterations[@]} iteration counts..."
echo "Total combinations: $((${#passwords[@]} * ${#salt_sources[@]} * ${#iterations[@]}))"

for iter in "${iterations[@]}"; do
    for salt_source in "${salt_sources[@]}"; do
        salt=$(echo -n "$salt_source" | md5sum | cut -d' ' -f1)
        echo "Testing iterations: $iter, salt: '$salt_source' -> $salt"
        
        for password in "${passwords[@]}"; do
            [[ -z "$password" ]] && continue
            
            # Test raw password
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
            
            # Also test SHA256 hash of password
            sha_password=$(echo -n "$password" | sha256sum | cut -d' ' -f1)
            openssl enc -aes-256-cbc -d -a -in "$BLOB" \
                -pass pass:"$sha_password" \
                -pbkdf2 -iter "$iter" -md sha256 \
                -S "$salt" -out decrypted.bin 2>/dev/null
            
            if [ $? -eq 0 ] && [ -s decrypted.bin ]; then
                echo -e "\n🎉 SUCCESS WITH SHA256! 🎉"
                echo "Salt source: '$salt_source'"
                echo "Salt: $salt"
                echo "Iterations: $iter"
                echo "Original password: $password"
                echo "SHA256 password: $sha_password"
                echo -e "\nDecrypted content:"
                cat decrypted.bin
                echo -e "\n\nHex dump:"
                hexdump -C decrypted.bin | head -10
                exit 0
            fi
        done
    done
done

echo "No valid combination found with any tested parameters"
exit 1
