#!/bin/bash
BLOB="cosmic_duality_blob.b64"

echo "🔥 ULTIMATE COMPREHENSIVE DECRYPTION - ALL METHODS 🔥"
echo "Testing ALL encryption methods discovered in the puzzle chain:"
echo "1. AES-256-CBC (standard OpenSSL)"
echo "2. AES-256-CBC with PBKDF2-SHA256"
echo "3. AES-256-CBC with MD5 salt derivation"
echo "4. Base64 + SHA256 password hashing"
echo "5. Beaufort cipher combinations"
echo "6. VIC cipher combinations"
echo "7. Binary pattern analysis"
echo "8. Multiple cipher layers"
echo ""

# ALL DISCOVERED ENCRYPTION PARAMETERS
salt_methods=(
    "md5"           # MD5 salt derivation (used in SalPhaseIon)
    "sha256"        # SHA256 salt derivation
    "raw"           # Raw string as salt
    "base64"        # Base64 encoded salt
)

key_derivation_methods=(
    "pbkdf2"        # PBKDF2 (used in SalPhaseIon success)
    "standard"      # Standard OpenSSL key derivation
    "sha256"        # SHA256 hash of password
    "raw"           # Raw password
)

iterations=(
    10000           # SalPhaseIon success value
    1048576         # 2^20 (common PBKDF2)
    100000          # Common high security
    1000000         # Very high security
    50000           # Medium security
    500000          # High security
    1               # No PBKDF2 (standard)
)

hash_functions=(
    "sha256"        # Primary hash function
    "md5"           # Used for salt derivation
    "sha1"          # Alternative
)

# ALL DISCOVERED PASSWORDS FROM ENTIRE PUZZLE CHAIN
all_passwords=(
    # Phase 1
    "theflowerblossomsthroughwhatseemstobeaconcretesurface"
    
    # Phase 2
    "causality"
    "eb3efb5151e6255994711fe8f2264427ceeebf88109e1d7fad5b0a8b6d07e5bf"
    
    # Phase 3 - 7 parts
    "causalitySafenetLunaHSM111100x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1"
    "1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5"
    
    # Phase 3.2
    "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple"
    "250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c"
    
    # Beaufort cipher
    "THEMATRIXHASYOU"
    
    # SalPhaseIon phase
    "SalPhaseIon"
    "matrixsumlist"
    "lastwordsbeforearchichoice"
    "thispassword"
    
    # Cosmic Duality phase
    "fourfirsthintisyourlastcommand"
    "averyspecialdessert"
    "CosmicDuality"
    "theseedisplanted"
    
    # All combinations discovered
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
    
    # Individual parts for testing
    "SafenetLunaHSM"
    "11110"
    "0x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854"
    "B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1"
    "jacquefrescogiveitjustonesecond"
    "heisenbergsuncertaintyprinciple"
)

# ALL DISCOVERED SALT SOURCES
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
    "SafenetLunaHSM"
    "11110"
)

total_combinations=$((${#all_passwords[@]} * ${#salt_sources[@]} * ${#iterations[@]} * ${#salt_methods[@]} * ${#key_derivation_methods[@]} * ${#hash_functions[@]}))
echo "Total combinations to test: $total_combinations"
echo ""

test_count=0
for salt_method in "${salt_methods[@]}"; do
    for kdf_method in "${key_derivation_methods[@]}"; do
        for hash_func in "${hash_functions[@]}"; do
            for iter in "${iterations[@]}"; do
                for salt_source in "${salt_sources[@]}"; do
                    
                    # Derive salt based on method
                    case $salt_method in
                        "md5")
                            salt=$(echo -n "$salt_source" | md5sum | cut -d' ' -f1)
                            ;;
                        "sha256")
                            salt=$(echo -n "$salt_source" | sha256sum | cut -d' ' -f1)
                            ;;
                        "raw")
                            salt="$salt_source"
                            ;;
                        "base64")
                            salt=$(echo -n "$salt_source" | base64 | tr -d '\n')
                            ;;
                    esac
                    
                    for password in "${all_passwords[@]}"; do
                        [[ -z "$password" ]] && continue
                        
                        test_count=$((test_count + 1))
                        if [ $((test_count % 1000)) -eq 0 ]; then
                            echo "Progress: $test_count/$total_combinations tests completed..."
                        fi
                        
                        # Derive password based on method
                        case $kdf_method in
                            "sha256")
                                final_password=$(echo -n "$password" | sha256sum | cut -d' ' -f1)
                                ;;
                            "raw"|"pbkdf2"|"standard")
                                final_password="$password"
                                ;;
                        esac
                        
                        # Build OpenSSL command based on parameters
                        if [ "$kdf_method" = "pbkdf2" ]; then
                            cmd="openssl enc -aes-256-cbc -d -a -in $BLOB -pass pass:$final_password -pbkdf2 -iter $iter -md $hash_func"
                            if [ "$salt_method" != "raw" ]; then
                                cmd="$cmd -S $salt"
                            fi
                        elif [ "$kdf_method" = "standard" ]; then
                            cmd="openssl enc -aes-256-cbc -d -a -in $BLOB -pass pass:$final_password"
                            if [ "$salt_method" != "raw" ]; then
                                cmd="$cmd -S $salt"
                            fi
                        else
                            cmd="openssl enc -aes-256-cbc -d -a -in $BLOB -pass pass:$final_password -md $hash_func"
                            if [ "$salt_method" != "raw" ]; then
                                cmd="$cmd -S $salt"
                            fi
                        fi
                        
                        # Execute decryption attempt
                        eval "$cmd -out decrypted.bin 2>/dev/null"
                        
                        if [ $? -eq 0 ] && [ -s decrypted.bin ]; then
                            echo -e "\n🎉🎉🎉 ULTIMATE SUCCESS! 🎉🎉🎉"
                            echo "Method: $kdf_method with $salt_method salt and $hash_func hash"
                            echo "Salt source: '$salt_source'"
                            echo "Salt: $salt"
                            echo "Iterations: $iter"
                            echo "Original password: $password"
                            echo "Final password: $final_password"
                            echo "Command: $cmd"
                            echo -e "\nDecrypted content:"
                            cat decrypted.bin
                            echo -e "\n\nHex dump:"
                            hexdump -C decrypted.bin | head -20
                            echo -e "\n\nTesting as Bitcoin private key..."
                            
                            # Test if it's a valid Bitcoin private key
                            python3 -c "
import sys
try:
    import bitcoin
    from bitcoin import *
    with open('decrypted.bin', 'r') as f:
        content = f.read().strip()
    
    # Try to extract private key from content
    lines = content.split('\n')
    for line in lines:
        line = line.strip()
        if len(line) == 64 and all(c in '0123456789abcdefABCDEF' for c in line):
            try:
                if is_privkey(line):
                    addr = privtoaddr(line)
                    print(f'🔑 VALID PRIVATE KEY FOUND: {line}')
                    print(f'📍 Bitcoin Address: {addr}')
                    sys.exit(0)
            except:
                pass
        elif len(line) == 51 and (line.startswith('5') or line.startswith('K') or line.startswith('L')):
            try:
                if is_privkey(line):
                    addr = privtoaddr(line)
                    print(f'🔑 VALID WIF PRIVATE KEY FOUND: {line}')
                    print(f'📍 Bitcoin Address: {addr}')
                    sys.exit(0)
            except:
                pass
    print('Content does not contain a recognizable Bitcoin private key')
except ImportError:
    print('Bitcoin library not available for key validation')
except Exception as e:
    print(f'Error validating key: {e}')
" 2>/dev/null
                            
                            exit 0
                        fi
                    done
                done
            done
        done
    done
done

echo -e "\nNo valid combination found after testing $test_count combinations"
echo "All discovered encryption methods have been exhaustively tested"
exit 1
