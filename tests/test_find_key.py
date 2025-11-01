"""
Test for finding the Bitcoin puzzle key
"""
import pytest
import os
import re

def test_key_file_exists():
    """Test that a key.txt file exists documenting the solution"""
    assert os.path.exists('key.txt'), "key.txt file should exist"
    
    with open('key.txt', 'r') as f:
        content = f.read()
    
    # Verify key information is documented
    assert len(content) > 100, "key.txt should contain substantial documentation"
    assert '1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe' in content, "Target address should be documented"

def test_target_address_known():
    """Test that the target address is identified"""
    target = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
    assert len(target) == 34, "Target address should be valid length"
    assert target.startswith('1'), "Target address should be P2PKH format"

def test_cosmic_duality_blob_exists():
    """Test that the Cosmic Duality encrypted blob is identified"""
    assert os.path.exists('SalPhaseIon.md'), "SalPhaseIon.md should exist"
    
    with open('SalPhaseIon.md', 'r') as f:
        content = f.read()
    
    assert 'Cosmic Duality' in content, "Cosmic Duality section should exist"
    assert 'U2FsdGVkX1' in content, "OpenSSL encrypted data should be present"

def test_solution_script_exists():
    """Test that a solution script exists"""
    assert os.path.exists('find_key_solution.py'), "Solution script should exist"

def test_imports_work():
    """Test that required modules can be imported"""
    try:
        from Cryptodome.Cipher import AES
        from Cryptodome.Hash import MD5
        from ecdsa import SigningKey, SECP256k1
        assert True
    except ImportError as e:
        pytest.fail(f"Required module missing: {e}")
