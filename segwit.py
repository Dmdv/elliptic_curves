import hashlib
import bech32


"""
Key points about witness version (witver):

1. For P2WPKH (Native SegWit):
- Witness version = 0
- Witness program = 20-byte pubkey hash
2. Future witness versions:
- Version 1: Taproot (P2TR)
- Versions 2-16: Reserved for future upgrades
3. Encoding rules (from BIP-173):
- Version 0: Uses Bech32 encoding
- Version 1+: Uses Bech32m encoding (BIP-350)
4. Length rules for version 0:
- P2WPKH: 20 bytes
- P2WSH: 32 bytes
"""


def public_to_p2wpkh_address(public_key: bytes, testnet: bool = False) -> str:
    """
    Convert public key to P2WPKH (Pay-to-Witness-Public-Key-Hash) Native SegWit address.

    References:
    - BIP-141: https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
    - BIP-173: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki

    For P2WPKH:
    - Witness version: 0
    - Witness program: HASH160 of public key (20 bytes)
    """
    # 1. HASH160 of public key (SHA256 + RIPEMD160)
    sha256_hash = hashlib.sha256(public_key).digest()
    ripemd160_hash = hashlib.new('ripemd160')
    ripemd160_hash.update(sha256_hash)
    pubkey_hash = ripemd160_hash.digest()  # 20 bytes

    # 2. Prepare parameters
    witver = 0  # Witness version 0 for P2WPKH
    hrp = 'tb' if testnet else 'bc'

    # 3. Convert witness program (pubkey hash) from 8-bit to 5-bit
    converted_bits = bech32.convertbits(pubkey_hash, 8, 5)
    if converted_bits is None:
        raise ValueError("Failed to convert bits")

    # 4. Encode address
    address = bech32.bech32_encode(hrp, [witver] + converted_bits)
    if address is None:
        raise ValueError("Failed to encode address")

    return address


def test_p2wpkh():
    """
    Test vectors from BIP-173
    https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#test-vectors
    """
    # Test vector 1
    pubkey_hash = bytes.fromhex('751e76e8199196d454941c45d1b3a323f1433bd6')

    class DummyPublicKey:
        def digest(self):
            return pubkey_hash

    def mock_sha256(_):
        return DummyPublicKey()

    original_sha256 = hashlib.sha256

    try:
        hashlib.sha256 = mock_sha256

        # Test mainnet address
        mainnet_address = public_to_p2wpkh_address(b'dummy_pubkey', testnet=False)
        expected_mainnet = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"

        # Test testnet address
        testnet_address = public_to_p2wpkh_address(b'dummy_pubkey', testnet=True)
        expected_testnet = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"

        print("Test Results:")
        print(f"Mainnet:")
        print(f"Generated: {mainnet_address}")
        print(f"Expected:  {expected_mainnet}")
        print(f"Match:     {mainnet_address == expected_mainnet}")

        print(f"\nTestnet:")
        print(f"Generated: {testnet_address}")
        print(f"Expected:  {expected_testnet}")
        print(f"Match:     {testnet_address == expected_testnet}")

    finally:
        hashlib.sha256 = original_sha256


def decode_p2wpkh(address: str) -> tuple:
    """
    Decode a P2WPKH address to its components.
    Returns (valid, hrp, witness_version, witness_program)
    """
    # 1. Decode the address
    hrp, data = bech32.bech32_decode(address)
    if None in (hrp, data):
        return False, None, None, None

    # 2. Check the witness version
    witness_version = data[0]
    if witness_version != 0:  # Must be 0 for P2WPKH
        return False, None, None, None

    # 3. Convert witness program back to bytes
    witness_program = bech32.convertbits(data[1:], 5, 8, False)
    if witness_program is None:
        return False, None, None, None

    # 4. For P2WPKH, witness program must be 20 bytes
    if len(witness_program) != 20:
        return False, None, None, None

    return True, hrp, witness_version, bytes(witness_program)


if __name__ == "__main__":
    test_p2wpkh()

    # Additional demonstration
    test_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    valid, hrp, witver, program = decode_p2wpkh(test_address)

    print("\nDecode example:")
    print(f"Address:          {test_address}")
    print(f"Valid:            {valid}")
    print(f"Network:          {'Mainnet' if hrp == 'bc' else 'Testnet'}")
    print(f"Witness Version:  {witver}")
    print(f"Witness Program:  {program.hex() if program else None}")