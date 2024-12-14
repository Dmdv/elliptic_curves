"""
Bitcoin Key Management and HD Wallet Implementation

This module provides classes and functions for Bitcoin key management,
address generation, and Hierarchical Deterministic (HD) wallet operations.

Classes:
    BitcoinKeys: Handles Bitcoin key operations and address generation.
    HDWallet: Implements Hierarchical Deterministic wallet functionality.

Functions:
    demonstrate_bitcoin_keys: Demonstrates the usage of BitcoinKeys and HDWallet classes.

The module implements core cryptographic operations used in Bitcoin,
including elliptic curve operations on the secp256k1 curve, key generation,
and address derivation. It also includes a basic implementation of BIP32
for HD wallets.

Note: This implementation is for educational purposes and should not be
used in production environments without proper security audits and enhancements.

Key concept:
1. Private Key Generation:
    - Random 256-bit number
    - Must be less than curve order n
    - Serves as the seed for all derivations
2. Public Key Generation:
    - Point multiplication: k * G (where k is private key, G is generator point)
    - Uses secp256k1 elliptic curve
    - Uncompressed format: 04 || x || y
3. Address Generation:
    - SHA256 then RIPEMD160 of public key
    - Version byte prepended (0x00 for mainnet)
    - Checksum added (double SHA256)
    - Base58Check encoding
4. HD Wallet Implementation:
    - BIP32 hierarchical deterministic wallets
    - Master key generation from seed
    - Child key derivation
    - Path-based derivation (BIP44 compatible)

Dependencies:
    - hashlib: For cryptographic hash functions
    - hmac: For HMAC operations
    - typing: For type hinting
    - base58: For Base58 encoding (requires installation)
    - random: For generating random numbers

Usage:
    Run this file directly to see a demonstration of key generation,
    address creation, and HD wallet derivation.

Example:
    $ python bitcoin.py
"""

import hashlib
from typing import Tuple
import base58
import random
import bech32
import hmac

class BitcoinKeys:
    """Bitcoin Key Management and Address Generation"""

    def __init__(self):
        """
        Initialize the BitcoinKeys class with secp256k1 curve parameters.
        """
        # secp256k1 curve parameters

        # Field prime
        self.p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        # Curve order
        self.n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        # Curve coefficients: y² = x³ + ax + b
        # Curve parameters for secp256k1
        self.a = 0 # Coefficient of x
        self.b = 7 # Constant term
        # Generator point
        self.Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        self.Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

    def point_add(self, p1: Tuple[int, int], p2: Tuple[int, int]) -> Tuple[int, int] | None:
        """
        Add two points on the secp256k1 curve.

        Args:
            p1 (Tuple[int, int]): The first point as a tuple of x and y coordinates.
            p2 (Tuple[int, int]): The second point as a tuple of x and y coordinates.

        Returns:
            Tuple[int, int] | None: The resulting point as a tuple of x and y coordinates,
                                    or None if the result is the point at infinity.
        """
        if p1 is None:
            return p2
        if p2 is None:
            return p1

        x1, y1 = p1
        x2, y2 = p2

        if x1 == x2 and y1 != y2:
            return None

        if x1 == x2:
            # Point doubling
            lam = (3 * x1 * x1) * pow(2 * y1, -1, self.p)
        else:
            # Point addition
            lam = (y2 - y1) * pow(x2 - x1, -1, self.p)

        lam %= self.p
        x3 = (lam * lam - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p

        return x3, y3

    def point_multiply(self, k: int, point: Tuple[int, int]) -> Tuple[int, int]:
        """
        Perform scalar multiplication of a point on the secp256k1 curve.

        Args:
            k (int): The scalar value to multiply the point by.
            point (Tuple[int, int]): The point to be multiplied, as a tuple of x and y coordinates.

        Returns:
            Tuple[int, int]: The resulting point after scalar multiplication,
                             as a tuple of x and y coordinates.
        """
        result = None
        addend = point

        while k:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            k >>= 1

        return result

    def generate_private_key(self) -> bytes:
        """
        Generate a random private key.

        Returns:
            bytes: A randomly generated private key as a 32-byte sequence.
        """
        return random.randrange(1, self.n).to_bytes(32, 'big')

    def private_to_public(self, private_key: bytes) -> bytes:
        """
        Convert a private key to its corresponding public key.

        Args:
            private_key (bytes): The private key as a 32-byte sequence.

        Returns:
            bytes: The corresponding public key in uncompressed format (65 bytes).
        """
        k = int.from_bytes(private_key, 'big')
        point = self.point_multiply(k, (self.Gx, self.Gy))

        # Uncompressed public key format
        return b'\x04' + point[0].to_bytes(32, 'big') + point[1].to_bytes(32, 'big')

class HDWallet:
    """Hierarchical Deterministic Wallet Implementation"""

    def __init__(self, seed: bytes = None):
        self.bitcoin_keys = BitcoinKeys()
        if seed is None:
            self.seed = self.generate_seed()
        else:
            self.seed = seed
        self.master_private_key, self.master_chain_code = self.generate_master_keys()

    def generate_seed(self, strength: int = 128) -> bytes:
        """Generate random seed (this is simplified - real implementations use BIP39)"""
        return random.randrange(2 ** strength).to_bytes(strength // 8, 'big')

    def generate_master_keys(self) -> Tuple[bytes, bytes]:
        """Generate master private key and chain code"""
        hmac_obj = hmac.new(b'Bitcoin seed', self.seed, hashlib.sha512)
        master_key = hmac_obj.digest()

        return master_key[:32], master_key[32:]

    def derive_child_key(self, parent_key: bytes, parent_chain: bytes,
                         index: int, hardened: bool = False) -> Tuple[bytes, bytes]:
        """Derive child key at index"""
        if hardened:
            index += 0x80000000

        if hardened:
            # Hardened derivation
            data = b'\x00' + parent_key + index.to_bytes(4, 'big')
        else:
            # Normal derivation
            public_key = self.bitcoin_keys.private_to_public(parent_key)
            data = public_key + index.to_bytes(4, 'big')

        hmac_obj = hmac.new(parent_chain, data, hashlib.sha512)
        derived = hmac_obj.digest()

        child_key = (int.from_bytes(derived[:32], 'big') +
                     int.from_bytes(parent_key, 'big')) % self.bitcoin_keys.n

        return child_key.to_bytes(32, 'big'), derived[32:]

    def derive_path(self, path: str) -> Tuple[bytes, bytes]:
        """
        Derive a child key from a given derivation path.

        This function takes a derivation path string and generates the corresponding
        child private key and chain code by applying the path to the master key.

        Args:
            path (str): A string representing the derivation path. It should be in the
                        format "m/a'/b/c", where numbers represent child key indices
                        and the apostrophe (') denotes hardened derivation.

        Returns:
            Tuple[bytes, bytes]: A tuple containing two elements:
                - The derived child private key (32 bytes)
                - The derived chain code (32 bytes)

        Example:
            To derive the first account's first external address in BIP44:
            derive_path("m/44'/0'/0'/0/0")
        """
        key = self.master_private_key
        chain = self.master_chain_code

        if path == 'm':
            return key, chain

        for level in path.split('/')[1:]:
            hardened = False
            if level[-1] == "'":
                hardened = True
                level = level[:-1]
            index = int(level)
            key, chain = self.derive_child_key(key, chain, index, hardened)

        return key, chain

def public_to_address(public_key: bytes, testnet: bool = False) -> str:
    """
    Convert a public key to a Bitcoin address.

    Args:
        public_key (bytes): The public key in uncompressed format (65 bytes).
        testnet (bool, optional): Whether to generate a testnet address. Defaults to False.

    Returns:
        str: The Bitcoin address as a Base58Check encoded string.
    """
    # SHA256 of public key
    sha256_hash = hashlib.sha256(public_key).digest()

    # RIPEMD160 of SHA256
    ripemd160_hash = hashlib.new('ripemd160')
    ripemd160_hash.update(sha256_hash)
    hash160 = ripemd160_hash.digest()

    # Add version byte (0x00 for mainnet, 0x6F for testnet)
    version = b'\x6f' if testnet else b'\x00'
    versioned_hash = version + hash160

    # Double SHA256 for checksum
    double_sha256 = hashlib.sha256(
        hashlib.sha256(versioned_hash).digest()
    ).digest()

    # First 4 bytes of double SHA256 as checksum
    checksum = double_sha256[:4]

    # Concatenate versioned hash and checksum
    binary_address = versioned_hash + checksum

    # Base58 encode
    address = base58.b58encode(binary_address).decode('utf-8')

    return address

def public_to_legacy_address(public_key: bytes, testnet: bool = False) -> str:
    """Convert public key to legacy P2PKH address (starts with 1)"""
    # This is the original public_to_address method
    sha256_hash = hashlib.sha256(public_key).digest()
    ripemd160_hash = hashlib.new('ripemd160')
    ripemd160_hash.update(sha256_hash)
    hash160 = ripemd160_hash.digest()

    version = b'\x6f' if testnet else b'\x00'
    versioned_hash = version + hash160
    checksum = hashlib.sha256(hashlib.sha256(versioned_hash).digest()).digest()[:4]
    binary_address = versioned_hash + checksum

    return base58.b58encode(binary_address).decode('utf-8')

def public_to_segwit_address(public_key: bytes, testnet: bool = False) -> str:
    """Convert public key to P2SH-wrapped SegWit address (starts with 3)"""
    # 1. Create the witness program
    sha256_hash = hashlib.sha256(public_key).digest()
    ripemd160_hash = hashlib.new('ripemd160')
    ripemd160_hash.update(sha256_hash)
    hash160 = ripemd160_hash.digest()

    # 2. Create P2SH redeemScript
    redeem_script = b'\x00\x14' + hash160  # 0x00 is witness version, 0x14 is push 20 bytes

    # 3. Hash the redeemScript
    sha256_hash = hashlib.sha256(redeem_script).digest()
    ripemd160_hash = hashlib.new('ripemd160')
    ripemd160_hash.update(sha256_hash)
    script_hash = ripemd160_hash.digest()

    # 4. Create P2SH address
    version = b'\xc4' if testnet else b'\x05'
    versioned_hash = version + script_hash
    checksum = hashlib.sha256(hashlib.sha256(versioned_hash).digest()).digest()[:4]
    binary_address = versioned_hash + checksum

    return base58.b58encode(binary_address).decode('utf-8')

def public_to_native_segwit_address_bech32(public_key: bytes, testnet: bool = False) -> str:
    """
    Convert public key to Native SegWit (bech32) address using bech32 library.
    Returns address in format bc1... for mainnet or tb1... for testnet
    """
    # 1. Hash the public key (HASH160) HASH160(x) = RIPEMD160(SHA256(x))
    sha256_hash = hashlib.sha256(public_key).digest()
    ripemd160_hash = hashlib.new('ripemd160')
    ripemd160_hash.update(sha256_hash)
    hash160 = ripemd160_hash.digest()

    # 2. Prepare parameters for bech32 encoding
    witver = 0  # Witness version for P2WPKH
    hrp = 'tb' if testnet else 'bc'  # Human-readable part

    # 3. Convert 8-bit bytes to 5-bit integers
    data = [witver] + list(hash160)
    five_bit_data = bech32.convertbits(data, 8, 5)

    # 4. Encode with bech32
    address = bech32.bech32_encode(hrp, five_bit_data)

    return address

def verify_bech32_address(address: str) -> Tuple[bool, str, int, bytes]:
    """
    Verify a Bech32 address and decode its components.

    Returns:
        Tuple containing:
        - bool: Whether address is valid
        - str: Human-readable prefix ('bc' or 'tb')
        - int: Witness version
        - bytes: Witness program (pubkey hash)
    """
    try:
        # Decode the address
        hrp, data = bech32.bech32_decode(address)

        # Check if decode was successful
        if hrp is None or data is None:
            return False, "", 0, b""

        # Convert from 5-bit to 8-bit
        decoded_data = bech32.convertbits(data[1:], 5, 8, False)
        if decoded_data is None:
            return False, "", 0, b""

        # Check valid prefix
        if hrp not in ['bc', 'tb']:
            return False, "", 0, b""

        # Check witness version
        witness_version = data[0]
        if witness_version > 16:
            return False, "", 0, b""

        # Check program length for v0
        if witness_version == 0 and len(decoded_data) != 20 and len(decoded_data) != 32:
            return False, "", 0, b""

        return True, hrp, witness_version, bytes(decoded_data)

    except Exception:
        return False, "", 0, b""

def demonstrate_bech32_addresses():
    """Demonstrate generation and verification of Bech32 addresses"""
    bitcoin_keys = BitcoinKeys()

    # Generate keys
    private_key = bitcoin_keys.generate_private_key()
    public_key = bitcoin_keys.private_to_public(private_key)

    # Generate addresses using different methods
    address1 = public_to_native_segwit_address_bech32(public_key)

    print("\nBech32 Address Generation:")
    print(f"Using bech32 library:    {address1}")

    # Verify addresses
    valid, hrp, witver, witprog = verify_bech32_address(address1)

    print("\nAddress Verification:")
    print(f"Valid:            {valid}")
    print(f"Network:          {'Mainnet' if hrp == 'bc' else 'Testnet'}")
    print(f"Witness Version:  {witver}")
    print(f"Witness Program:  {witprog.hex()}")

    # Test with some example addresses
    test_addresses = [
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",  # Valid mainnet
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",  # Valid testnet
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",  # Invalid checksum
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3"  # Invalid length
    ]

    print("\nTesting Various Addresses:")
    for addr in test_addresses:
        valid, hrp, witver, witprog = verify_bech32_address(addr)
        print(f"\nAddress: {addr}")
        print(f"Valid: {valid}")
        if valid:
            print(f"Network: {'Mainnet' if hrp == 'bc' else 'Testnet'}")
            print(f"Witness Version: {witver}")
            print(f"Witness Program: {witprog.hex()}")

def demonstrate_bitcoin_keys():
    # Create Bitcoin keys
    bitcoin_keys = BitcoinKeys()

    # Generate private key
    private_key = bitcoin_keys.generate_private_key()
    print(f"\nPrivate Key (hex): {private_key.hex()}")

    # Generate public key
    public_key = bitcoin_keys.private_to_public(private_key)
    print(f"Public Key (hex): {public_key.hex()}")

    # Generate Bitcoin address
    address = public_to_address(public_key)
    testnet_address = public_to_address(public_key, testnet=True)
    print(f"Bitcoin Address (mainnet): {address}")
    print(f"Bitcoin Address (testnet): {testnet_address}")

    # Demonstrate HD Wallet
    print("\nHD Wallet Demonstration:")
    wallet = HDWallet()

    # Derive some common paths
    paths = [
        "m/44'/0'/0'/0/0",  # First receiving address
        "m/44'/0'/0'/0/1",  # Second receiving address
        "m/44'/0'/0'/1/0"  # First change address
    ]

    for path in paths:
        private_key, chain_code = wallet.derive_path(path)
        public_key = bitcoin_keys.private_to_public(private_key)
        address = public_to_address(public_key)
        print(f"\nPath: {path}")
        print(f"Address: {address}")

if __name__ == "__main__":
    demonstrate_bitcoin_keys()
    demonstrate_bech32_addresses()