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
import hmac
from typing import Tuple, List
import base58
import random

# Rest of the code...

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

    def public_to_address(self, public_key: bytes, testnet: bool = False) -> str:
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
    address = bitcoin_keys.public_to_address(public_key)
    testnet_address = bitcoin_keys.public_to_address(public_key, testnet=True)
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
        address = bitcoin_keys.public_to_address(public_key)
        print(f"\nPath: {path}")
        print(f"Address: {address}")


if __name__ == "__main__":
    demonstrate_bitcoin_keys()