import hmac
import hashlib

class KeyDerivationMath:
    def __init__(self):
        # Curve parameters
        self.p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        self.n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        self.G = (
            0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
            0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        )

    def master_key_generation(self, seed: bytes) -> tuple:
        """
        Demonstrates master key generation mathematics
        Returns (private_key, chain_code)
        """
        # HMAC-SHA512(key="Bitcoin seed", message=seed)
        hmac_obj = hmac.new(b'Bitcoin seed', seed, hashlib.sha512)
        I = hmac_obj.digest()

        # Split into left (IL) and right (IR) 256-bit sequences
        IL = I[:32]  # Master private key
        IR = I[32:]  # Chain code

        # Verify private key is valid (between 1 and n-1)
        key_value = int.from_bytes(IL, 'big')
        if key_value == 0 or key_value >= self.n:
            raise ValueError("Invalid master key, try different seed")

        return IL, IR

    def child_key_derivation(self,
                             parent_key: bytes,
                             parent_chain_code: bytes,
                             index: int,
                             is_hardened: bool) -> tuple:
        """
        Demonstrates child key derivation mathematics
        Returns (child_private_key, child_chain_code)
        """
        if is_hardened:
            # Hardened derivation: data = 0x00 || parent_private_key || index
            data = b'\x00' + parent_key + index.to_bytes(4, 'big')
        else:
            # Normal derivation: data = parent_public_key || index
            parent_public = self.private_to_public(parent_key)
            data = parent_public + index.to_bytes(4, 'big')

        # HMAC-SHA512(key=parent_chain_code, message=data)
        hmac_obj = hmac.new(parent_chain_code, data, hashlib.sha512)
        I = hmac_obj.digest()

        # Split into left (IL) and right (IR) 256-bit sequences
        IL = I[:32]
        IR = I[32:]  # child chain code

        # Calculate child private key: parse256(IL) + parent_private_key (mod n)
        IL_int = int.from_bytes(IL, 'big')
        parent_key_int = int.from_bytes(parent_key, 'big')
        child_key_int = (IL_int + parent_key_int) % self.n

        if IL_int >= self.n or child_key_int == 0:
            raise ValueError("Invalid child key, try next index")

        child_key = child_key_int.to_bytes(32, 'big')
        return child_key, IR

    def private_to_public(self, private_key: bytes) -> bytes:
        """
        Convert private key to compressed public key
        Using elliptic curve point multiplication: K = k*G
        """
        k = int.from_bytes(private_key, 'big')
        point = self.point_multiply(k)

        # Convert to compressed format (02 or 03 prefix based on y coordinate)
        prefix = b'\x02' if point[1] % 2 == 0 else b'\x03'
        return prefix + point[0].to_bytes(32, 'big')

    def point_multiply(self, k: int) -> tuple:
        """
        Elliptic curve point multiplication using double-and-add algorithm
        Returns (x, y) coordinates of k*G
        """
        result = None
        addend = self.G

        while k:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            k >>= 1

        return result

    def point_add(self, P1: tuple, P2: tuple) -> tuple:
        """
        Elliptic curve point addition
        Returns (x, y) coordinates of P1 + P2
        """
        if P1 is None:
            return P2
        if P2 is None:
            return P1

        x1, y1 = P1
        x2, y2 = P2

        if x1 == x2 and y1 != y2:
            return None

        if x1 == x2:
            m = (3 * x1 * x1) * pow(2 * y1, -1, self.p)
        else:
            m = (y2 - y1) * pow(x2 - x1, -1, self.p)

        m %= self.p
        x3 = (m * m - x1 - x2) % self.p
        y3 = (m * (x1 - x3) - y1) % self.p

        return (x3, y3)


def demonstrate_derivation():
    kdm = KeyDerivationMath()

    # Example seed
    seed = bytes.fromhex('000102030405060708090a0b0c0d0e0f')

    # Generate master key
    master_private_key, master_chain_code = kdm.master_key_generation(seed)
    print(f"Master Private Key: {master_private_key.hex()}")
    print(f"Master Chain Code: {master_chain_code.hex()}")

    # Derive normal child key (index 0)
    child_private_key, child_chain_code = kdm.child_key_derivation(
        master_private_key,
        master_chain_code,
        0,
        False
    )
    print(f"\nNormal Child Private Key: {child_private_key.hex()}")
    print(f"Normal Child Chain Code: {child_chain_code.hex()}")

    # Derive hardened child key (index 0')
    hardened_private_key, hardened_chain_code = kdm.child_key_derivation(
        master_private_key,
        master_chain_code,
        0x80000000,
        True
    )
    print(f"\nHardened Child Private Key: {hardened_private_key.hex()}")
    print(f"Hardened Child Chain Code: {hardened_chain_code.hex()}")


if __name__ == "__main__":
    demonstrate_derivation()