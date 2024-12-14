from DoubleAndAdd import DoubleAndAdd


class MontgomeryLadder:
    """
    Montgomery ladder algorithm for elliptic curve point multiplication
    Key Advantages of Montgomery Ladder:

    1. Side-Channel Protection:
        - The algorithm is not vulnerable to simple power analysis (SPA) attacks.
        - It does not leak information about the key through power consumption or timing.
        - No branches based on key bits, which can be exploited by attackers.
        - Uniform power consumption.
        - Harder to exploit via power analysis or timing attacks.
    2. It is a constant-time algorithm.
        - Always performs both add and double
        - Regular execution pattern
        - Better resistance to timing attacks
    3. It is efficient for scalar multiplication.
    4. It is widely used in cryptographic applications.
    5. Memory Efficiency:
        - Only two points are stored at a time.
        - No need for a precomputed table.
        - Compact implementation possible

    """
    def __init__(self):
        # secp256k1 parameters
        self.p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        self.a = 0
        self.b = 7
        self.G = (
            0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
            0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        )

    def point_add_and_double(self, P1: tuple, P2: tuple, P: tuple) -> tuple:
        """
        Perform combined point addition and doubling in Montgomery form.

        This function calculates both P1 + P2 and 2P2 in a single operation,
        which is a key component of the Montgomery ladder algorithm for
        elliptic curve point multiplication.

        Parameters:
        P1 (tuple): A point on the elliptic curve represented as (x, y).
        P2 (tuple): Another point on the elliptic curve represented as (x, y).
        P (tuple): The base point of the elliptic curve (not used in this implementation).

        Returns:
        tuple: A tuple containing two points:
               - The first element is the result of P1 + P2.
               - The second element is the result of 2P2.
               Each point is represented as a tuple (x, y).
               Returns (None, None) if P1 and P2 are inverse points.
        """
        x1, y1 = P1
        x2, y2 = P2
        xp, yp = P

        # Calculate differences and sums
        dx = (x2 - x1) % self.p
        dy = (y2 - y1) % self.p
        sx = (x2 + x1) % self.p
        sy = (y2 + y1) % self.p

        # Slope for addition
        if dx != 0:
            m1 = (dy * pow(dx, -1, self.p)) % self.p
        else:
            if dy == 0:  # P1 = P2
                m1 = (3 * x1 * x1) * pow(2 * y1, -1, self.p)
            else:
                return None, None  # Points are inverses

        # Slope for doubling
        m2 = (3 * x2 * x2) * pow(2 * y2, -1, self.p)

        # New x-coordinates
        x3 = (m1 * m1 - sx) % self.p  # For P1 + P2
        x4 = (m2 * m2 - 2 * x2) % self.p  # For 2P2

        # New y-coordinates
        y3 = (m1 * (x1 - x3) - y1) % self.p  # For P1 + P2
        y4 = (m2 * (x2 - x4) - y2) % self.p  # For 2P2

        return (x3, y3), (x4, y4)

    def montgomery_ladder(self, k: int, P: tuple = None) -> tuple:
        """
        Compute scalar multiplication k*P using the Montgomery ladder algorithm.

        This method implements the Montgomery ladder, which is a constant-time algorithm
        for elliptic curve scalar multiplication. It's resistant to simple power analysis
        attacks as it always performs both addition and doubling operations.

        Parameters:
        k (int): The scalar value to multiply with the point P.
        P (tuple, optional): The point on the elliptic curve to be multiplied.
                             If None, the generator point G is used. Default is None.

        Returns:
        tuple: The resulting point k*P on the elliptic curve, represented as (x, y).
               Returns None if k is 0.

        Note:
        - The method handles negative k by negating the y-coordinate of P.
        - The binary representation of k is processed from left to right.
        """
        if P is None:
            P = self.G

        if k == 0:
            return None
        if k < 0:
            k = -k
            P = (P[0], (-P[1]) % self.p)

        R0 = None  # Point at infinity
        R1 = P

        # Process bits from left to right
        bits = bin(k)[2:]  # Remove '0b' prefix
        for bit in bits:
            if bit == '0':
                R1, R0 = self.point_add_and_double(R1, R0, P)
            else:
                R0, R1 = self.point_add_and_double(R0, R1, P)

        return R0

    def demonstrate_ladder(self, k: int):
        """
        Demonstrate Montgomery ladder steps
        """
        if k < 0:
            raise ValueError("Demonstrate with positive k for clarity")

        print(f"Computing {k} * G using Montgomery ladder")
        print(f"Binary representation of {k}: {bin(k)[2:]}")

        R0 = None
        R1 = self.G
        step = 1

        bits = bin(k)[2:]
        for bit in bits:
            print(f"\nStep {step}:")
            print(f"Current bit: {bit}")

            prev_R0, prev_R1 = R0, R1

            if bit == '0':
                R1, R0 = self.point_add_and_double(R1, R0, self.G)
                print("Operation: R1 = R0 + R1, R0 = 2R0")
            else:
                R0, R1 = self.point_add_and_double(R0, R1, self.G)
                print("Operation: R0 = R0 + R1, R1 = 2R1")

            print(f"R0: {R0}")
            print(f"R1: {R1}")

            step += 1

        return R0


class SecurePointMultiplication:
    """
    Comparison of multiplication methods with timing attack resistance
    """

    def __init__(self):
        self.montgomery = MontgomeryLadder()

    def constant_time_compare(self, point1: tuple, point2: tuple) -> bool:
        """
        Constant-time point comparison to prevent timing attacks
        """
        if point1 is None or point2 is None:
            return False

        # Convert points to bytes for comparison
        p1_bytes = point1[0].to_bytes(32, 'big') + point1[1].to_bytes(32, 'big')
        p2_bytes = point2[0].to_bytes(32, 'big') + point2[1].to_bytes(32, 'big')

        result = 0
        for x, y in zip(p1_bytes, p2_bytes):
            result |= x ^ y
        return result == 0

    def timing_analysis(self, k: int):
        """
        Compare timing characteristics of different multiplication methods
        """
        import time

        # Montgomery ladder timing
        start = time.perf_counter()
        mont_result = self.montgomery.montgomery_ladder(k)
        mont_time = time.perf_counter() - start

        # Standard double-and-add timing (for comparison)
        start = time.perf_counter()
        da = DoubleAndAdd()
        da_result = da.double_and_add(k)
        da_time = time.perf_counter() - start

        print(f"\nTiming Analysis for k = {k}:")
        print(f"Montgomery Ladder: {mont_time:.6f} seconds")
        print(f"Double-and-Add: {da_time:.6f} seconds")
        print(f"Results match: {self.constant_time_compare(mont_result, da_result)}")


def compare_methods():
    secure = SecurePointMultiplication()

    # Test with different scalar values
    test_values = [
        0x3,  # Small value
        0x1234,  # Medium value
        0x123456789ABCDEF  # Large value
    ]

    for k in test_values:
        secure.timing_analysis(k)


if __name__ == "__main__":
    compare_methods()