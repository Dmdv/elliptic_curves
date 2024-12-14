class DoubleAndAdd:
    """
    A class implementing the Double-and-Add algorithm for elliptic curve point multiplication
    on the secp256k1 curve.
    Key Concepts of Double-and-Add:

    1. Binary Representation:
    - Scalar k is processed in binary form
    - Each bit determines operation sequence
    - Works from right to left (least to most significant bit)
    2. Core Operations:
    - Point Doubling (DOUBLE):
        - Calculates 2P for point P
        - Uses tangent line at P
    - Point Addition (ADD):
        - Adds two different points
        - Uses line through points
    3. Algorithm Flow:
    - Initialize result = 0, addend = P
    - For each bit in k:
        - If bit is 1: result += addend
        - Double addend for next iteration
        - Shift to next bit
    4. Efficiency:
    - Requires log₂(k) doublings
    - Number of additions depends on Hamming weight of k
    - Average: log₂(k)/2 additions
    5. Security Considerations:
    - Vulnerable to timing attacks if not constant-time
    - Should implement additional protections for private key operations
    - Regular double-and-add provides better timing resistance
    """

    def __init__(self):
        """
        Initialize the DoubleAndAdd object with secp256k1 curve parameters.

        Sets the following attributes:
        - p: The prime field modulus
        - a: The 'a' coefficient of the curve equation (y^2 = x^3 + ax + b)
        - b: The 'b' coefficient of the curve equation
        - G: The generator point (base point) of the curve

        Returns:
        None
        """
        # secp256k1 parameters
        self.p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        self.a = 0
        self.b = 7
        self.G = (
            0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
            0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        )

    def point_double(self, P: tuple) -> tuple | None:
        """Double a point P: Calculate P + P"""
        if P is None:
            return None

        x, y = P
        if y == 0:
            return None

        # Calculate slope (λ) = (3x²) / (2y)
        # For secp256k1, a=0 so we omit it from numerator
        numerator = (3 * x * x) % self.p
        denominator = (2 * y) % self.p
        slope = (numerator * pow(denominator, -1, self.p)) % self.p

        # New x = λ² - 2x
        x3 = (slope * slope - 2 * x) % self.p

        # New y = λ(x - x3) - y
        y3 = (slope * (x - x3) - y) % self.p

        return (x3, y3)

    def point_add(self, P: tuple, Q: tuple) -> tuple | None:
        """Add two different points P and Q"""
        if P is None:
            return Q
        if Q is None:
            return P
        if P == Q:
            return self.point_double(P)

        x1, y1 = P
        x2, y2 = Q

        if x1 == x2:
            return None  # Points are inverses of each other

        # Calculate slope (λ) = (y2 - y1) / (x2 - x1)
        numerator = (y2 - y1) % self.p
        denominator = (x2 - x1) % self.p
        slope = (numerator * pow(denominator, -1, self.p)) % self.p

        # New x = λ² - x1 - x2
        x3 = (slope * slope - x1 - x2) % self.p

        # New y = λ(x1 - x3) - y1
        y3 = (slope * (x1 - x3) - y1) % self.p

        return (x3, y3)

    def double_and_add(self, k: int, P: tuple = None) -> tuple | None:
        """
        Calculate k * P using double-and-add algorithm
        If P is None, uses generator point G
        """
        if P is None:
            P = self.G

        if k == 0:
            return None
        if k == 1:
            return P
        if k < 0:
            k = -k
            P = (P[0], (-P[1]) % self.p)

        # Convert k to binary and process each bit
        result = None
        addend = P

        while k:
            if k & 1:  # If current bit is 1
                result = self.point_add(result, addend)
            addend = self.point_double(addend)  # Double for next bit
            k >>= 1  # Move to next bit

        return result

    def demonstrate_multiplication(self, k: int):
        """Demonstrate steps of double-and-add algorithm"""
        print(f"Calculating {k} * G")
        print(f"Binary representation of {k}: {bin(k)[2:]}")

        result = None
        addend = self.G
        original_k = k
        step = 1

        while k:
            print(f"\nStep {step}:")
            if k & 1:
                prev_result = result
                result = self.point_add(result, addend)
                print(f"Bit is 1: Adding current value")
                print(f"Result updated: {result}")
            else:
                print(f"Bit is 0: Skipping addition")

            prev_addend = addend
            addend = self.point_double(addend)
            print(f"Doubled value for next step")

            k >>= 1
            step += 1

        return result


def verify_multiplication():
    """Verify double-and-add results with test cases"""
    da = DoubleAndAdd()

    # Test case 1: Small scalar
    k1 = 3
    result1 = da.demonstrate_multiplication(k1)
    print(f"\nResult of {k1} * G:")
    print(f"x: {hex(result1[0])}")
    print(f"y: {hex(result1[1])}")

    # Test case 2: Powers of 2
    k2 = 4  # 2²
    result2 = da.demonstrate_multiplication(k2)
    print(f"\nResult of {k2} * G:")
    print(f"x: {hex(result2[0])}")
    print(f"y: {hex(result2[1])}")

    # Test case 3: Private key-sized number (truncated for demonstration)
    k3 = 0x123456789
    result3 = da.double_and_add(k3)
    print(f"\nResult of {hex(k3)} * G:")
    print(f"x: {hex(result3[0])}")
    print(f"y: {hex(result3[1])}")


if __name__ == "__main__":
    verify_multiplication()