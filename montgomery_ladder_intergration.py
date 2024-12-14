from dataclasses import dataclass
from typing import Optional, Tuple, Union
import hashlib


@dataclass
class CurveParameters:
    """Base class for curve parameters"""
    name: str
    field_p: int
    order_n: int

    def __post_init__(self):
        self.field_bits = (self.field_p).bit_length()


class WeierstrassCurve(CurveParameters):
    """Y² = X³ + aX + b"""

    def __init__(self, name: str, p: int, a: int, b: int, n: int, G: Tuple[int, int]):
        super().__init__(name, p, n)
        self.a = a
        self.b = b
        self.G = G


class EdwardsCurve(CurveParameters):
    """x² + y² = 1 + dx²y²"""

    def __init__(self, name: str, p: int, d: int, n: int, G: Tuple[int, int]):
        super().__init__(name, p, n)
        self.d = d
        self.G = G


class TwistedEdwardsCurve(CurveParameters):
    """ax² + y² = 1 + dx²y²"""

    def __init__(self, name: str, p: int, a: int, d: int, n: int, G: Tuple[int, int]):
        super().__init__(name, p, n)
        self.a = a
        self.d = d
        self.G = G


class MontgomeryCurveMultiplication:
    def __init__(self, curve: Union[WeierstrassCurve, EdwardsCurve, TwistedEdwardsCurve]):
        self.curve = curve

    def montgomery_ladder(self, k: int, P: Optional[Tuple[int, int]] = None) -> Tuple[int, int]:
        """Generic Montgomery ladder implementation"""
        if P is None:
            P = self.curve.G

        if k == 0:
            return None
        if k < 0:
            k = -k
            P = self.negate_point(P)

        R0 = None
        R1 = P

        for bit in bin(k)[2:]:  # Remove '0b' prefix
            if bit == '0':
                R1, R0 = self.curve_specific_add_double(R1, R0, P)
            else:
                R0, R1 = self.curve_specific_add_double(R0, R1, P)

        return R0

    def curve_specific_add_double(self, P1, P2, P):
        """Select appropriate addition formulas based on curve type"""
        if isinstance(self.curve, WeierstrassCurve):
            return self.weierstrass_add_double(P1, P2, P)
        elif isinstance(self.curve, EdwardsCurve):
            return self.edwards_add_double(P1, P2, P)
        elif isinstance(self.curve, TwistedEdwardsCurve):
            return self.twisted_edwards_add_double(P1, P2, P)
        else:
            raise ValueError("Unsupported curve type")

    def weierstrass_add_double(self, P1, P2, P):
        """Addition and doubling for Weierstrass curves"""
        if P1 is None:
            return (P2, self.weierstrass_double(P2))
        if P2 is None:
            return (P1, self.weierstrass_double(P1))

        x1, y1 = P1
        x2, y2 = P2

        # Addition
        if x1 == x2:
            if y1 == y2:
                m = ((3 * x1 * x1 + self.curve.a) *
                     pow(2 * y1, -1, self.curve.field_p)) % self.curve.field_p
            else:
                return None, None
        else:
            m = ((y2 - y1) * pow(x2 - x1, -1, self.curve.field_p)) % self.curve.field_p

        x3 = (m * m - x1 - x2) % self.curve.field_p
        y3 = (m * (x1 - x3) - y1) % self.curve.field_p

        # Doubling P2
        x4, y4 = self.weierstrass_double(P2)

        return (x3, y3), (x4, y4)

    def edwards_add_double(self, P1, P2, P):
        """Addition and doubling for Edwards curves"""
        if P1 is None:
            return (P2, self.edwards_double(P2))
        if P2 is None:
            return (P1, self.edwards_double(P1))

        x1, y1 = P1
        x2, y2 = P2

        # Addition
        x1y2 = (x1 * y2) % self.curve.field_p
        y1x2 = (y1 * x2) % self.curve.field_p
        dx1x2y1y2 = (self.curve.d * x1y2 * y1x2) % self.curve.field_p

        x3 = ((x1y2 + y1x2) * pow(1 + dx1x2y1y2, -1, self.curve.field_p)) % self.curve.field_p
        y3 = ((y1 * y2 - x1 * x2) * pow(1 - dx1x2y1y2, -1, self.curve.field_p)) % self.curve.field_p

        # Doubling P2
        x4, y4 = self.edwards_double(P2)

        return (x3, y3), (x4, y4)

    def twisted_edwards_add_double(self, P1, P2, P):
        """Addition and doubling for Twisted Edwards curves"""
        if P1 is None:
            return (P2, self.twisted_edwards_double(P2))
        if P2 is None:
            return (P1, self.twisted_edwards_double(P1))

        x1, y1 = P1
        x2, y2 = P2

        # Addition
        x1y2 = (x1 * y2) % self.curve.field_p
        y1x2 = (y1 * x2) % self.curve.field_p
        dx1x2y1y2 = (self.curve.d * x1y2 * y1x2) % self.curve.field_p

        x3 = ((x1y2 + y1x2) * pow(1 + dx1x2y1y2, -1, self.curve.field_p)) % self.curve.field_p
        y3 = ((y1 * y2 + self.curve.a * x1 * x2) *
              pow(1 - dx1x2y1y2, -1, self.curve.field_p)) % self.curve.field_p

        # Doubling P2
        x4, y4 = self.twisted_edwards_double(P2)

        return (x3, y3), (x4, y4)

    def weierstrass_double(self, P):
        """Point doubling for Weierstrass curves"""
        if P is None:
            return None

        x, y = P
        if y == 0:
            return None

        m = ((3 * x * x + self.curve.a) * pow(2 * y, -1, self.curve.field_p)) % self.curve.field_p
        x3 = (m * m - 2 * x) % self.curve.field_p
        y3 = (m * (x - x3) - y) % self.curve.field_p

        return (x3, y3)

    def edwards_double(self, P):
        """Point doubling for Edwards curves"""
        if P is None:
            return None

        x, y = P
        x2 = (x * x) % self.curve.field_p
        y2 = (y * y) % self.curve.field_p

        x3 = ((2 * x * y) * pow(1 + self.curve.d * x2 * y2, -1, self.curve.field_p)) % self.curve.field_p
        y3 = ((y2 - x2) * pow(1 - self.curve.d * x2 * y2, -1, self.curve.field_p)) % self.curve.field_p

        return (x3, y3)

    def twisted_edwards_double(self, P):
        """Point doubling for Twisted Edwards curves"""
        if P is None:
            return None

        x, y = P
        x2 = (x * x) % self.curve.field_p
        y2 = (y * y) % self.curve.field_p

        x3 = ((2 * x * y) * pow(self.curve.a * x2 + y2, -1, self.curve.field_p)) % self.curve.field_p
        y3 = ((y2 - self.curve.a * x2) *
              pow(2 - self.curve.a * x2 - y2, -1, self.curve.field_p)) % self.curve.field_p

        return (x3, y3)

    def negate_point(self, P):
        """Point negation specific to curve type"""
        if P is None:
            return None

        x, y = P
        if isinstance(self.curve, WeierstrassCurve):
            return (x, (-y) % self.curve.field_p)
        elif isinstance(self.curve, (EdwardsCurve, TwistedEdwardsCurve)):
            return ((-x) % self.curve.field_p, y)


def demonstrate_curves():
    # Define example curves
    secp256k1 = WeierstrassCurve(
        name="secp256k1",
        p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
        a=0,
        b=7,
        n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
        G=(
            0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
            0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        )
    )

    # Ed25519 parameters
    ed25519 = EdwardsCurve(
        name="Ed25519",
        p=2 ** 255 - 19,
        d=-121665 * pow(121666, -1, 2 ** 255 - 19),
        n=2 ** 252 + 27742317777372353535851937790883648493,
        G=(
            15112221349535400772501151409588531511454012693041857206046113283949847762202,
            46316835694926478169428394003475163141307993866256225615783033603165251855960
        )
    )

    # Example multiplication on each curve
    k = 0x1234

    for curve in [secp256k1, ed25519]:
        print(f"\nTesting {curve.name}:")
        mult = MontgomeryCurveMultiplication(curve)
        result = mult.montgomery_ladder(k)
        print(f"k * G = ({hex(result[0])}, {hex(result[1])})")


if __name__ == "__main__":
    demonstrate_curves()