Elliptic curves applications

1. BitcoinKeys class
2. DoubleAndAdd - A class implementing the Double-and-Add algorithm for elliptic curve point multiplication
3. MontgomeryLadder - Montgomery ladder algorithm for elliptic curve point multiplication
4. KeyDerivationMath - Math explanation of key derivations


How to extend the BitcoinKeys class to handle different Bitcoin address formats and their relationships:

Key relationships between address formats:

1. Legacy Addresses (P2PKH):
- Start with '1'
- Uses full public key hash
- Direct hash of public key
- Less efficient script
- Most compatible but highest transaction fees
- Script: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG

2. Nested SegWit addresses (P2SH-P2WPKH):
- Start with '3'
- Wrapped witness program
- Backward compatible wrapped SegWit
- Lower fees than legacy
- Two-layer structure:
  * Outer: P2SH script
  * Inner: Witness program
- Script: OP_HASH160 <scriptHash> OP_EQUAL

3. Native SegWit Addresses (bech32) (P2WPKH):
- Start with 'bc1' (mainnet) or 'tb1' (testnet)
- Most efficient format
- Lowest transaction fees
- Direct witness program
- Not compatible with older wallets
- Script: Witness version + Witness program

4. Taproot (P2TR):
- X-only public keys
- Schnorr signatures
- Advanced script capabilities

Key Differences:
1. Transaction Size:
- Legacy: Largest
- SegWit: Medium
- Native SegWit: Smallest

2. Fee Structure:
- Legacy: Highest fees
- SegWit: Lower fees
- Native SegWit: Lowest fees

3. Script Complexity:
- Legacy: Simple script
- SegWit: Wrapped script
- Native SegWit: Direct witness program

4. Compatibility:
- Legacy: Universal
- SegWit: High
- Native SegWit: Modern wallets only

The main technical innovation of SegWit addresses is separating the transaction signature (witness) from the transaction data, which:
1. Fixes transaction malleability
2. Reduces transaction size
3. Enables more advanced scripting capabilities
4. Provides upgrade path for future improvements

The differences between P2WPKH and P2SH-P2WPKH scripts.
Adapt the code to support BIP49 (P2SH-P2WPKH) derivation paths?

Future developments:
https://github.com/sipa/bech32/blob/master/ref/python/segwit_addr.py#L134
https://github.com/sipa/bech32/tree/master/ref/python
https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#user-content-Examples

### Media Wiki
https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki. 
https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#user-content-Witness_program. 
https://medium.com/@lorenzoprotocol/what-is-segregated-witness-segwit-and-how-does-it-work-c890116f8c20. 

The witness version (witver) is defined in BIP-141 (SegWit) and BIP-173 (Bech32 address format). Here are the key references:

BIP-141 (SegWit): https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
BIP-173 (Bech32): https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
BIP-350 (Bech32m): https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki