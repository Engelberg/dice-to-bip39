#!/usr/bin/env python3
"""
Convert 26 manually generated Bech32-alphabet characters into a
12-word BIP39 mnemonic.

The input is NOT a full Bech32 string:

    - no human-readable prefix
    - no separator
    - no checksum

It is simply 26 base-32 characters generated using the Bech32 character set.

Characters 1 through 25 contribute 5 bits each: 125 bits.
Character 26 contributes its 3 most significant bits.
Its 2 least significant bits are deliberately discarded.

Total: 125 + 3 = 128 bits of BIP39 entropy.
"""

import hashlib
import sys
from pathlib import Path


BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def decode_entropy(text: str) -> bytes:
    """Decode 26 Bech32-alphabet characters into exactly 128 bits."""
    text = text.strip().lower()

    if len(text) != 26:
        raise ValueError(
            f"Expected exactly 26 characters, but received {len(text)}."
        )

    invalid = [character for character in text
               if character not in BECH32_ALPHABET]

    if invalid:
        raise ValueError(
            f"Invalid character: {invalid[0]!r}. "
            "Only Bech32-alphabet characters are allowed."
        )

    # Convert every character to its corresponding five-bit number.
    values = [BECH32_ALPHABET.index(character) for character in text]

    entropy = 0

    # First 25 characters contribute all five bits.
    for value in values[:25]:
        entropy = (entropy << 5) | value

    # The final character contributes only its three most significant bits.
    #
    # A value from 0 through 31 has binary form abcde.
    # Shifting right by two leaves abc.
    final_three_bits = values[25] >> 2
    entropy = (entropy << 3) | final_three_bits

    return entropy.to_bytes(16, byteorder="big")


def load_wordlist(filename: str) -> list[str]:
    """Load a standard 2048-word BIP39 wordlist."""
    words = Path(filename).read_text(encoding="utf-8").splitlines()
    words = [word.strip() for word in words if word.strip()]

    if len(words) != 2048:
        raise ValueError(
            f"Expected 2048 BIP39 words, but found {len(words)}."
        )

    if len(set(words)) != 2048:
        raise ValueError("The wordlist contains duplicate words.")

    return words


def entropy_to_mnemonic(
    entropy: bytes,
    wordlist: list[str],
) -> str:
    """Convert 128 bits of entropy into a 12-word BIP39 mnemonic."""
    if len(entropy) != 16:
        raise ValueError("BIP39 entropy must be exactly 16 bytes.")

    # For 128-bit entropy, BIP39 appends the first four bits
    # of SHA256(entropy).
    checksum = hashlib.sha256(entropy).digest()[0] >> 4

    # Append the four-bit checksum, producing 132 total bits.
    combined = (int.from_bytes(entropy, "big") << 4) | checksum

    words = []

    # Split the 132 bits into twelve groups of eleven bits.
    for position in range(12):
        shift = 11 * (11 - position)
        index = (combined >> shift) & 0x7FF
        words.append(wordlist[index])

    return " ".join(words)


def main() -> None:
    if len(sys.argv) != 3:
        program = Path(sys.argv[0]).name
        raise SystemExit(
            f"Usage: {program} <26-character entropy> <bip39-wordlist>\n"
            f"Example: {program} qqqqqqqqqqqqqqqqqqqqqqqqqq english.txt"
        )

    encoded_entropy = sys.argv[1]
    wordlist_filename = sys.argv[2]

    entropy = decode_entropy(encoded_entropy)
    wordlist = load_wordlist(wordlist_filename)
    mnemonic = entropy_to_mnemonic(entropy, wordlist)

    print("Input characters:  ", encoded_entropy.lower())
    print("Entropy hex:   ", entropy.hex())
    print("BIP39 mnemonic:", mnemonic)


if __name__ == "__main__":
    try:
        main()
    except (OSError, UnicodeError, ValueError) as error:
        raise SystemExit(f"Error: {error}")
