# dice-to-bip39

Generate a standard 12-word BIP39 mnemonic from physical dice entropy without trusting a hardware wallet's random-number generator or assuming that ordinary dice are perfectly balanced.

This project combines two deliberately small pieces:

1. A pen-and-paper, von Neumann-style debiasing procedure adapted from the [Codex32 dice worksheet](https://secretcodex32.com/docs/2022-09-26--color.pdf). Five differently colored six-sided dice produce one character from the Bech32 alphabet at a time.
2. Two independently written, easily audited programs that convert 26 such characters into 128 bits of entropy and then into a standard 12-word BIP39 mnemonic.

The Python and Rust implementations should produce identical entropy and identical words. Neither program generates randomness.

## Why this exists

The [2026 COLDCARD seed-generation vulnerability](https://blog.coinkite.com/coldcard-mk3-seed-generation-warning/) was a vivid demonstration that a hardware wallet can be excellent at protecting a stored key while still failing at the earlier job of creating one with enough entropy. [Block's technical analysis](https://engineering.block.xyz/blog/predictable-rng-fallback-and-32-bit-reseed-in-coldcard-firmware) describes how firmware behavior made affected seeds much more predictable than intended.

Physical dice let the owner supply the randomness. Some hardware wallets already accept dice rolls, but their usual procedure is different from this project. For example, COLDCARD documents calculating the entropy as [SHA-256 of the dice faces written as an ASCII string](https://coldcard.com/docs/verifying-dice-roll-math/) and counts each D6 roll as `log2(6)` bits of entropy. That entropy count assumes that all six faces are equally likely.

Hashing can make an output look uniformly distributed, but it cannot create unpredictability that was absent from its input. If a die is biased, the roll sequence contains less entropy than the fair-die calculation claims. This project instead removes stable per-die bias before the data reaches a computer. SHA-256 is used only where BIP39 requires it: to calculate the four checksum bits appended to the already-complete 128 bits of entropy. The entropy itself is not replaced by a hash.

Writing 128 individual zeroes and ones by hand would invite transcription and counting errors. The [Bech32 character set](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) is a convenient compact notation: each character represents five bits and the alphabet omits several visually ambiguous characters. Twenty-six characters can therefore carry the required 128 bits, with two surplus bits at the end.

## Important terminology

The 26-character input is **not a Bech32 or Codex32 string**. It has no `ms1` prefix, metadata, secret sharing, or Codex32 checksum. This project only borrows the Bech32 alphabet and the debiasing idea used by Codex32.

The output is a **12-word BIP39 mnemonic**. When a wallet restores those words, BIP39 derives a 512-bit seed from the mnemonic and an optional passphrase. In everyday wallet conversation both are often called a "seed," but they are different values.

## What you need

- Five ordinary six-sided dice, each a different color
- Five movable markers whose colors match the dice; labeled scraps of paper work
- A printed copy of the two-page D6 worksheet
- A pen and a private place to work
- An offline computer on which to run and cross-check both programs

![Five differently colored D6 dice with five matching markers](five-colored-dice-and-markers.png)

The dice do not need to have perfectly equal face probabilities. The procedure does assume that successive rolls are independent, that each die's bias stays reasonably stable between the two rolls being compared, and that the dice are rolled in a way that does not intentionally control or correlate the outcomes.

## Printable D6-only debiasing worksheet

**[Download the printable D6 worksheet](d6-debiasing-worksheet.pdf).** It is formatted as two landscape US Letter pages intended to be placed side by side:

- Page 1 provides five generously spaced marker tracks and separate `L` and `H` landing pads for the dice after the second roll.
- Page 2 provides a large Codex32-style decision tree and the line of 26 character boxes. For each die, follow `L` when the second roll is lower than the first and `H` when it is higher. The five choices lead directly to a character; the user never needs to write or translate binary.

Choose a permanent order for the five die colors and assign them to Die 1 through Die 5. For each character, place the five matching markers according to the first roll. Roll again, compare each die with its marker, and place the die on its `L` or `H` pad. If a die matches its marker, discard that pair and reroll that die twice; keep the other four accepted comparisons. Follow Die 1 through Die 5 on the character tree, record the result on page 2, and repeat.

The tree uses uppercase characters because they are easier to distinguish when handwritten. Both programs accept uppercase or lowercase input.

### Why the comparison is unbiased

Suppose one die lands on face `i` with probability `p_i` and face `j` with probability `p_j`. The ordered pair `(i, j)` has probability `p_i * p_j`; the reversed pair `(j, i)` has exactly the same probability. Once ties are discarded, "second roll lower" and "second roll higher" are therefore equally likely even when the individual faces are not. Each accepted comparison supplies one unbiased bit.

### Why there are 26 characters

Each character represents five L/H choices. The first 25 characters contribute all five choices, and the 26th contributes its first three choices. The converter ignores the final two excess choices. Generate the 26th character normally; do not restrict or reroll it. Discarding its last two choices does not bias the three choices that remain.

## Security precautions

The 26 characters and the resulting mnemonic are both wallet secrets. Anyone who obtains either can reproduce the wallet (unless a separate BIP39 passphrase is also required).

Use these programs on a computer that is offline and free of malware—ideally a disposable live operating system that will not retain shell history, swap, logs, or printed output. The programs receive the secret as a command-line argument, which ordinary shells may preserve in history and may briefly expose to other local processes. Do not enter real wallet entropy on a normal networked computer merely to try the software.

The 26-character notation has no checksum of its own. BIP39's four checksum bits are calculated *after* the characters are entered, so they cannot detect an earlier transcription mistake in the character string. Run both implementations independently and compare the displayed entropy hex and all twelve words. After importing the mnemonic, confirm that receive addresses displayed by the companion wallet match those displayed on the hardware wallet itself before depositing funds. Preserve the final BIP39 mnemonic as the authoritative hardware-wallet backup.

## Python usage

The Python implementation uses only the standard library. Python 3.9 or newer is required because the source uses built-in generic type annotations such as `list[str]`.

```console
python dice_characters_to_bip39.py <26-character-input> english.txt
```

For the all-zero test vector, Bech32 character `q` represents `00000`, so 26 `q` characters encode 128 zero bits after the final two bits are discarded:

```console
python dice_characters_to_bip39.py qqqqqqqqqqqqqqqqqqqqqqqqqq english.txt
```

Expected result:

```text
Input characters:   qqqqqqqqqqqqqqqqqqqqqqqqqq
Entropy hex:    00000000000000000000000000000000
BIP39 mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

On Windows, `py` may be used instead of `python`.

## Rust usage

The Rust implementation is a single source file with no Cargo dependencies. It includes its own compact SHA-256 implementation so it can be compiled directly with `rustc`.

Compile it:

```console
rustc -O dice_characters_to_bip39.rs
```

Run the same all-zero test on Linux or macOS:

```console
./dice_characters_to_bip39 qqqqqqqqqqqqqqqqqqqqqqqqqq english.txt
```

Or on Windows:

```console
.\dice_characters_to_bip39.exe qqqqqqqqqqqqqqqqqqqqqqqqqq english.txt
```

The Rust output must contain the same zero entropy and the same twelve-word mnemonic shown above.

## Recommended verification workflow

Before using real entropy:

1. Read the short custom conversion logic in both programs.
2. Run the all-zero test vector above.
3. Try several nontrivial test strings and require the Python and Rust programs to agree exactly.
4. If possible, verify the entropy-to-mnemonic conversion with a third, established BIP39 implementation used offline.

For a real wallet:

1. Generate and carefully transcribe 26 debiased characters in private.
2. Run both programs in separate offline environments or, preferably, on independently prepared machines.
3. Require identical entropy hex and identical BIP39 mnemonics.
4. Import the mnemonic into the hardware wallet. Before sending funds, test that the backup can reproduce the same wallet—ideally on a spare device—and confirm that receive addresses displayed by the companion wallet match those displayed on the hardware wallet itself.
5. Securely destroy temporary character worksheets and electronic traces once the recovery backup has been tested and preserved.

The included `english.txt` is the official [BIP39 English word list](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt). Both programs verify its canonical SHA-256 hash and refuse to continue if any word or its position has changed. The conversion follows the [BIP39 specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki): SHA-256 supplies a four-bit checksum for 128-bit entropy, producing 132 bits that divide into twelve 11-bit word indices.

## Scope

This project intentionally produces only 12-word English BIP39 mnemonics from 128 bits of user-generated entropy. It does not generate 24-word mnemonics, derive wallet addresses or private keys, implement Codex32 checksums or secret sharing, or store secrets.

See [LICENSE](LICENSE) for the project's license.
