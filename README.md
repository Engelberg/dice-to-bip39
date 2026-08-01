# dice-to-bip39

## An easily auditable method for converting dice rolls to a BIP39 mnemonic using the Bech32 character set

Objective: Generate a standard 12-word BIP39 mnemonic from physical dice entropy without trusting a hardware wallet's random-number generator or assuming that ordinary dice are perfectly balanced.

This project combines two deliberately small pieces:

1. A pen-and-paper, von Neumann-style debiasing procedure adapted from the [Codex32 dice worksheet](https://secretcodex32.com/docs/2022-09-26--color.pdf). Five distinguishable dice produce one character from the Bech32 alphabet at a time.
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

- Either five distinguishable D6 dice, or one each of D6, D8, D10, D12, and D20
- Five movable markers that fit inside the selected worksheet's tracks; coins or bingo chips suit the D6 sheet, while the compact polyhedral tracks need markers about 1/2 inch (12 mm) or smaller, such as beads, small buttons, or folded paper tabs
- A printed copy of the corresponding two-page worksheet
- A pen and a private place to work
- An offline computer on which to run and cross-check both programs

![One possible setup: five differently colored D6 dice with five matching markers](five-colored-dice-and-markers.png)

The photograph shows matching markers because they are visually convenient, but matching is optional. The worksheet row identifies the die, so the five markers need not match the dice or one another.

The dice do not need to have perfectly equal face probabilities. The procedure does assume that successive rolls are independent, that each die's bias stays reasonably stable between the two rolls being compared, and that the dice are rolled in a way that does not intentionally control or correlate the outcomes.

## Printable debiasing worksheets

Choose whichever option matches the dice you have. Both worksheets are formatted as two landscape US Letter pages intended to be placed side by side, and both produce exactly the same kind of 26-character input.

### Option 1: five distinguishable D6 dice

**[Download the five-D6 worksheet](d6-debiasing-worksheet.pdf).** The dice must be distinguishable so each die can be compared with its own earlier roll. Different colors are convenient; assign them permanently to Die 1 through Die 5 using the lines on page 1.

### Option 2: D6, D8, D10, D12, and D20

**[Download the polyhedral-dice worksheet](polyhedral-debiasing-worksheet.pdf).** The shapes distinguish the dice, so the worksheet uses the fixed order D6, D8, D10, D12, then D20. Treat `0` on the D10 as 10. The D20 track wraps into two rows to keep the marker spaces large enough to use.

For either worksheet:

- Page 1 provides one marker track per die and separate `L` and `H` landing pads for the dice after the second roll.
- Page 2 provides a large Codex32-style decision tree and the line of 26 character boxes. For each die, follow `L` when the second roll is lower than the first and `H` when it is higher. The five choices lead directly to a character; the user never needs to write or translate binary.

For each character, roll all five dice and place one marker on each row according to that die's first value. Roll again, compare each die with the marker on its row, and place the die on either the `L` or `H` space depending on whether its second value is lower or higher. If the values match, reroll that die twice, move its marker to the first reroll, and compare the second reroll; keep the other four accepted comparisons. Follow the five dice in worksheet order on the character tree, record the result on page 2, and repeat.

The tree uses uppercase characters because they are easier to distinguish when handwritten. Both programs accept uppercase or lowercase input.

### Why the comparison is unbiased

Suppose one die lands on face `i` with probability `p_i` and face `j` with probability `p_j`. The ordered pair `(i, j)` has probability `p_i * p_j`; the reversed pair `(j, i)` has exactly the same probability. Once ties are discarded, "second roll lower" and "second roll higher" are therefore equally likely even when the individual faces are not. Each accepted comparison supplies one unbiased bit.

### Why there are 26 characters

Each character represents five L/H choices. The first 25 characters contribute all five choices, and the 26th contributes its first three choices. The converter ignores the final two excess choices. Generate the 26th character normally; do not restrict or reroll it. Discarding its last two choices does not bias the three choices that remain.

## Security precautions

The 26 characters and the resulting mnemonic are both wallet secrets. Anyone who obtains either can reproduce the wallet (unless a separate BIP39 passphrase is also required).

Use these programs on a computer that is offline and free of malware—ideally a disposable live operating system, such as Tails with networking disabled and persistent storage off, that will not retain shell history, swap, logs, or program output after shutdown. The programs receive the secret as a command-line argument, which ordinary shells may preserve in history and may briefly expose to other local processes. Do not enter real wallet entropy on a normal networked computer merely to try the software.

The 26-character notation has no checksum of its own. BIP39's four checksum bits are calculated *after* the characters are entered, so they cannot detect an earlier transcription mistake in the character string. Both the Python and Rust programs are small enough and simple enough in scope that they can be easily audited (ask your AI to verify and test these programs). Use whichever you like, or run both implementations independently and compare the displayed entropy hex and all twelve words. The twelve output words are your BIP39 mnemonic, which can be imported into a BIP39-compatible hardware wallet that accepts 12-word mnemonics. Best practice is to record several receive addresses and then import the mnemonic a second time—either by wiping and restoring the hardware wallet or, preferably, by restoring it on a second hardware wallet—and confirm that the same addresses are reproduced. Preserve the final BIP39 mnemonic as the authoritative hardware-wallet backup.

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
2. Run both programs in separate offline environments.
3. Verify the two programs output identical entropy hex and identical BIP39 mnemonics.
4. Import the mnemonic into the hardware wallet. Before sending funds, test that the backup can reproduce the same wallet—ideally on a spare device—and confirm that receive addresses displayed by the companion wallet match those displayed on the hardware wallet itself.
5. Securely destroy temporary character worksheets and electronic traces once the recovery backup has been tested and preserved.

The included `english.txt` is the official [BIP39 English word list](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt). Both programs verify its canonical SHA-256 hash and refuse to continue if any word or its position has changed. The conversion follows the [BIP39 specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki): SHA-256 supplies a four-bit checksum for 128-bit entropy, producing 132 bits that divide into twelve 11-bit word indices.

## Scope

This project intentionally produces only 12-word English BIP39 mnemonics from 128 bits of user-generated entropy. It does not generate 24-word mnemonics, derive wallet addresses or private keys, implement Codex32 checksums or secret sharing, or store secrets.

See [LICENSE](LICENSE) for the project's license.
