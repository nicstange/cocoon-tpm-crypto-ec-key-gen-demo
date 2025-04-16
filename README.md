# `cocoon-tpm-crypto-ec-key-gen-demo`

Demo for generating a ECC key with the
[`cocoon-tpm-crypto`](https://github.com/nicstange/cocoon-tpm) crate.

## Usage:
```

# cargo run -r

```

Note that you'll likely encounter spurious `RngFailure` errors. These
are due to improper x86 `rdseed` error handling in the example
code. Simply retry then.
