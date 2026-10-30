# Security policy

SuriComAI is a development build. There is no live network, no wallet, no payment and no token, and nothing here should hold real secrets or real funds. See the [README](README.md) for what is and is not built.

## Report a vulnerability

Please report privately. Do not open a public issue for a security problem.

Use GitHub's private reporting: open the **Security** tab of this repository and choose **Report a vulnerability**. If that is not available, contact the owner through [github.com/suraj-chavda](https://github.com/suraj-chavda) and ask for a private channel before sending details.

Please include what you found, how to reproduce it, and which commit you tested.

## What to expect

- An acknowledgement, then a fix or a written reason it is not one.
- Credit in the fix, if you want it.
- There is no bug bounty yet.

## Scope

In scope: the Rust crates, the desktop app, the proof verifiers and the build workflows in this repository.

Out of scope: the escrow contract's economics (it is unverified and unaudited reference code), anything that needs the `lab` stand-ins to be treated as hardware evidence, and social engineering.

Reporting does not grant permission to use the software. The [license](LICENSE) still applies.
