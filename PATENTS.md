# Patents

hiyoriOS, the owner of this repository, makes the Kaze specification available under the [Open Web Foundation Final Specification Agreement (OWFa 1.0)](https://openwebfoundation.org/the-agreements/the-owf-1-0-agreements-granted-claims/owfa-1-0) (Patent and Copyright Grants).

## What it covers

- **The specification:** [`spec/kaze.md`](spec/kaze.md) and the JSON Schemas in [`spec/schema/`](spec/schema/), in the version named in the header of `spec/kaze.md`. A later revision is covered when its header carries the same line.
- **Who may rely on it:** anyone who implements the specification, including an independent implementation that uses none of this code. OWFa 1.0 sets the exact terms, including the conditions under which the promise ends. Read it, because this file only summarises it.
- **What it grants:** a patent non-assert and a commitment to license on reasonable and non-discriminatory terms, for hiyoriOS's claims that an implementation of the required parts of the specification necessarily infringes. It also grants a copyright license to the specification text.

## How it relates to the code's license

The code in this repository (the `kzp` crate and `kzp.wasm`), and everything else in it, is licensed under [Apache-2.0](LICENSE). Apache-2.0 §3 grants patent rights for that code only, to those who use it. It gives nothing to someone who writes their own implementation of the specification. OWFa 1.0 does, and it applies in addition to Apache-2.0.
