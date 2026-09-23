# Local additions on branch `thesis-harness`

This checkout is upstream [ait-crypto/faest-rs](https://github.com/ait-crypto/faest-rs) plus a
small test-only harness for a Java Card port of FAEST-EM-128f. Upstream library behaviour is
unchanged.

**Branch `main` is kept pristine.** All local work lives on `thesis-harness`, so upstream updates
are a `git checkout main && git pull` followed by a rebase.

## What was added

| file | lines | what |
|---|---|---|
| `src/faest_dump.rs` | ~350 | the signature tracer, `#[cfg(all(test, feature = "std"))]` |
| `src/faest.rs` | +4 | the `mod dump;` declaration that pulls it in |
| `tests/data/dump/trace_faest_em_128f.json` | generated | its output, committed |

Nothing is reachable from a non-test build: the module is `#[cfg(test)]` and no library code
calls into it.

## The tracer

`cargo test --lib dump_trace -- --nocapture`

It regenerates `(sk, msg, rho)` from record 0 of `reduced_PQCsignKAT_faest_em_128f.rsp` — driving
the NIST DRBG exactly as `tests/nist.rs` does, keygen first and then the 16 `rho` bytes — signs,
and writes every intermediate to `tests/data/dump/trace_faest_em_128f.json` as hex.

Output: `FAEST_TRACE_OUT=<path>` overrides the destination.

22 recorded fields, in computation order (the file's `order` array):

```
mu, r, iv_pre, iv, witness, hcom, u, c[15], v[128], chall1, u_tilde, d, chall2,
a0_tilde, a1_tilde, a2_tilde, chall3, ctr, i_delta[16], decom_i_coms[16],
decom_i_nodes[107], decom_i
```

`a0_tilde` is the reason a trace is needed at all rather than just the KAT: it is hashed into
`chall3` and never transmitted, so nothing in the signature reveals whether it was computed
correctly.

### Why it is in `src/` and not `examples/`

Every crypto module in `src/lib.rs` is private (`mod bavc`, `mod vole`, `mod prover`, ...), and so
is `faest::sign`. An `examples/` or `tests/` binary is an external consumer of the crate and can
only see the finished signature. A tracer has to be compiled as part of the crate, which is why
this is a `#[cfg(test)]` module rather than a standalone binary.

### Drift, and what guards against it

`sign_traced` is a **copy** of `faest::sign` with recording interleaved; the `// ::N` step comments
are kept aligned so `git diff` between the two functions stays readable. A copy can silently fall
behind the original.

What catches that: the test asserts the traced signature equals the KAT's own `sm` byte for byte.
If the copy drifts, or a parameter changes, or the portable path stops agreeing with the SIMD path,
the test fails. If it ever does fail after an upstream merge, diff `sign_traced` against `sign`
before looking anywhere else.

## Provenance

Upstream is Apache-2.0 OR MIT; these additions carry the same terms. The test vectors and `.rsp`
files in `tests/data/` are upstream's, except `tests/data/dump/`, which is generated here.
