//! Test-only signature tracer: emits every intermediate value of one FAEST-EM-128f
//! signature as JSON, for the Java Card implementation to diff against.
//!
//! # Why this exists
//!
//! The NIST KAT is a single pass/fail over 5060 bytes produced by eleven modules. When it
//! fails it says *that* something is wrong, never *where*. This harness fixes one
//! `(sk, msg, rho)` and writes down each intermediate, so the Java side can compare field
//! by field and stop at the first divergence — one module instead of eleven.
//!
//! # Why it lives inside the crate
//!
//! Every crypto module in `lib.rs` is private (`mod bavc`, `mod vole`, ...). An
//! `examples/` or `tests/` binary is an external consumer and sees only `sign`'s finished
//! output, so a tracer has to be compiled as part of the crate.
//!
//! # Why the inputs come from the KAT
//!
//! `(sk, msg, rho)` are not invented here: they are regenerated from record 0 of
//! `reduced_PQCsignKAT_faest_em_128f.rsp` by re-running the NIST DRBG exactly as
//! `tests/nist.rs` does. The trace therefore ends at the KAT's own signature, and
//! `dump_trace_faest_em_128f` asserts precisely that. One artefact serves both the
//! per-field debugging and the end-to-end gate.
//!
//! # Drift
//!
//! `sign_traced` is a copy of `super::sign` with recording interleaved; the `// ::N` step
//! comments are kept aligned so the two can be diffed. A copy can drift from the
//! original — the final assertion against the KAT signature is what catches it. If that
//! assertion fails after an upstream update, re-diff the two functions first.
//!
//! Run with:
//!
//! ```text
//! cargo test --lib dump_trace -- --nocapture
//! ```

use std::{env, fs, io::BufRead, path::PathBuf};

use nist_pqc_seeded_rng::NistPqcAes256CtrRng;
use rand_core::{Rng, SeedableRng};
use serde_json::{Map, Value, json};

use super::*;
use crate::{ByteEncoding, declassify, parameter::FAESTEM128fParameters};

/// Which KAT record the trace is built from.
const KAT_FILE: &str = "reduced_PQCsignKAT_faest_em_128f.rsp";

/// Where the trace is written, relative to the crate root, unless `FAEST_TRACE_OUT` says
/// otherwise.
const DEFAULT_OUT: &str = "tests/data/dump/trace_faest_em_128f.json";

// ---------------------------------------------------------------------------------------
// Trace recording
// ---------------------------------------------------------------------------------------

/// Recorded intermediates, keyed by name and kept in computation order.
///
/// `order` is emitted alongside the values so a consumer can walk the fields in the order
/// the signer produced them and report the *first* mismatch, which is the one that
/// localises the bug. Later mismatches are usually downstream noise.
struct Trace {
    order: Vec<Value>,
    values: Map<String, Value>,
}

impl Trace {
    fn new() -> Self {
        Self {
            order: Vec::new(),
            values: Map::new(),
        }
    }

    fn put(&mut self, name: &str, value: Value) {
        assert!(
            self.values.insert(name.to_owned(), value).is_none(),
            "field recorded twice: {name}"
        );
        self.order.push(Value::String(name.to_owned()));
    }

    fn put_bytes(&mut self, name: &str, bytes: &[u8]) {
        self.put(name, Value::String(hex::encode(bytes)));
    }

    /// A collection of equal-purpose byte strings (matrix rows, opening nodes), each hex.
    fn put_rows<'a>(&mut self, name: &str, rows: impl Iterator<Item = &'a [u8]>) {
        self.put(
            name,
            Value::Array(
                rows.map(|row| Value::String(hex::encode(row)))
                    .collect::<Vec<_>>(),
            ),
        );
    }
}

// ---------------------------------------------------------------------------------------
// The traced signer — a copy of `super::sign`, step comments aligned
// ---------------------------------------------------------------------------------------

fn sign_traced<P, O>(
    msg: &[u8],
    sk: &SecretKey<O>,
    witness: &Witness<O>,
    rho: &[u8],
    signature: &mut [u8],
    trace: &mut Trace,
) -> Result<(), Error>
where
    P: FAESTParameters<OWF = O>,
    O: OWFParameters,
{
    // ::0
    let mut signature = SignatureRefMut::<P, O>::from(signature);

    // ::3
    let mut mu = Array::<u8, O::LambdaBytesTimes2>::default();
    RO::<P>::hash_mu(&mut mu, &sk.pk.owf_input, &sk.pk.owf_output, msg);
    trace.put_bytes("mu", mu.as_slice());

    // ::4
    let mut r = Array::<u8, O::LambdaBytes>::default();
    let iv_pre: &mut IV = signature.iv_pre.try_into().map_err(|_| Error::new())?;
    RO::<P>::hash_r_iv(&mut r, iv_pre, &sk.owf_key, &mu, rho);

    // ::5
    let mut iv = iv_pre.to_owned();
    trace.put_bytes("r", r.as_slice());
    trace.put_bytes("iv_pre", iv.as_slice());
    RO::<P>::hash_iv(&mut iv);
    trace.put_bytes("iv", iv.as_slice());

    // ::12 — computed by the caller; recorded here so the witness sits in step order
    trace.put_bytes("witness", witness.as_slice());

    // ::7
    let VoleCommitResult { com, decom, u, v } =
        volecommit::<P::BAVC, O::LHatBytes>(VoleCommitmentCRefMut::new(signature.cs), &r, &iv);
    trace.put_bytes("hcom", com.as_slice());
    trace.put_bytes("u", u.as_slice());
    trace.put_rows("c", signature.cs.chunks(O::LHatBytes::USIZE));
    trace.put_rows("v", v.iter().map(|row| row.as_slice()));

    // ::8
    // Contrarly to specification, faest-ref uses iv instead of iv_pre
    let mut chall1 = Array::default();
    RO::<P>::hash_challenge_1(&mut chall1, &mu, &com, signature.cs, iv.as_slice());
    trace.put_bytes("chall1", chall1.as_slice());

    // ::10
    // hash u and write the result (i.e., u_tilde) into signature
    O::BaseParams::hash_u_vector(signature.u_tilde, &u, &chall1);
    trace.put_bytes("u_tilde", signature.u_tilde);

    // ::11
    // hash v row by row and update h2_hasher with the row hashes
    let mut h2_hasher = RO::<P>::hash_challenge_2_init(chall1.as_slice(), signature.u_tilde);
    O::BaseParams::hash_v_matrix(&mut h2_hasher, v.as_slice(), &chall1);

    // ::13
    // compute and write masked witness 'd' in signature
    signature.mask_witness(witness, &u[..<O as OWFParameters>::LBytes::USIZE]);
    trace.put_bytes("d", signature.d);

    // ::14
    let mut chall2 = Array::default();
    RO::<P>::hash_challenge_2_finalize(h2_hasher, &mut chall2, signature.d);
    trace.put_bytes("chall2", chall2.as_slice());

    // ::18
    let (a0_tilde, a1_tilde, a2_tilde) = P::OWF::prove(
        witness,
        // ::16
        &u[O::LBytes::USIZE..O::LBytes::USIZE + O::LambdaBytesTimes2::USIZE]
            .try_into()
            .map_err(|_| Error::new())?,
        &v,
        &sk.pk,
        &chall2,
    );

    // a0_tilde is hashed into chall3 but never transmitted, so a trace is the only place
    // it can be compared against — which is a large part of why this file exists.
    trace.put_bytes("a0_tilde", a0_tilde.as_bytes().as_slice());

    // Save a1_tilde, a2_tilde in signature
    signature.save_zk_constraints(&a1_tilde.as_bytes(), &a2_tilde.as_bytes());
    trace.put_bytes("a1_tilde", signature.a1_tilde);
    trace.put_bytes("a2_tilde", signature.a2_tilde);

    // ::19
    let hasher = RO::<P>::hash_challenge_3_init(
        &chall2,
        &a0_tilde.as_bytes(),
        signature.a1_tilde,
        signature.a2_tilde,
    );

    for ctr in 0u32.. {
        // ::20
        RO::<P>::hash_challenge_3_finalize(&hasher, signature.chall3, ctr);
        // declassify chall_3 which is put into the signature
        declassify!(signature.chall3);
        // ::21
        if check_challenge_3::<P, O>(signature.chall3) {
            // ::24
            let i_delta = decode_all_chall_3::<P::Tau>(signature.chall3);

            // ::26
            if let Some(decom_i) = <P as FAESTParameters>::BAVC::open(&decom, &i_delta) {
                trace.put_bytes("chall3", signature.chall3);
                trace.put("ctr", json!(ctr));
                trace.put(
                    "i_delta",
                    Value::Array(i_delta.iter().map(|i| json!(*i)).collect::<Vec<_>>()),
                );
                trace.put_rows("decom_i_coms", decom_i.coms.iter().copied());
                trace.put_rows("decom_i_nodes", decom_i.nodes.iter().copied());

                // Save decom_i and ctr bits
                signature.save_decom_and_ctr(&decom_i, ctr);
                trace.put_bytes("decom_i", signature.decom_i);
                return Ok(());
            }
        }
    }

    Err(Error::new())
}

// ---------------------------------------------------------------------------------------
// KAT record 0
// ---------------------------------------------------------------------------------------

#[derive(Default)]
struct KatRecord {
    seed: Vec<u8>,
    msg: Vec<u8>,
    pk: Vec<u8>,
    sk: Vec<u8>,
    sm: Vec<u8>,
}

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data")
}

/// Read the first record of a `.rsp` file. Modelled on `tests/nist.rs`, which is the
/// authority on this format.
fn read_first_kat(name: &str) -> KatRecord {
    let path = data_dir().join(name);
    let file = fs::File::open(&path).unwrap_or_else(|e| panic!("open {}: {e}", path.display()));

    let mut kat = KatRecord::default();
    let mut mlen = 0usize;
    let mut smlen = 0usize;

    for line in std::io::BufReader::new(file).lines() {
        let line = line.expect("read line");
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (kind, value) = line.split_once(" = ").expect("kind = value");
        match kind {
            "count" => assert_eq!(value, "0", "expected record 0 first in {name}"),
            "mlen" => mlen = value.parse().unwrap(),
            "smlen" => smlen = value.parse().unwrap(),
            "seed" => kat.seed = hex::decode(value).expect("hex seed"),
            "sk" => kat.sk = hex::decode(value).expect("hex sk"),
            "pk" => kat.pk = hex::decode(value).expect("hex pk"),
            "msg" => {
                kat.msg = hex::decode(value).expect("hex msg");
                assert_eq!(kat.msg.len(), mlen);
            }
            "sm" => {
                kat.sm = hex::decode(value).expect("hex sm");
                assert_eq!(kat.sm.len(), smlen);
                return kat;
            }
            _ => unreachable!("unknown kind: {kind}"),
        }
    }
    panic!("no complete record in {name}");
}

// ---------------------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------------------

#[test]
fn dump_trace_faest_em_128f() {
    type P = FAESTEM128fParameters;
    type O = <P as FAESTParameters>::OWF;

    let kat = read_first_kat(KAT_FILE);

    // Same DRBG, same order of draws as tests/nist.rs: keygen first, then rho.
    let mut rng =
        NistPqcAes256CtrRng::from_seed(kat.seed.as_slice().try_into().expect("48-byte KAT seed"));

    let sk = faest_keygen::<O, _>(&mut rng);
    let pk = sk.as_public_key();
    assert_eq!(
        hex::encode(sk.to_vec()),
        hex::encode(&kat.sk),
        "regenerated secret key differs from the KAT — the DRBG or keygen changed"
    );
    assert_eq!(
        hex::encode(pk.to_vec()),
        hex::encode(&kat.pk),
        "regenerated public key differs from the KAT"
    );

    // lib.rs::sample_rho — lambda bytes, drawn after keygen.
    let mut rho = Array::<u8, <O as OWFParameters>::LambdaBytes>::default();
    rng.fill_bytes(&mut rho);

    // ::12
    let witness = <O as OWFParameters>::witness(&sk);

    let mut signature = vec![0u8; <P as FAESTParameters>::SIGNATURE_SIZE];
    let mut trace = Trace::new();
    sign_traced::<P, O>(&kat.msg, &sk, &witness, &rho, &mut signature, &mut trace).expect("sign");

    // The gate. If the traced copy has drifted from `sign`, or the parameter set is not
    // the one this KAT file holds, this is where it shows up.
    let expected = &kat.sm[kat.sm.len() - signature.len()..];
    assert_eq!(
        hex::encode(&signature),
        hex::encode(expected),
        "traced signature does not match the KAT"
    );

    let document = json!({
        "parameter_set": "faest_em_128f",
        "generated_by": "faest-rs src/faest_dump.rs (thesis-harness branch)",
        "source": {
            "file": KAT_FILE,
            "count": 0,
        },
        "sizes": {
            "lambda_bytes": <O as OWFParameters>::LambdaBytes::USIZE,
            "l_bytes": <O as OWFParameters>::LBytes::USIZE,
            "l_hat_bytes": <O as OWFParameters>::LHatBytes::USIZE,
            "tau": <<P as FAESTParameters>::Tau as TauParameters>::Tau::USIZE,
            "decom_size": <P as FAESTParameters>::get_decom_size(),
            "signature_size": <P as FAESTParameters>::SIGNATURE_SIZE,
        },
        "inputs": {
            "seed": hex::encode(&kat.seed),
            "msg": hex::encode(&kat.msg),
            "sk": hex::encode(&kat.sk),
            "pk": hex::encode(&kat.pk),
            "rho": hex::encode(rho.as_slice()),
        },
        "order": Value::Array(trace.order.clone()),
        "trace": Value::Object(trace.values.clone()),
        "signature": hex::encode(&signature),
    });

    let out = match env::var("FAEST_TRACE_OUT") {
        Ok(path) => PathBuf::from(path),
        Err(_) => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DEFAULT_OUT),
    };
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent).expect("create output directory");
    }
    fs::write(
        &out,
        serde_json::to_string_pretty(&document).expect("serialize trace"),
    )
    .unwrap_or_else(|e| panic!("write {}: {e}", out.display()));

    println!("wrote {} fields to {}", trace.order.len(), out.display());
}
