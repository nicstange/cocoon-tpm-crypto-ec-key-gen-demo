// In no_std crates, add:
// extern crate alloc;
// use alloc::vec::Vec;

use cocoon_tpm_crypto::{
    ecc,
    rng::{self, RngCore as _},
    CryptoError, EmptyCryptoIoSlices,
};
use cocoon_tpm_tpm2_interface as tpm2_interface;
use cocoon_tpm_utils_common::{
    alloc::try_alloc_zeroizing_vec,
    io_slices::{self, IoSlicesIterCommon as _},
};

// For the pure rust cocoon-tpm-crypto backend, instantiate a NIST Hash DRBG seeded from x86 rdseed.
// Don't inline for stack usage analysis purposes.
#[cfg(not(feature = "boringssl"))]
#[inline(never)]
fn instantiate_rng() -> Result<rng::HashDrbg, CryptoError> {
    // Error here if rdseed is unsupported.
    let mut rdseed_rng = rng::X86RdSeedRng::instantiate().map_err(|_| CryptoError::RngFailure)?;
    let hash_drbg_entropy_len =
        rng::HashDrbg::min_seed_entropy_len(tpm2_interface::TpmiAlgHash::Sha256);
    let mut hash_drbg_entropy = try_alloc_zeroizing_vec(hash_drbg_entropy_len)?;
    rdseed_rng.generate::<_, EmptyCryptoIoSlices>(
        io_slices::SingletonIoSliceMut::new(hash_drbg_entropy.as_mut_slice()).map_infallible_err(),
        None,
    )?;
    rng::HashDrbg::instantiate(
        tpm2_interface::TpmiAlgHash::Sha256,
        &hash_drbg_entropy,
        None, // Nonce. Could be some id unique to the VM instance.
        Some(b"SVSM primary rng"),
    )
}

// For the BoringSSL cocoon-tpm-crypto backend, instantiate a BsslRandBytesRng, forwarding the
// request to OPENSSL_rand_bytes().  Don't inline for stack usage analysis purposes.
#[cfg(feature = "boringssl")]
#[inline(never)]
fn instantiate_rng() -> Result<rng::BsslRandBytesRng, CryptoError> {
    Ok(rng::BsslRandBytesRng::new())
}

// Generate an ECC key and return a pair of (public, private) key.
// Don't inline for stack usage analysis purposes.
#[inline(never)]
fn gen_ecc_key(
    curve_id: tpm2_interface::TpmEccCurve,
    rng: &mut dyn rng::RngCoreDispatchable,
    additional_rng_generate_input: Option<&[Option<&[u8]>]>,
) -> Result<
    (
        tpm2_interface::TpmsEccPoint<'static>,
        tpm2_interface::Tpm2bEccParameter<'static>,
    ),
    CryptoError,
> {
    // 1.) Get the curve. This is cheap.
    let curve = ecc::curve::Curve::new(curve_id)?;

    // 2.) Get a CurveOps instance. This precomputes some stuff, but nothing dramatic (it brings the
    // two curve coefficients into Montgomery form and stores that internally). It does memory
    // allocations though: three buffers of length suitable for scalars in the curve's field. That
    // is, three buffers of length 72 each at worst.
    let curve_ops = curve.curve_ops()?;

    // 3.) This is the heavy operation.
    let ecc_key = ecc::EccKey::generate(&curve_ops, rng, additional_rng_generate_input)?;

    // 4.) Unpeel.
    let (pub_key, priv_key) = ecc_key.into_tpms(&curve_ops)?;
    // The priv_key is always there after a generate operation, of course.
    let priv_key = priv_key.ok_or(CryptoError::Internal)?;
    Ok((pub_key, priv_key))
}

// No proper error handling, use unwrap() everywhere for demo purposes.
fn main() {
    // First step: instantiate a RNG. In the long run the SVSM would probably maintain a single
    // global instance that could possible seed secondary RNGs.
    let mut rng = instantiate_rng().unwrap();

    // Second step: generate an ECC key.
    let (pub_key, priv_key) =
        gen_ecc_key(tpm2_interface::TpmEccCurve::NistP521, &mut rng, None).unwrap();

    // Get raw Vecs. These are nops, as all buffers are owned already.
    let tpm2_interface::TpmsEccPoint {
        x: pub_key_x,
        y: pub_key_y,
    } = pub_key;
    let pub_key_x = pub_key_x.buffer.into_owned().unwrap();
    let pub_key_y = pub_key_y.buffer.into_owned().unwrap();
    let priv_key = priv_key.buffer.into_owned().unwrap();

    // Third step: dump.
    print!(
        "\
pub.x = {}
pub.y = {}
priv  = {}
",
        cmpa::hexstr::bytes_to_hexstr(&pub_key_x).unwrap(),
        cmpa::hexstr::bytes_to_hexstr(&pub_key_y).unwrap(),
        cmpa::hexstr::bytes_to_hexstr(&priv_key).unwrap()
    );
}
