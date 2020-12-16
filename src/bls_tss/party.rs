use crate::bls_tss::Error;
use curv::cryptographic_primitives::hashing::hash_sha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::pairing::pairing_bls12_381::PairingBls;
use curv::cryptographic_primitives::pairing::traits::PAIRING;
use curv::cryptographic_primitives::proofs::sigma_ec_ddh;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::{
    ShamirSecretSharing, VerifiableSS,
};
use curv::elliptic::curves::bls12_381::g1;
use curv::elliptic::curves::bls12_381::g2;
use curv::elliptic::curves::traits::ECPoint;
use curv::elliptic::curves::traits::ECScalar;
use curv::BigInt;
use serde::export::fmt::Debug;

type GE1 = g1::GE;
type FE1 = g1::FE;
type GE2 = g2::GE;
pub(crate) type FE2 = g1::FE;

#[derive(Debug)]
pub struct Parameters {
    pub threshold: usize,   //t
    pub share_count: usize, //n
}

#[derive(Clone, Debug, Serialize)]
pub struct Party{
    pub index: usize,
    a_i0: FE1,
    qual_parties: Vec<usize>,
    shares: Vec<FE1>,
    shares_prime: Vec<FE1>,
    pub commitments_a: Vec<GE1>,
    commitments_b: Vec<GE1>,
}

#[derive(Clone, Debug, Serialize)]
pub struct VerificationKeys {
    pub vk_vec: Vec<GE1>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SharesSkOfParty {
    pub sk_ij: Vec<FE1>,
    party_index: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct KeyGenMessagePhase1 {
    C_ik: Vec<GE1>,
    share: FE1,
    share_prime: FE1,
    pub index: usize,
}

#[derive(Clone, Debug, Serialize, Copy)]
pub struct KeyGenBroadcastMessagePhase2<'a> {
    pub A_ik_vec: &'a Vec<GE1>,
    pub B_i0: GE2,
    pub index: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct Keys {
    sk: FE1,
    vk: GE1,
    rk: FE1,
    pub(crate) QUAL: Vec<usize>, //vector of qualified sender, i.e., senders who sent valid commitments that passed eq(4)
    party_index: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct SharedKeys {
    pub public_key: GE2,
    pub verification_keys: Vec<GE1>,
}

#[derive(Clone)]
pub struct PartialSignatureProverOutput {
    pub party_index: usize,
    sig_i: GE1,
    proof: sigma_ec_ddh::ECDDHProof<GE1>,
}

use std::fmt;

impl fmt::Debug for PartialSignatureProverOutput
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("PartialSignatureProverOutput")
            .field("party_index", &self.party_index)
            .field("sig_i", &self.sig_i)
            .field("proof", &self.proof)
            .finish()
    }
}

impl KeyGenMessagePhase1 {
    pub fn output_shares(&self) -> (FE1, FE1) {
        (self.share, self.share_prime)
    }
}

pub fn phase_1_validate_commitments(
    received_msg_comm: KeyGenMessagePhase1,
) -> Result<(), Error> {
    let commitment = received_msg_comm.C_ik;
    let shares_j = received_msg_comm.share;
    let shares_j_prime = received_msg_comm.share_prime;
    let index = received_msg_comm.index;
    let g = GE1::generator();
    let h = GE1::base_point2();
    //computing g^s_ij*h^s'_ij
    let s_ij = shares_j;
    let s_ij_prime = shares_j_prime;
    let commitment_from_eval: GE1 = g * s_ij + h * s_ij_prime;
    let mut commitment_iter = commitment.iter();
    let head = commitment_iter.next().unwrap();
    let commitment_from_comms = commitment_iter.enumerate().fold(*head, |acc, (j, &comm)| {
        let exp =
            <FE1 as ECScalar>::from(&BigInt::from((index + 1) as i32).pow((j + 1) as u32));
        acc + comm * exp
    });
    assert_eq!(commitment_from_eval, commitment_from_comms);
    if commitment_from_eval == commitment_from_comms {
        Ok(())
    } else {
        Err(Error::InvalidSS_phase1)
    }
}

//keygen_generating_phase_validate_and_combine_shares function validates eq(4) and combine the secret key shares from the other parties
pub fn keygen_generating_phase_validate_and_combine_shares(
    received_msg_phase_1: &Vec<KeyGenMessagePhase1>,
) -> (Keys, SharesSkOfParty) {
    let party_index = received_msg_phase_1[0].index;

    let QUAL: Vec<usize> = received_msg_phase_1
        .iter()
        .filter(|&rec_msg| phase_1_validate_commitments(rec_msg.clone()).is_ok())
        .enumerate()
        .map(|(index_valid, _)| index_valid)
        .collect();

    let (sk_vec, vk_vec): (Vec<FE1>, Vec<FE1>) = received_msg_phase_1
        .iter()
        .enumerate()
        .filter(|(index_valid, _)| QUAL.iter().any(|&i| i == *index_valid))
        .map(|(_, valid_msg)| valid_msg.output_shares())
        .unzip();

    (
        Keys::combine_key_shares_from_qualified(sk_vec.clone(), vk_vec, party_index, QUAL),
        SharesSkOfParty {
            sk_ij: sk_vec.clone(),
            party_index,
        },
    )
}

pub fn create_list_of_blames(blame_from_i: Vec<Vec<bool>>, t: usize) -> Vec<usize> {
    let trans_vec: Vec<Vec<bool>> = (0..blame_from_i[0].len())
        .map(|j| {
            (0..blame_from_i.len())
                .map(|i| blame_from_i[i][j])
                .collect()
        })
        .collect();
    let count_false: Vec<usize> = trans_vec
        .iter()
        .map(|v| v.iter().filter(|&i| !*i).count())
        .collect();
    let blame_greater_than_t: Vec<usize> = count_false
        .iter()
        .enumerate()
        .filter(|&(_index, i)| i > &t)
        .map(|(_index, _)| _index)
        .collect();
    println!("transformed vec {:?}", trans_vec);
    println!("count_false {:?}", count_false);
    println!("greater_than_t {:?}", blame_greater_than_t);
    blame_greater_than_t
}

impl Party {
    pub fn phase_1_commit(index: usize, params: &Parameters) -> Self
     {
        let t = params.threshold;
        let l = params.share_count;
        let a_i0: FE1 = FE1::new_random();

        let G = GE1::generator();
        let (vss_a, shares) = VerifiableSS::share_given_generator(t, l, &a_i0, G);
        let commitments_a: Vec<GE1>= vss_a.commitments;
        let H = GE1::base_point2();
        let (vss_b, shares_prime) =
            VerifiableSS::share_given_generator(t, l, &FE1::new_random(), H);
        let commitments_b: Vec<GE1>= vss_b.commitments;
        Self {
            a_i0,
            index,
            qual_parties: vec![],
            shares,
            shares_prime,
            commitments_a,
            commitments_b,
        }
    }

    pub fn phase_1_broadcast_commitment(&self, index: usize) -> KeyGenMessagePhase1 {
        //assert_ne!(self.index,index);
        let C_ik = self
            .commitments_a
            .iter()
            .zip(self.commitments_b.iter())
            .map(|(&comm_a, &comm_b)| comm_a + comm_b)
            .collect();
        KeyGenMessagePhase1 {
            C_ik,
            share: self.shares[index],
            share_prime: self.shares_prime[index],
            index,
        }
    }

    pub fn phase_2_broadcast_commitment(&self) -> KeyGenBroadcastMessagePhase2 {
        let g2: GE2 = GE2::generator();
        let a_i0: &FE2 = &<FE2 as ECScalar>::from(&self.a_i0.to_big_int()); //converting a_i0 from P to T (i.e., from group G1 to group G2)
        let B_i0 = g2.scalar_mul(&a_i0.get_element());
        let index = self.index;
        KeyGenBroadcastMessagePhase2 {
            A_ik_vec: &self.commitments_a,
            B_i0,
            index,
        }
    }
}

pub fn keygen_extracting_phase_validate_and_compute_PK_and_verification_keys(
    party_receiver_index: usize,
    received_broadcast: Vec<KeyGenBroadcastMessagePhase2>,
    sk_shares: Vec<SharesSkOfParty>,
    QUAL: Vec<usize>,
    params: &Parameters,
) -> SharedKeys {
    let valid_broadcasts: Vec<KeyGenBroadcastMessagePhase2> = received_broadcast
        .iter()
        .filter(|&bc_from_sender| {
            //	if bc_from_sender.index in QUAL  - continue this
            let s_ij = sk_shares[party_receiver_index].sk_ij[bc_from_sender.index];
            validate_i_commitment_phase_2(party_receiver_index, &bc_from_sender, s_ij).is_ok() //passes eq(4) tests
				&& QUAL.iter().any(|&index| index == bc_from_sender.index) //passes eq(5) test
        })
        .map(|&e| e)
        .collect();
    let pk_vec = valid_broadcasts
        .iter()
        .map(|bc_from_sender| bc_from_sender.B_i0)
        .collect();
    let pk = compute_public_key(pk_vec);
    let vk_vec = compute_verification_keys(valid_broadcasts, &params);
    SharedKeys {
        public_key: pk,
        verification_keys: vk_vec,
    }
}

pub fn validate_i_commitment_phase_2(
    party_receiver_index: usize,
    msg_2: &KeyGenBroadcastMessagePhase2,
    s_ij: FE1,
) -> Result<(), Error> {
    let commitment_i = msg_2.A_ik_vec;
    let B_i0 = msg_2.B_i0;
    let mut commitment_iter = commitment_i.iter();
    let head = commitment_iter.next().unwrap();
    let A_ik_prod = commitment_iter.enumerate().fold(*head, |acc, (k, &A_ik)| {
        let exp = <FE1 as ECScalar>::from(
            &BigInt::from((party_receiver_index + 1) as i32).pow((k + 1) as u32),
        );
        acc + A_ik * exp
    });

    let g1 = &GE1::generator();
    let check_A_ik_commitments = A_ik_prod == g1 * &s_ij;
    let A_i0 = commitment_i[0];
    let g2 = &GE2::generator();
    let check_ai0_secret =
        PairingBls::compute_pairing(&A_i0, &g2) == PairingBls::compute_pairing(&g1, &B_i0);

    if check_A_ik_commitments && check_ai0_secret {
        Ok(())
    } else {
        Err(Error::InvalidSS_Phase2)
    }
}

pub fn compute_public_key(B_i0_vec: Vec<GE2>) -> GE2 {
    let mut B_i0_iter = B_i0_vec.iter();
    let head = B_i0_iter.next().unwrap();
    B_i0_iter.fold(*head, |acc, B_i0| acc + B_i0)
}

pub fn compute_verification_keys(
    bc_vec: Vec<KeyGenBroadcastMessagePhase2>,
    params: &Parameters,
) -> Vec<GE1> {
    let v_vec: Vec<GE1> = (0..params.threshold + 1)
        .map(|i| {
            let mut bc_vec_iter = bc_vec.iter();
            let A_i0 = bc_vec_iter.next().unwrap().A_ik_vec;
            bc_vec_iter.fold(A_i0[i], |acc, bc_party| acc + bc_party.A_ik_vec[i])
        })
        .collect();

    let vk_vec: Vec<GE1> = bc_vec
        .iter()
        .map(|bc_party| {
            let mut v_vec_iter = v_vec.iter();
            let head = v_vec_iter.next().unwrap();
            v_vec_iter.enumerate().fold(*head, |acc, (j, &vk_base)| {
                let exp = <FE1 as ECScalar>::from(
                    &BigInt::from((bc_party.index + 1) as i32).pow((j + 1) as u32),
                );
                acc + vk_base * exp
            })
        })
        .collect();
    vk_vec
}

impl Keys {
    pub fn createKeys(
        sk: FE1,
        vk: GE1,
        rk: FE1,
        party_index: usize,
        QUAL: Vec<usize>,
    ) -> Self {
        Self {
            sk,
            vk,
            rk,
            party_index,
            QUAL,
        }
    }

    pub fn combine_key_shares_from_qualified(
        sk_qualified: Vec<FE1>,
        sk_prime_qualified: Vec<FE1>,
        party_index: usize,
        QUAL: Vec<usize>,
    ) -> Keys {
        let sk = sk_qualified
            .into_iter()
            .fold(FE1::zero(), |acc, e| acc + e);
        let vk = GE1::generator() * sk;
        let rk = sk_prime_qualified
            .iter()
            .fold(FE1::zero(), |acc, &e| acc + e);
        Keys::createKeys(sk, vk, rk, party_index, QUAL)
    }
}

pub fn hash_to_curve_with_auxillary(message: &BigInt, auxillary: &BigInt) -> GE1
{
    let hashed = hash_sha256::HSha256::create_hash(&[message, auxillary]);
    let hashed_scalar = <FE1 as ECScalar>::from(&hashed);
    GE1::generator().scalar_mul(&hashed_scalar.get_element())
}

pub fn hash_1(message: &[u8]) -> GE1 {
    let message_bn = &BigInt::from(message);
    hash_to_curve_with_auxillary(&message_bn, &BigInt::from(3))
}

pub fn hash_to_curve(message: &BigInt) -> GE1

{
    let hashed = hash_sha256::HSha256::create_hash(&[message]);
    let hashed_scalar = <FE1 as ECScalar>::from(&hashed);
    GE1::generator().scalar_mul(&hashed_scalar.get_element())
}

impl Keys
{
    pub fn get_vk(&self) -> GE1 {
        self.vk
    }

    pub fn generate_random_key(index: usize) -> Self {
        let sk = FE1::new_random();
        let vk = GE1::generator() * sk;
        let rk = FE1::new_random();
        let QUAL = vec![];
        Keys {
            sk,
            vk,
            rk,
            party_index: index,
            QUAL,
        }
    }

    pub fn partial_eval(&self, message: &[u8]) -> PartialSignatureProverOutput {
        let message_bn = &BigInt::from(message);
        let hashed_msg: GE1 = hash_to_curve_with_auxillary(&message_bn, &BigInt::from(3));
        //let hashed_msg: GE1 = self::hash_to_curve(&message_bn, &self.vk.bytes_compressed_to_big_int());
        let x = &self.sk;
        let sig_i = hashed_msg.scalar_mul(&x.get_element());
        let w = sigma_ec_ddh::ECDDHWitness {
            x: ECScalar::from(&x.to_big_int()),
        };
        let g = GE1::generator();
        let vk = self.vk;
        let delta = sigma_ec_ddh::ECDDHStatement {
            g1: g,
            h1: vk,
            g2: hashed_msg,
            h2: sig_i,
        };
        let proof = sigma_ec_ddh::ECDDHProof::prove(&w, &delta);
        assert!(proof.verify(&delta).is_ok());

        PartialSignatureProverOutput {
            party_index: self.party_index,
            sig_i,
            proof,
        }
    }

    pub fn partial_eval_non_valid(&self, message: &[u8]) -> PartialSignatureProverOutput {
        let message_bn = &BigInt::from(message);
        let hashed_msg: GE1 = hash_to_curve_with_auxillary(&message_bn, &BigInt::from(3));
        //let hashed_msg: GE1 = self::hash_to_curve(&message_bn, &self.vk.bytes_compressed_to_big_int());
        let x = FE1::new_random();
        let sig_i = hashed_msg.scalar_mul(&x.get_element());
        let w = sigma_ec_ddh::ECDDHWitness {
            x: ECScalar::from(&x.to_big_int()),
        };
        let g = GE1::generator();
        let vk = g * FE1::new_random();
        let delta = sigma_ec_ddh::ECDDHStatement {
            g1: g,
            h1: vk,
            g2: hashed_msg,
            h2: sig_i,
        };
        let proof = sigma_ec_ddh::ECDDHProof::prove(&w, &delta);

        PartialSignatureProverOutput {
            party_index: self.party_index,
            sig_i,
            proof,
        }
    }
}

pub fn verify_partial_sig(
    message: &[u8],
    vk: GE1,
    prover_output: &PartialSignatureProverOutput,
) -> Result<(), Error>
{
    let message_bn = &BigInt::from(message);
    let hashed_msg: GE1 = hash_to_curve_with_auxillary(&message_bn, &BigInt::from(3));
    let g = GE1::generator();
    let delta = sigma_ec_ddh::ECDDHStatement {
        g1: g,
        h1: vk,
        g2: hashed_msg,
        h2: prover_output.sig_i,
    };
    let valid = &prover_output.proof.verify(&delta);
    if valid.is_ok() {
        Ok(())
    } else {
        Err(Error::InvalidPartialSig)
    }
}

pub fn valid_signers(
    message: &[u8],
    vk_vec: Vec<GE1>,
    prover_output_vec: Vec<PartialSignatureProverOutput>,
) -> (Vec<usize>, Vec<GE1>) {
    let valid_signers = prover_output_vec
        .iter()
        .filter(|&prover_output| {
            verify_partial_sig(message, vk_vec[prover_output.party_index], prover_output).is_ok()
        })
        .map(|prover_output| (prover_output.party_index, prover_output.sig_i))
        .unzip();
    valid_signers
}

pub fn combine_sig_shares_to_sig(
    params: &Parameters,
    indices: Vec<usize>,
    sig_shares: Vec<GE1>,
) -> GE1 {
    assert_eq!(indices.len(), sig_shares.len());
    let valid_verifiers = (indices, sig_shares);
    let indices = valid_verifiers.0;
    let sig_i_vec = valid_verifiers.1;
    let vss_scheme: VerifiableSS<GE1> = VerifiableSS {
        parameters: ShamirSecretSharing {
            threshold: params.threshold,
            share_count: params.share_count,
        },
        commitments: vec![],
    };
    let shares: Vec<GE1> = indices
        .iter()
        .zip(&sig_i_vec)
        .map(|(&i, &sig_i)| {
            let lagrange_coeff_i = vss_scheme.map_share_to_new_params(i, &indices.as_slice());
            sig_i * lagrange_coeff_i
        })
        .collect();
    let mut shares_iter = shares.iter();
    let head: &GE1 = shares_iter.next().unwrap();
    let sig: GE1 = shares_iter.fold(*head, |acc, share_i| acc + share_i);
    sig
}

pub fn combine(
    params: &Parameters,
    message: &[u8],
    vk_vec: Vec<GE1>,
    provers_output_vec: Vec<PartialSignatureProverOutput>,
) -> GE1 {
    assert_eq!(provers_output_vec.len(), params.share_count as usize);
    let (indices, sig_shares) = valid_signers(message, vk_vec, provers_output_vec);
    combine_sig_shares_to_sig(params, indices, sig_shares)
}

pub fn verify(pk: GE2, message: &[u8], sig: GE1) -> bool {
    let g2 = GE2::generator();
    PairingBls::compute_pairing(&sig, &g2) == PairingBls::compute_pairing(&hash_1(message), &pk)
}
