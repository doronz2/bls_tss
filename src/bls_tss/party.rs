use curv::elliptic::curves::bls12_381::g1;
use curv::elliptic::curves::bls12_381::g2;
use curv::BigInt;
use curv::cryptographic_primitives::hashing::hash_sha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::elliptic::curves::traits::ECPoint;
use curv::elliptic::curves::traits::ECScalar;
use serde::export::fmt::Debug;
use curv::cryptographic_primitives::secret_sharing::feldman_vss;
use curv::cryptographic_primitives::pairing::pairing_bls12_381::PairingBls;
use curv::cryptographic_primitives::pairing::traits::PAIRING;
use curv::cryptographic_primitives::proofs::sigma_ec_ddh;
//use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use crate::bls_tss::Error;
use zeroize::{Zeroize, DefaultIsZeroes};


type GE1 = g1::GE;
type FE1 = g1::FE;
type GE2 = g2::GE;
type FE2 = g1::FE;


/*
//step a in creating phase Ni send commitments to Nj
pub fn committing_to_two_polynomials<P:ECPoint>(a_i0: &P::Scalar, l: usize, t: usize)-> (VerifiableSS<P>,Vec<(P,P)>){
	//let shares: Vec<P::Scalar>;
	let (sss, shares) =
		feldman_vss::VerifiableSS::<P>::share(t,l,&a_i0.get_element());
	let commitments_a = sss.commitments;
	let (sss_prime, shares_prime) =
		feldman_vss::VerifiableSS::<P>::share(t,l,&P::Scalar::new_random());
	let commitments_b = sss_prime.commitments;
	let share_pair =  shares.iter().zip(shares_prime).collect();
	let commitment_c = commitments_a.iter().zip(commitments_b.iter()).
		map(|(comm_a_i,comm_b_i)| comm_a_i * comm_b_i).collect();
	(
		VerifiableSS{
			parameters: feldman_vss::ShamirSecretSharing{
				threshold: t,
				share_count: l,
			},
			commitments: commitment_c,
		},
		share_pair
	)
}
*/
//step b in creating phase
/*
pub struct ReceivedCommitment{
	commitment: &Vec<P>,
	shares_j: &[P::Scalar; 2],

}
*/

#[derive(Clone,Debug,Serialize)]
pub struct Party<P: ECPoint>{
	pub index: usize,
	a_i0: P::Scalar,
	qual_parties: Vec<usize>,
	shares: Vec<P::Scalar>,
	shares_prime: Vec<P::Scalar>,
	pub commitments_a: Vec<P>,
	commitments_b: Vec<P>,
}


#[derive(Clone,Debug,Serialize)]
pub struct VerificationKeys<P: ECPoint>{
	pub vk: Vec<P>,
}


#[derive(Clone,Debug,Serialize)]
pub struct KeyGenMessagePhase1<P: ECPoint>{
	C_ik: Vec<P>,
	share: P::Scalar,
	share_prime: P::Scalar,
	pub index: usize
}



#[derive(Clone,Debug,Serialize)]
pub struct KeyGenBroadcastMessagePhase2<'a, P:ECPoint>{
	pub A_ik_vec: &'a Vec<P>,
	B_i0: GE2
}

#[derive(Clone,Debug,Serialize)]
pub struct Keys<P: ECPoint>{
	sk: P::Scalar,
	vk: P,
	rk: P::Scalar,
	party_index: usize
}

#[derive(Clone,Debug)]
pub struct PartyKeys<P:ECPoint> {
	pub Keys: Keys<P>,
	pub sk_ij : Vec<P::Scalar>,
}

//(self.party_index, sig_i, proof)
#[derive(Clone)]
pub struct PartialSignatureProverOutput<P:ECPoint>{
	pub party_index: usize,
	sig_i : P,
	proof: sigma_ec_ddh::ECDDHProof<P>
}

use std::fmt;

impl<P> fmt::Debug for PartialSignatureProverOutput<P>
where
	P: ECPoint + fmt::Debug,
	sigma_ec_ddh::ECDDHProof<P>: fmt::Debug,
{
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("PartialSignatureProverOutput")
			.field("party_index", &self.party_index)
			.field("sig_i", &self.sig_i)
			.field("proof", &self.proof)
			.finish()
	}
}

impl <P:ECPoint>KeyGenMessagePhase1<P>{
	pub fn output_shares(&self)->(P::Scalar,P::Scalar){
		(self.share, self.share_prime)
	}

}

pub fn phase_1_validate_commitments<P: ECPoint + Copy + Debug>(received_msg_comm: KeyGenMessagePhase1<P>) -> Result<(), Error> {
	let commitment = received_msg_comm.C_ik;
	let shares_j = received_msg_comm.share;
	let shares_j_prime = received_msg_comm.share_prime;
	let index = received_msg_comm.index;
	let g = P::generator();
	let h = P::base_point2();
	//computing g^s_ij*h^s'_ij
	let s_ij = shares_j;
	let s_ij_prime = shares_j_prime;
	let commitment_from_eval: P = g * s_ij + h * s_ij_prime;
	let mut commitment_iter = commitment.iter();
	let head= commitment_iter.next().unwrap();
	let commitment_from_comms = commitment_iter
		.enumerate()
		.fold(*head, |acc, (j,  &comm)|{
			let exp = <P::Scalar as ECScalar>::from(&BigInt::from((index + 1) as i32).pow((j+1) as u32));
		//	println!("index {}, j {}, exp: {:?}", index,j,exp.to_big_int());
			acc + comm * exp
		});
	assert_eq!(commitment_from_eval,commitment_from_comms);
	if commitment_from_eval == commitment_from_comms{
		Ok(())
	} else {
		Err(Error::InvalidSS_phase1)
	}
}


/*
pub fn invalid_commitments_vec<P:ECPoint + Copy + Debug>
(
	l: u32, commitment: &Vec<Vec<P>>, shares_vec: Vec<(&P::Scalar, &P::Scalar)>
)-> Vec<bool> {
	(0..l as usize).
		map(|i| !phase_1_validate_commitments((KeyGenMessagePhase1{commitment[i].clone(), shares_vec[i], i)).is_ok())
		.collect()
}

 */

pub fn create_list_of_blames(blame_from_i: Vec<Vec<bool>>, t: usize)->Vec<usize> {
	//let vecs = Vec::from([Vec::from([1, 2, 3, 8]), Vec::from([4, 5, 6, 9]), Vec::from([10, 11, 12, 13])]);
	//transpose the rows and the vecs
	//let vecs = Vec::from([Vec::from([true, false, true, false]), Vec::from([true, false, false, false]),Vec::from([true, true, false, false])]);
	let trans_vec: Vec<Vec<bool>> = (0..blame_from_i[0].len()).map(|j| (0..blame_from_i.len()).map(|i| blame_from_i[i][j]).collect()).collect();
	let count_false:Vec<usize> = trans_vec.iter().map(|v| v.iter().filter(|&i| !*i).count()).collect();
	let blame_greater_than_t: Vec<usize> = count_false.iter().enumerate().filter(|&(_index,i)| i>&t).map(|(_index,_)| _index).collect();
	println!("transformed vec {:?}", trans_vec);
	println!("count_false {:?}", count_false);
	println!("greater_than_t {:?}", blame_greater_than_t);
	blame_greater_than_t
}


impl<P: ECPoint + Clone + Debug> Party<P> {

	pub fn phase_1_commit( index: usize,  l: usize, t: usize) -> Self where <P as ECPoint>::Scalar: Clone {
		let a_i0: P::Scalar = P::Scalar::new_random();

		let G = P::generator();
		let (vss_a, shares) =
			feldman_vss::VerifiableSS::share_given_generator(t, l, &a_i0,G);
		let commitments_a: Vec<P> =vss_a.commitments;
		let H = P::base_point2();
		let (vss_b, shares_prime) =
			feldman_vss::VerifiableSS::<P>::share_given_generator(t, l, &P::Scalar::new_random(), H);
		let commitments_b: Vec<P> = vss_b.commitments;
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





	pub fn phase_1_broadcast_commitment(&self, index: usize)-> KeyGenMessagePhase1<P>{
		//assert_ne!(self.index,index);
		let C_ik = self.commitments_a.iter()
			.zip(self.commitments_b.iter())
			.map(|(&comm_a,&comm_b)| comm_a + comm_b)
			.collect();
		//println!(self.shares);
		KeyGenMessagePhase1 {
			C_ik,
			share: self.shares[index],
			share_prime:  self.shares_prime[index],
			index
		}
	}


	pub fn phase_2_broadcast_commitment(&self) -> KeyGenBroadcastMessagePhase2<P> {
		let g2: GE2 = GE2::generator();
		//converting a_i0 from P to T (i.e., from group G1 to group G2)
		let a_i0: &FE2 = &<FE2 as ECScalar>::from(&self.a_i0.to_big_int());
		let B_i0 = g2.scalar_mul(&a_i0.get_element());
		KeyGenBroadcastMessagePhase2{
			A_ik_vec: &self.commitments_a,
			B_i0
		}
	}


	pub fn validate_i_commitment_phase_2(&self,  msg_2: KeyGenBroadcastMessagePhase2<GE1>, s_ij: FE1) -> Result<(),Error>{
		let commitment_i = msg_2.A_ik_vec;
		let B_i0 = msg_2.B_i0;
		let mut commitment_iter = commitment_i.iter();
		let head = commitment_iter.next().unwrap();
		let A_ik_prod = commitment_iter
			.enumerate()
			.fold(*head, |acc, (k,  &A_ik)|{
				let exp =
					<FE1 as ECScalar>::from(&BigInt::from((self.index + 1) as i32).pow((k+1) as u32));
				//	println!("index {}, j {}, exp: {:?}", index,j,exp.to_big_int());
				acc + A_ik * exp
			});

		let g1 = &GE1::generator();
		let check_A_ik_commitments =  A_ik_prod == g1 * &s_ij;
		let A_i0 = commitment_i[0];
		let g2 = &GE2::generator();
		let check_ai0_secret =
			PairingBls::compute_pairing(&A_i0,&g2) == PairingBls::compute_pairing(&g1,&B_i0);

		if check_A_ik_commitments && check_ai0_secret{
			Ok(())
		} else {
			Err(Error::InvalidSS_Phase2)
		}

	}

	pub fn compute_public_key(B_i0_vec: Vec<GE2>) -> GE2{
		let mut B_i0_iter = B_i0_vec.iter();
		let head = B_i0_iter.next().unwrap();
		B_i0_iter.fold(*head, |acc , B_i0| acc + B_i0)
	}
}



/*
pub fn hash_to_curve<P: ECPoint>(message: &BigInt) -> P
	where P: ECPoint + Clone + Debug
{
	let hashed = hash_sha256::HSha256::create_hash(&[message]);
	let hashed_scalar = <P::Scalar as ECScalar>::from(&hashed);
	P::generator().scalar_mul(&hashed_scalar.get_element())
}

impl<P: ECPoint > Party<P>{
	pub fn partial_signature(message: [u8;4], sk_i: &FE1) {
		let message_bn = &BigInt::from(message);
		let hashed_msg: P = hash_to_curve(&message_bn);
		let partial_sig = hashed_msg.scalar_mul(&sk_i.get_element());

	}
}
*/




impl<P:ECPoint + Debug> Keys<P> {
	pub fn createKeys(sk: P::Scalar, vk: P, rk: P::Scalar, party_index: usize) -> Self {
		Self {
			sk,
			vk,
			rk,
			party_index
		}
	}

	pub fn combine_key_shares_from_qualified(sk_qualified: &Vec<P::Scalar>, sk_prime_qualified: Vec<P::Scalar>, party_index: usize) -> Keys<P> {
		let sk = sk_qualified.into_iter().
			fold(P::Scalar::zero(), |acc, &e| acc + e);
		let vk = P::generator() * sk;
		let rk = sk_prime_qualified.iter().
			fold(P::Scalar::zero(), |acc, &e| acc + e);
		Keys::createKeys(sk, vk, rk, party_index)
	}
}

pub fn hash_to_curve_with_auxillary<P:ECPoint>(message: &BigInt, auxillary: &BigInt) -> P
	where P: ECPoint + Clone
{
	let hashed = hash_sha256::HSha256::create_hash(&[message, auxillary]);
	let hashed_scalar = <P::Scalar as ECScalar>::from(&hashed);
	P::generator().scalar_mul(&hashed_scalar.get_element())
}

pub fn hash_to_curve<P:ECPoint>(message: &BigInt) -> P
	where P: ECPoint + Clone
{
	let hashed = hash_sha256::HSha256::create_hash(&[message]);
	let hashed_scalar = <P::Scalar as ECScalar>::from(&hashed);
	P::generator().scalar_mul(&hashed_scalar.get_element())
}


impl<P> Keys<P> where
P:ECPoint,
P::Scalar: Zeroize + Clone
{
	pub fn get_vk(&self) -> P {
		self.vk
	}

	pub fn generate_random_key(index: usize) -> Self {
		let sk = P::Scalar::new_random();
		let vk = P::generator() * sk;
		let rk = P::Scalar::new_random();
		Keys {
			sk,
			vk,
			rk,
			party_index: 0
		}
	}

	pub fn partial_eval(&self, message: &[u8]) -> PartialSignatureProverOutput<P>
	{
		let message_bn = &BigInt::from(message);
		let hashed_msg: P = hash_to_curve_with_auxillary(&message_bn, &BigInt::from(3));
		//let hashed_msg: P = self::hash_to_curve(&message_bn, &self.vk.bytes_compressed_to_big_int());
		let x = &self.sk;
		let sig_i = hashed_msg.scalar_mul(&x.get_element());
		let w = sigma_ec_ddh::ECDDHWitness { x: ECScalar::from(&x.to_big_int()) };
		let g = P::generator();
		let vk = self.vk;
		let delta = sigma_ec_ddh::ECDDHStatement {
			g1: g,
			h1: vk,
			g2: hashed_msg,
			h2: sig_i
		};
		let proof = sigma_ec_ddh::ECDDHProof::prove(&w, &delta);
		assert!(proof.verify(&delta).is_ok());

		PartialSignatureProverOutput {
			party_index: self.party_index,
			sig_i,
			proof
		}
	}


	pub fn partial_eval_non_valid(&self, message: &[u8]) -> PartialSignatureProverOutput<P>
	{
		let message_bn = &BigInt::from(message);
		let hashed_msg: P = hash_to_curve_with_auxillary(&message_bn, &BigInt::from(3));
		//let hashed_msg: P = self::hash_to_curve(&message_bn, &self.vk.bytes_compressed_to_big_int());
		let x =  P::Scalar::new_random();
		let sig_i = hashed_msg.scalar_mul(&x.get_element());
		let w = sigma_ec_ddh::ECDDHWitness { x: ECScalar::from(&x.to_big_int()) };
		let g = P::generator();
		let vk = g * P::Scalar::new_random();
		let delta = sigma_ec_ddh::ECDDHStatement {
			g1: g,
			h1: vk,
			g2: hashed_msg,
			h2: sig_i
		};
		let proof = sigma_ec_ddh::ECDDHProof::prove(&w, &delta);
		//assert!(proof.verify(&delta).is_ok());

		PartialSignatureProverOutput {
			party_index: self.party_index,
			sig_i,
			proof
		}
	}
}
pub fn verify_partial_sig<P:ECPoint> (
		message: &[u8], vk: P, prover_output: PartialSignatureProverOutput<P>)
		-> Result<(),Error>
		where
			P:ECPoint,
			P::Scalar: Zeroize + Clone
	{
			let message_bn = &BigInt::from(message);
			let hashed_msg: P = hash_to_curve_with_auxillary(&message_bn, &BigInt::from(3));
			let g = P::generator();
			let delta = sigma_ec_ddh::ECDDHStatement {
				g1: g,
				h1: vk,
				g2: hashed_msg,
				h2: prover_output.sig_i
			};
		let valid = prover_output.proof.verify(&delta);
			if valid.is_ok(){
				Ok(())
			}
			else{
				Err(Error::InvalidPartialSig)
			}
		}

pub fn valid_signers<P:ECPoint>(
	message: &[u8], vk_vec: Vec<P>, prover_output_vec: Vec<PartialSignatureProverOutput<P>>)
	-> Vec<usize>
	where
		P:ECPoint ,
		P::Scalar: Zeroize + Clone
	{
		let g = P::generator();
		let valid_signers_index = prover_output_vec
			.iter()
			.filter(|&prover_output| {
				verify_partial_sig(
					message,vk_vec[prover_output.party_index].clone(), prover_output.clone())
					.is_ok()
				})
			.map(|prover_output| prover_output.party_index)
			.collect();
	valid_signers_index
	}

