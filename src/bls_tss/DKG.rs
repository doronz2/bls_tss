use super::pairing_bls12_381::PairingBls;
use super::pairing_bls12_381::PAIRING;
use curv::elliptic::curves::bls12_381::g1;
use curv::elliptic::curves::bls12_381::g2;
use curv::BigInt;
use curv::cryptographic_primitives::hashing::hash_sha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::elliptic::curves::traits::ECPoint;
use curv::elliptic::curves::traits::ECScalar;
use serde::export::fmt::Debug;
use curv::cryptographic_primitives::secret_sharing::feldman_vss;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use p256::Scalar;

type GE1 = g1::GE;
type GE2 = g2::GE;


//step a in creating phase Ni send commitments to Nj
pub fn committing_to_two_polynomials<P:ECPoint>(a_i0: P::Scalar, l: usize, t: usize)-> (VerifiableSS<P>,Vec<(P,P)>){
	let (sss, shares) =
		feldman_vss::VerifiableSS::<P>::share(t,l,a_i0 )  ;
	let commitments_a = sss.commitments;
	let (sss_prime, shares_prime) =
		feldman_vss::VerifiableSS::<P>::share(t,l,P::Scalar::new_random())  ;
	let commitments_b = sss_prime.commitments;
	let share_pair =  shares.iter().zip(shares_prime).collect();
	let commitment_c = commitments_a.iter().zip(commitments_b.iter()).
		map(|comm_a_i,comm_b_i| comm_a_i*comm_b_i).collect();
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

//step b in creating phase
pub fn validating_commitments<P: ECPoint>(commitment: Vec<P>, shares_j: &[P; 2], index: u32) -> bool {
	let g: ECPoint = P::generator();
	let h: ECPoint = P::base_point2();
	//computing g^s_ij*h^s'_ij
	let commitment_from_eval: P =
		g.scalar_mul(shares_j[&0]).add_point(h.scalar_mul(shares_j[&1]));
	let mut commitment_iter = commitment.iter();
	let head= commitment_iter.next().unwrap();
	let commitment_from_comms = commitment_iter
		.enumerate()
		.fold(head, |acc, (j,comm)|{
			acc.add_point(comm.scalar_mul( P::Scalar::from(&BigInt::from(index).pow(j as u32))))
		});
	commitment_from_eval == commitment_from_comms
}

pub fn invalid_commitments_vec<P:ECPoint>
(
	l: u32, commitment: Vec<Vec<P>>, shares_vec: Vec<&[P; 2]>
)-> Vec<bool> {
	(0..l).
		map(|&i| !validating_commitments(commitment[i], shares_vec[i], i))
		.collect()
}

pub fn create_list_of_blames(blame_from_i: Vec<Vec<bool>>, t: usize)->Vec<usize> {
	//let vecs = Vec::from([Vec::from([1, 2, 3, 8]), Vec::from([4, 5, 6, 9]), Vec::from([10, 11, 12, 13])]);
	//transpose the rows and the vecs
	let vecs = Vec::from([Vec::from([true, false, true, false]), Vec::from([true, false, false, false]),Vec::from([true, true, false, false])]);
	let trans_vec: Vec<Vec<bool>> = (0..vecs[0].len()).map(|j| (0..vecs.len()).map(|i| vecs[i][j]).collect()).collect();
	let count_false:Vec<usize> = trans_vec.iter().map(|v| v.iter().filter(|&i| !*i).count()).collect();
	let blame_greater_than_t: Vec<usize> = count_false.iter().enumerate().filter(|&(_index,i)| i>&t).map(|(_index,_)| _index).collect();
	println!("transformed vec {:?}", trans_vec);
	println!("count_false {:?}", count_false);
	println!("greater_than_t {:?}", blame_greater_than_t);

}

#[derive(Copy, Clone,Debug,Serialize)]
pub struct Party<P: ECPoint>{
	index: usize,
	a_i0: P::Scalar,
	qual_parties: Vec<usize>,
}

#[derive(Copy, Clone,Debug,Serialize)]
pub struct PartyComm<P>{
	shares_poly: Vec<P>,
	shares_poly_prime: Vec<P>,
	commitments: Vec<P>,
}

impl<P: ECPoint> Party<P> {
	//step a in creating phase Ni send commitments to Nj
	pub fn create_party_and_commit_to_poly(index: usize) -> Self <P> {
		Self {
			a_i0: P::Scalar::new_random(),
			index,
			qual_parties: vec![],

		}
	}
}

impl<P: ECPoint> PartyComm<P> {

	pub fn phase_1_committing_to_two_polynomials_to_self<P: ECPoint>(&self,  l: usize, t: usize) -> Self {
		let (_, shares) =
			feldman_vss::VerifiableSS::<P>::share(t, l, &self.a_i0);
		let commitments_a = sss.commitments;
		let (_, shares_prime) =
			feldman_vss::VerifiableSS::<P>::share(t, l, P::Scalar::new_random());
		let commitments_b = sss.commitments;
		let commitment_c = commitments_a.iter().zip(commitments_b.iter()).
			map(|comm_a_i, comm_b_i| comm_a_i * comm_b_i).collect();
		Self { shares_poly, shares_poly_prime, commitments: commitment_c}
		//(commitment_c,shares,shares_prime)
	}



	pub fn phase_2_ExposingCoeffs(){

	}
}


pub struct KeyPair<P: ECPoint>{
	sk: P::Scalar,
	vk: P,
	rk: P::Scalar
}

impl<P:ECPoint> KeyPair<P> {
	pub fn create_key_pair_from_qualified(sk_qualified: Vec<P::Scalar>, sk_prime_qualified : Vec<P::Scalar>) -> Self<P>{
		let sk = sk_qualified.iter().
			fold(P::Scalar::zero(), |acc, e| acc + e);
		let vk = P::generator().scalar_mul(sk);
		let rk = sk_prime_qualified.iter().
			fold(P::Scalar::zero(), |acc, e| acc + e);
		Self{
			sk, vk, rk
		}
	}
}

#[cfg(test)]
mod test{
	use super::*;
	#[test]
	fn test_phase_1(){
		let party_1 = Party::create_party(0);
		let party_2 = Party::create_party(1);

	}


}


