use curv::elliptic::curves::bls12_381::g1;
use curv::elliptic::curves::bls12_381::g2;
use curv::BigInt;
//use curv::cryptographic_primitives::hashing::hash_sha256;
//use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::elliptic::curves::traits::ECPoint;
use curv::elliptic::curves::traits::ECScalar;
use serde::export::fmt::Debug;
use curv::cryptographic_primitives::secret_sharing::feldman_vss;
use curv::cryptographic_primitives::pairing::pairing_bls12_381::PairingBls;
use curv::cryptographic_primitives::pairing::traits::PAIRING;
//use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;


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
pub fn validating_commitments<P: ECPoint + Copy + Debug>(received_msg_comm: ( Vec<P>, (&P::Scalar,&P::Scalar), usize)) -> bool {
	let (commitment, shares_j, index) = received_msg_comm;
	let g = P::generator();
	let h = P::base_point2();
	//computing g^s_ij*h^s'_ij
	let s_ji = shares_j.0;
	let s_ji_prime = shares_j.1;
	let commitment_from_eval: P = g * (*s_ji) + h * (*s_ji_prime);
//	println!("comm iter with head: {:?}", commitment);
	let mut commitment_iter = commitment.iter();
	let head= commitment_iter.next().unwrap();
//	println!("comm iter  without head: {:?}", commitment_iter);
	let commitment_from_comms = commitment_iter
		.enumerate()
		.fold(*head, |acc, (j,  &comm)|{
			let exp = <P::Scalar as ECScalar>::from(&BigInt::from(index as i32).pow((j+1) as u32));
		//	println!("index {}, j {}, exp: {:?}", index,j,exp.to_big_int());
			acc + comm * exp
		});

	assert_eq!(commitment_from_eval,commitment_from_comms);
	commitment_from_eval == commitment_from_comms
}



pub fn invalid_commitments_vec<P:ECPoint + Copy + Debug>
(
	l: u32, commitment: &Vec<Vec<P>>, shares_vec: Vec<(&P::Scalar, &P::Scalar)>
)-> Vec<bool> {
	(0..l as usize).
		map(|i| !validating_commitments((commitment[i].clone(), shares_vec[i], i)))
		.collect()
}

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

#[derive(Clone,Debug,Serialize)]
pub struct Party<P: ECPoint>{
	index: usize,
	a_i0: P::Scalar,
	qual_parties: Vec<usize>,
	shares: Vec<P::Scalar>,
	shares_prime: Vec<P::Scalar>,
	commitments_a: Vec<P>,
	commitments_b: Vec<P>,
}


impl<P: ECPoint + Clone> arty<P> {

	pub fn phase_1_commit( index: usize,  l: usize, t: usize) -> Self where <P as ECPoint>::Scalar: Clone {
		let a_i0: P::Scalar = P::Scalar::new_random();

		let G = P::generator();
		let (vss_a, shares) =
			feldman_vss::VerifiableSS::share_given_generator(t, l, &a_i0, G);
		let commitments_a: Vec<P> =vss_a.commitments;

		let H = P::base_point2();
		let (vss_b, shares_prime) =
			feldman_vss::VerifiableSS::<P>::share_given_generator(t, l, &P::Scalar::new_random(), H);
		let commitments_b: Vec<P> = vss_b.commitments;

		//let commitment_c = commitments_a.iter().zip(commitments_b.iter()).
		//	map(|(&comm_a_i, &comm_b_i)| comm_a_i + comm_b_i).collect();
		Self {
			a_i0,
			index,
			qual_parties: vec![],
			shares,
			shares_prime,
			commitments_a,
			commitments_b,
		}
		//(commitment_c,shares,shares_prime)
	}


	pub fn phase_1_broadcast_commitment(&self, index: usize)-> (Vec<P>,(&P::Scalar,&P::Scalar), usize){
		assert_ne!(self.index,index);
		let C_ik = self.commitments_a.iter()
			.zip(self.commitments_b.iter())
			.map(|(&comm_a,&comm_b)| comm_a + comm_b)
			.collect();
		(C_ik, (&self.shares[index - 1] ,&self.shares_prime[index - 1]),index)
	}

	pub fn phase_2_ExposingCoeffs(&self) -> (&Vec<GE1>,GE2){
		let g2: GE2 = GE2::generator();
		//converting a_i0 from P to T (i.e., from group G1 to group G2)
		let a_i0: &FE2 = &<FE2 as ECScalar>::from(&self.a_i0.to_big_int());
		let B_i0 = g2.scalar_mul(&a_i0.get_element());
		(&self.commitments_a, B_i0)
	}

	pub fn phase_2_verify_validity_of_i_commitment(&self, commitment_i: &Vec<GE1>, s_ij: &FE1, B_i0: GE2) -> bool{
		let mut commitment_iter = commitment_i.iter();
		let head = commitment_iter.next().unwrap();
		let A_ik_prod = commitment_iter
			.enumerate()
			.fold(*head, |acc, (j,  &A_ik)|{
				let exp =
					<FE1 as ECScalar>::from(&BigInt::from(self.index as i32).pow((j+1) as u32));
				//	println!("index {}, j {}, exp: {:?}", index,j,exp.to_big_int());
				acc + A_ik * exp
			});
		let g1 = &GE1::generator();
		let g2 = &GE2::generator();
		let check_A_ik_commitments =  A_ik_prod == g1.scalar_mul(&s_ij.get_element());
		let A_i0 = commitment_i[0];
		let check_ai0_secret =
			PairingBls::compute_pairing(&A_i0,&g2) == PairingBls::compute_pairing(&g1,&B_i0);
		check_A_ik_commitments && check_ai0_secret
	}
}

#[derive(Debug)]
pub struct KeyPair<P: ECPoint>{
	sk: P::Scalar,
	vk: P,
	rk: P::Scalar
}

impl<P:ECPoint> KeyPair<P> {
	pub fn combine_key_shares_from_qualified(sk_qualified: Vec<P::Scalar>, sk_prime_qualified : Vec<P::Scalar>) -> Self{
		let sk = sk_qualified.into_iter().
			fold(P::Scalar::zero(), |acc, e| acc + e);
		let vk = P::generator()* sk;
		let rk = sk_prime_qualified.iter().
			fold(P::Scalar::zero(), |acc, &e| acc + e);
		Self{
			sk, vk, rk
		}
	}
}

#[cfg(test)]
mod test{
	use super::*;
	type GE1 = curv::elliptic::curves::bls12_381::g1::GE;
	type FE1 = curv::elliptic::curves::bls12_381::g1::FE;
	type GE2 = curv::elliptic::curves::bls12_381::g2::GE;


	#[test]
	fn test_generating_phase(){
		let l = 3;
		let t = 2;
		let mut party_vec = vec![];
		let party_1 = Party::<GE1>::phase_1_commit(1,l,t);
		let party_2 = Party::<GE1>::phase_1_commit(2,l,t);
		let party_3 = Party::<GE1>::phase_1_commit(3,l,t);
		party_vec.push(party_1.clone());
		party_vec.push(party_2.clone());
		party_vec.push(party_3.clone());
		let party_msg_received_vec: Vec<Vec<_>> = party_vec.
			iter().
			enumerate().
			map(|(party_sender_index, party_sender)| {
				(1..l+1).
				filter(|index_receiver| party_sender_index != index_receiver - 1).
				map(|index_receiver|{
					let received_msg = party_sender.phase_1_broadcast_commitment(index_receiver);
						assert!(validating_commitments(received_msg.clone()));
					received_msg
				}).
				collect::<Vec<_>>()
			}).
			collect::<Vec<Vec<_>>>();
		println!("party_msg_received {:?}", party_msg_received_vec);

		let party_keys_vec: Vec<KeyPair<GE1>> = party_msg_received_vec.iter().
			map(| party_msg_received| {
				let (sk_vec,rk_vec) = party_msg_received.iter().map(|msg_tuple| {
					let (sk, rk) = msg_tuple.1;
					(sk, rk)
				})
					.unzip();
				let party_keys = KeyPair::<GE1>::combine_key_shares_from_qualified(sk_vec,rk_vec);
				party_keys
				})
			.collect();

		println!("party_keys_vec {:?}", party_keys_vec);

	//	let phase_2_msg_vec =
	}


}


