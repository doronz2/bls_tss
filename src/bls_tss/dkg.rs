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
use crate::bls_tss::Error;

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
	index: usize,
	a_i0: P::Scalar,
	qual_parties: Vec<usize>,
	shares: Vec<P::Scalar>,
	shares_prime: Vec<P::Scalar>,
	commitments_a: Vec<P>,
	commitments_b: Vec<P>,
}


#[derive(Clone,Debug,Serialize)]
pub struct VerificationKeys<P: ECPoint>{
	v: Vec<P>,
	vk: Vec<P>,
}


#[derive(Clone,Debug,Serialize)]
pub struct KeyGenMessagePhase1<P: ECPoint>{
	C_ik: Vec<P>,
	share: P::Scalar,
	share_prime: P::Scalar,
	index: usize
}



#[derive(Clone,Debug,Serialize)]
pub struct KeyGenBroadcastMessagePhase2<'a, P:ECPoint>{
	A_ik_vec: &'a Vec<P>,
	B_i0: GE2
}

#[derive(Clone,Debug,Serialize)]
pub struct KeyPair<P: ECPoint>{
	sk: P::Scalar,
	vk: P,
	rk: P::Scalar
}

#[derive(Clone,Debug)]
pub struct PartyKeys<P:ECPoint> {
	keyPair: KeyPair<P>,
	sk_ij : Vec<P::Scalar>,
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
}



impl<P:ECPoint + Debug> KeyPair<P> {
	pub fn combine_key_shares_from_qualified(sk_qualified: &Vec<P::Scalar>, sk_prime_qualified : Vec<P::Scalar>) -> Self{
		/*
		for i in (0..3){
			println!("sk col {:?}",P::generator() * sk_qualified[i]);
		}
*/
		let sk = sk_qualified.into_iter().
			fold(P::Scalar::zero(), |acc, &e| acc + e);
		let vk = P::generator() * sk;
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
	use std::any::Any;

	type GE1 = curv::elliptic::curves::bls12_381::g1::GE;
	type FE1 = curv::elliptic::curves::bls12_381::g1::FE;
	type GE2 = curv::elliptic::curves::bls12_381::g2::GE;


	#[test]
	fn test_key_gen(){
		let l = 3;
		let t = 2;
		let mut party_vec = vec![];
		let party_0 = Party::<GE1>::phase_1_commit(0,l,t);
		let party_1 = Party::<GE1>::phase_1_commit(1,l,t);
		let party_2 = Party::<GE1>::phase_1_commit(2,l,t);
	//	let party_4 = Party::<GE1>::phase_1_commit(4,l,t);
	//	let party_5 = Party::<GE1>::phase_1_commit(5,l,t);

		party_vec.push(party_0.clone());
		party_vec.push(party_1.clone());
		party_vec.push(party_2.clone());
	//	party_vec.push(party_4.clone());
	//	party_vec.push(party_5.clone());


		//return a vector of vectors of received messages for each party
		let msg_received_vec_phase_1: Vec<Vec<_>> =
				(0..l).
					//filter(|index_receiver| party_sender_index != index_receiver).
				map(|index_receiver|{
					party_vec.
						iter().
						map(| party_sender| {
					let received_msg = party_sender.phase_1_broadcast_commitment(index_receiver);
					let valid = phase_1_validate_commitments(received_msg.clone()).is_ok();
						assert!(valid);
						if valid {
							Ok(received_msg)// receive messages sk and sk'
						}
					else{
							Err(Error::InvalidSS_phase1)
					}
				}).
				collect::<Vec<_>>()
			}).
			collect::<Vec<Vec<_>>>();
		//println!("party_msg_received {:?}", msg_received_vec_phase_1[0].len());





		let party_keys_vec_received: Vec<PartyKeys<GE1>> = msg_received_vec_phase_1.iter().
			map(| party_msg_received| {
				let (sk_vec,rk_vec)= party_msg_received.iter().
					filter(|msg_1| msg_1.is_ok()).//filter out the non valid commitiments
					map(|msg_1| {
					let msg = msg_1.clone().expect("not valid commitment - did not pass eq 4");

						(msg.share, msg.share_prime)
				})
					.unzip();
				//println!(" --------------- sk_vec ----- {:?}",sk_vec::<Vec<FE1>>.len());
				let party_key_pairs = KeyPair::<GE1>::combine_key_shares_from_qualified(&sk_vec,rk_vec);
				//println!("sk_vec {:?}",sk_vec.clone());
				PartyKeys{
					keyPair: party_key_pairs,
					sk_ij: sk_vec
					}
				})
			.collect();




//////extraction phase/////////////////
	//constructing the vector v from the A_ik elements

		let msg_received_vec_phase_2: Vec<Vec<_>> = party_vec.
			iter().
			enumerate().
			map(|(party_sender_index, party_sender)| {
				(0..l).
					//filter(|index_receiver| party_sender_index != index_receiver).
					map(|index_receiver|{
						let received_msg = party_sender.phase_2_broadcast_commitment();
						let s_ij = party_keys_vec_received[index_receiver].sk_ij[party_sender_index];
						let valid = party_vec[index_receiver].validate_i_commitment_phase_2(received_msg.clone(),s_ij).is_ok();
						assert!(valid);
						if valid {
							Ok(received_msg)// receive messages sk and sk'
						}
						else{
							Err(Error::InvalidSS_phase1)
						}
					}).
					collect::<Vec<_>>()
			}).
			collect::<Vec<Vec<_>>>();

		let v_vec: Vec<GE1> = (0..t+1)
			.map(|i| {
				let mut party_vec_iter = party_vec.iter();
				let head = party_vec_iter.next().unwrap();
				party_vec_iter
					.fold(head.commitments_a[i], |acc,comm|
						acc + comm.phase_2_broadcast_commitment().A_ik_vec[i])
			})
			.collect();
		let vk: Vec<GE1> = party_vec
			.iter()
			.map(|party| {
				let mut v_vec_iter = v_vec.iter();
				let head = v_vec_iter.next().unwrap();
				v_vec_iter.enumerate()
					.fold(*head, |acc, (j,  &vk_base)|{
						let exp =
							<FE1 as ECScalar>::from(&BigInt::from( (party.index + 1) as i32).pow(	(j+1) as u32));
						//	println!("index {}, j {}, exp: {:?}", index,j,exp.to_big_int());
						acc + vk_base * exp
					})
			}).collect();
		assert_eq!(vk[0],party_keys_vec_received[0].keyPair.vk)
	}
}


