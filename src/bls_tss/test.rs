

#[cfg(test)]
mod test{
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
    use zeroize::Zeroize;
    use rand::Rng;
    use crate::bls_tss::party::*;
    use crate::bls_tss::*;
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
                        msg.output_shares()
                    })
                    .unzip();
                //println!(" --------------- sk_vec ----- {:?}",sk_vec::<Vec<FE1>>.len());
                let party_index = party_msg_received[0].clone().unwrap().index;
                let party_key_pairs = Keys::<GE1>::combine_key_shares_from_qualified(&sk_vec,rk_vec, party_index);
                //println!("sk_vec {:?}",sk_vec.clone());
                PartyKeys{
                    Keys: party_key_pairs,
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
       // assert_eq!(vk[0],party_keys_vec_received[0].Keys.vk);
        let vk_others = VerificationKeys{vk};
        //
    }

    #[test]
    fn test_partial_sig() {
        let message: &[u8; 4] = &[124, 12, 251, 82];
        let party_keys = Keys::<GE1>::generate_random_key(0);
        let prover_output = party_keys.partial_eval(message);
        let valid = verify_partial_sig(message, party_keys.get_vk(), prover_output).is_ok();
        assert!(valid);
    }

    #[test]
    fn test_vector_sig(){
        let message: &[u8; 4] = &[124, 12, 251, 82];
        let G = GE1::generator();

        let mut key_vec: Vec<Keys<GE1>> = Vec::new();
        for i in 0..20{
            key_vec.push(Keys::<GE1>::generate_random_key(i));
        }
        println!("key_vec {:#?}",key_vec);
        let mut rng = rand::thread_rng();

        let provers_output_vec: Vec<PartialSignatureProverOutput<GE1>> = key_vec
            .iter()
            .map(|party_keys| {
                let b = rng.gen_range(0,2);
                println!("b={}",b);
                if b >= 0 {
                    party_keys.partial_eval(message)
                }
                else{
                    party_keys.partial_eval_non_valid(message)
                }
            })
            .collect();

        let vk_vec = key_vec.iter().map(|key| key.get_vk()).collect();
        let valid_signers_index = valid_signers(message,vk_vec,provers_output_vec);
        println!("valid signers indices {:?}",valid_signers_index);
    }


}


