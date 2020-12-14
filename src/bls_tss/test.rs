

#[cfg(test)]
mod test{
    use curv::BigInt;
    use curv::elliptic::curves::traits::ECScalar;
    use crate::bls_tss::Error;
    use rand::Rng;
    use crate::bls_tss::party::*;

    type GE1 = curv::elliptic::curves::bls12_381::g1::GE;
    type FE1 = curv::elliptic::curves::bls12_381::g1::FE;
    type GE2 = curv::elliptic::curves::bls12_381::g2::GE;

    #[test]
    fn integration_test(){
        let l = 3;
        let t = 2;
        let valid_shares = 0;

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
        let msg_received_vec_phase_1: Vec<Vec<KeyGenMessagePhase1<GE1>>> =
            (0..l).
                //filter(|index_receiver| party_sender_index != index_receiver).
                map(|index_receiver|{
                    party_vec.
                        iter().
                        map(| party_sender| {
                            party_sender.phase_1_broadcast_commitment(index_receiver)
                        }).
                        collect::<Vec<KeyGenMessagePhase1<GE1>>>()
                }).
                collect::<Vec<Vec<KeyGenMessagePhase1<GE1>>>>();
        //println!("party_msg_received {:?}", msg_received_vec_phase_1[0].len());


        let (party_keys_vec_received, sk_shares_vec): (Vec<Keys<GE1>>,Vec<SharesSkOfParty>) = msg_received_vec_phase_1.iter().
            map(| party_msg_received|
                keygen_generating_phase_validate_and_combine_shares(party_msg_received)
            )
            .unzip();




//////extraction phase/////////////////
        //constructing the vector v from the A_ik elements
      //  let pk_vec = Vec::new();
        let extraction_phase_broadcast_vec: Vec<Vec<KeyGenBroadcastMessagePhase2<GE1>>> =
            (0..l).
                map(|index_receiver|
                    party_vec.iter()
                        .map(|party_sender| party_sender.phase_2_broadcast_commitment())
                        .collect())
                .collect();

        let shared_key_vec = extraction_phase_broadcast_vec
            .iter()
            .enumerate()
            .map(|(party_index, &bc_received_by_party)|
                keygen_extracting_phase_validate_and_compute_PK_and_verification_keys(
                    party_index,
                    bc_received_by_party,
                    bcsk_shares_vec)
            ).collect();


/*
        let public_keys_vec: Vec<_> =
            (0..l).
            map(|index_receiver|  {
                    let pk_vec: Vec<Result<GE2,Error>> = party_vec
                        .iter()
                        .enumerate()
                    //filter(|index_receiver| party_sender_index != index_receiver).
                        .map(|(party_sender_index, party_sender)|{
                        let received_msg = party_sender.phase_2_broadcast_commitment();
                        let s_ij = sk_shares_vec[index_receiver].sk_ij[party_sender_index];
                        let valid = party_vec[index_receiver].validate_i_commitment_phase_2(received_msg.clone(),s_ij).is_ok();
                        assert!(valid);
                        if valid {
                            //Ok(received_msg)// receive messages sk and sk'
                            Ok(received_msg.B_i0)
                        }
                            else{
                                Err(Error::InvalidSS_Phase2)
                            }
                    }).
                    collect();
                    Party::<GE1>::compute_public_key(pk_vec)
                }
            ).
            collect::<Vec<GE2>>();
  */
        assert_eq!(public_keys_vec[0], public_keys_vec[0]);
        println!("pub_keys: {:#?}", public_keys_vec);

        let v_vec: Vec<GE1> = (0..t+1)
            .map(|i| {
                let mut party_vec_iter = party_vec.iter();
                let head = party_vec_iter.next().unwrap();
                party_vec_iter
                    .fold(head.commitments_a[i], |acc,comm|
                        acc + comm.phase_2_broadcast_commitment().A_ik_vec[i])
            })
            .collect();
        let vk_vec: Vec<GE1> = party_vec
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
       // assert_eq!(vk_vec[0],party_keys_vec_received[0].Keys.vk);
        //let vk_others = VerificationKeys{vk_vec};
        //







        let message: &[u8; 4] = &[124, 12, 251, 82];


        let provers_output_vec: Vec<PartialSignatureProverOutput<GE1>> = party_keys_vec_received
            .iter()
            .map(|party_keys| {
                    party_keys.partial_eval(message)
                })
            .collect();

        let params = &Parameters{ threshold: t, share_count: l };
        let combined_sig = combine(params, message,vk_vec,provers_output_vec);
        let pk = public_keys_vec[0];
        assert!(verify(pk,message,combined_sig));
    }

    #[test]
    fn test_partial_sig() {
        let message: &[u8; 4] = &[124, 12, 251, 82];
        let party_keys = Keys::<GE1>::generate_random_key(0);
        let prover_output = &party_keys.partial_eval(message);
        let valid = verify_partial_sig(message, party_keys.get_vk(), prover_output).is_ok();
        assert!(valid);
    }

    #[test]
    fn test_vector_sig(){
        let message: &[u8; 4] = &[124, 12, 251, 82];

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
                if b == 0 {
                    party_keys.partial_eval(message)
                }
                else{
                    party_keys.partial_eval_non_valid(message)
                }
            })
            .collect();

        let vk_vec = key_vec.iter().map(|key| key.get_vk()).collect();
        let valid_signers_index = valid_signers(message,vk_vec,provers_output_vec);
        println!("valid signers indices {:#?}",valid_signers_index);
    }

/*
    pub fn test_combine_shares(){
        let message: &[u8; 4] = &[124, 12, 251, 82];
        const n: usize = 3;
        const t: usize = 2;
        let sk  = FE1::new_random();

        VerifiableSS::share(t,n,sk);
        let pk = GE2 * sk;

        sk_shares = [FE1;5];
        for i in 0..n-1{
            sk_vec[i] = FE1::new_random();
        }
        let sum_shares_except_the_last = sk_shares
            .iter()
            .fold(FE2::zero(), |acc, share| acc + share);
        sk[n-1] = sk - sum_shares_except_the_last;

        let params = Parameters{ threshold: t, share_count: n };
    }
*/

}

