#[cfg(test)]
mod test {
    use crate::bls_tss::party::*;

    #[test]
    fn integration_test() {
        let l = 3;
        let t = 2;
        let params = &Parameters {
            threshold: t,
            share_count: l,
        };

        let mut party_vec = vec![];
        let party_0 = Party::phase_1_commit(0, &params);
        let party_1 = Party::phase_1_commit(1, &params);
        let party_2 = Party::phase_1_commit(2, &params);
        let party_malicious = Party::phase_false_broadcast_commit(3, &params);

        party_vec.push(party_0);
        party_vec.push(party_1);
        party_vec.push(party_2);
        party_vec.push(party_malicious);

        //////KeyGen: extraction phase/////////////////

        //return a vector of vectors of received messages for each party
        let msg_received_vec_phase_1: Vec<Vec<KeyGenMessagePhase1>> = (0..l).
                map(|index_receiver|{
                    party_vec.
                        iter().
                        map(| party_sender| {
                            party_sender.phase_1_broadcast_commitment(index_receiver)
                        }).
                        collect::<Vec<KeyGenMessagePhase1>>()
                }).
                collect::<Vec<Vec<KeyGenMessagePhase1>>>();

        let (party_keys_vec_received, sk_shares_vec): (Vec<Keys>, Vec<SharesSkOfParty>) =
            msg_received_vec_phase_1
                .iter()
                .map(|party_msg_received| {
                    keygen_generating_phase_validate_and_combine_shares(party_msg_received)
                })
                .unzip();

        //////KeyGen: extraction phase/////////////////
        let extraction_phase_broadcast_vec: Vec<Vec<KeyGenBroadcastMessagePhase2>> = (0..params
            .share_count)
            .map(|_| {
                party_vec
                    .iter()
                    .map(|party_sender| party_sender.phase_2_broadcast_commitment())
                    .collect()
            })
            .collect();

        let shared_key_vec: Vec<SharedKeys> = extraction_phase_broadcast_vec
            .iter()
            .enumerate()
            .zip(party_keys_vec_received.iter())
            .map(|((party_index, bc_received_by_party), party_sender_keys)| {
                keygen_extracting_phase_validate_and_compute_PK_and_verification_keys(
                    party_index,
                    bc_received_by_party.clone(),
                    sk_shares_vec.clone(),
                    party_sender_keys.clone().QUAL,
                    &params,
                )
            })
            .collect();

        let vk_vec = shared_key_vec[0].verification_keys.clone();
        let message: &[u8; 4] = &[124, 12, 251, 82];

        //create partial signature
        let provers_output_vec: Vec<PartialSignatureProverOutput> = party_keys_vec_received
            .iter()
            .map(|party_keys| party_keys.partial_eval(message))
            .collect();

        //validate the partial signature and combine the shares of the partial signature into a unified signature
        let combined_sig = combine(params, message, vk_vec, provers_output_vec);
        let pk = shared_key_vec[0].public_key;
        assert!(verify(pk, message, combined_sig));
    }



    #[test]
    fn test_partial_sig() {
        let message: &[u8; 4] = &[124, 12, 251, 82];
        let party_keys = Keys::generate_random_key(0);
        let prover_output = &party_keys.partial_eval(message);
        let valid = verify_partial_sig(message, party_keys.get_vk(), prover_output).is_ok();
        assert!(valid);
    }


    #[test]
    fn test_vector_sig() {
        let message: &[u8; 4] = &[124, 12, 251, 82];
        let num_of_provers = 5;
        let mut key_vec: Vec<Keys> = Vec::new();
        for i in 0..num_of_provers {
            key_vec.push(Keys::generate_random_key(i));
        }

        let non_valid_provers = [1, 3];
        let provers_output_vec: Vec<PartialSignatureProverOutput> = key_vec
            .iter()
            .enumerate()
            .map(|(prover_index, party_keys)| {
                if non_valid_provers
                    .iter()
                    .any(|&non_valid_prover_index| non_valid_prover_index == prover_index)
                {
                    party_keys.partial_eval_non_valid(message)
                } else {
                    party_keys.partial_eval(message)
                }
            })
            .collect();
        let vk_vec = key_vec.iter().map(|key| key.get_vk()).collect();
        let valid_signers_index = valid_signers(message, vk_vec, provers_output_vec);
        assert_eq!([0, 2, 4], valid_signers_index.0.as_slice());
    }
}
