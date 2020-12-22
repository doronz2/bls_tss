#[cfg(test)]
mod test {
    use crate::bls_tss::party::*;
    use std::collections::HashMap;

    #[test]
    fn integration_test() {
        let l = 6;
        let t = 2;
        let params = &Parameters {
            threshold: t,
            share_count: l,
        };

        let mut party_vec = vec![];
        let party_0 = Party::phase_1_commit(0, &params);
        let party_1 = Party::phase_1_commit(1, &params);
        let party_2 = Party::phase_1_commit(2, &params);
        let party_3 = Party::phase_1_commit(3, &params);
        let party_4 = Party::phase_1_commit(4, &params);
        let party_malicious = Party::phase_1_false_commit(5, &params);

        party_vec.push(party_0);
        party_vec.push(party_1);
        party_vec.push(party_2);
        party_vec.push(party_3);
        party_vec.push(party_4);
        party_vec.push(party_malicious);

        assert_eq!(party_vec.len(),l);
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
        let malicious_broadcaster_phase_2 = [10];



        let extraction_phase_broadcast_vec: Vec<KeyGenBroadcastMessagePhase2> =
                party_vec
                    .iter()
                    .map(|party_sender|
                        {
                            if malicious_broadcaster_phase_2.iter().any(|&mal_broadcaster| mal_broadcaster == party_sender.index){
                                party_sender.phase_2_broadcast_false_commitment()
                            }
                            else {
                                party_sender.phase_2_broadcast_commitment()
                            }
                        })
                    .collect();


        let shared_key_vec: Vec<SharedKeys> = (0..params.share_count)
            .zip(party_keys_vec_received.iter())
            .map(|(party_index, party_sender_keys)| {
                keygen_extracting_phase_validate_and_compute_PK_and_verification_keys(
                    party_index,
                    extraction_phase_broadcast_vec.clone(),
                    sk_shares_vec.clone(),
                    party_sender_keys.clone().QUAL,
                    &params,
                )
            })
            .collect();

        let message: &[u8; 4] = &[124, 12, 251, 82];
        let honest_party = 0;

        //define a set of parties who send non valid proofs
        let non_valid_provers = [2,4];

        //create partial signature
        let provers_output_vec: HashMap<usize, PartialSignatureProverOutput> = party_keys_vec_received
            .iter()
            .enumerate()
            .map(|(prover_index, party_keys)| {
                if non_valid_provers
                    .iter()
                    .any(|&non_valid_prover_index| non_valid_prover_index == prover_index)
                {
                    (party_keys.party_index, party_keys.partial_eval_non_valid(message))
                } else {
                    (party_keys.party_index, party_keys.partial_eval(message))
                }
            })
            .collect();

        //validate the partial signature and combine the shares of the partial signature into a unified signature
        let vk_vec = shared_key_vec[honest_party].verification_keys.clone();

        let combined_sig = combine(params, message, vk_vec, provers_output_vec);
        let pk = shared_key_vec[honest_party].public_key;
        assert!(verify(pk, message, combined_sig));
    }


}
