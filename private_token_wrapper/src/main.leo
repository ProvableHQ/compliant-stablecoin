import stablecoin_bridge.aleo;
import stablecoin_program.aleo;
import multisig_core.aleo;


// The 'private_token_wrapper' program.
program private_token_wrapper.aleo {
    // This is the constructor for the program.
    // The constructor allows you to manage program upgrades.
    // It is called when the program is deployed or upgraded.
    // It is currently configured to **prevent** upgrades.
    // Other configurations include:
    //  - @admin(address="aleo1...")
    //  - @checksum(mapping="credits.aleo/fixme", key="0field")
    //  - @custom
    // For more information, please refer to the documentation: `https://docs.leo-lang.org/guides/upgradability`
    @custom
    constructor() {
        // Only require multisig for upgrades - initial deployment has no checks.
        if self.edition > 0u16 {
            let signing_op_id = BHP256::hash_to_field(ChecksumEdition { checksum: self.checksum, edition: self.edition });

            let wallet_signing_op_id_hash = BHP256::hash_to_field(multisig_core.aleo::WalletSigningOpId { wallet_id: self.address, signing_op_id: signing_op_id });
            let signing_complete = multisig_core.aleo::completed_signing_ops.contains(wallet_signing_op_id_hash);
            assert(signing_complete);
        }
    }

    struct ChecksumEdition {
        checksum: [u8; 32],
        edition: u16,
    }

    fn mint_private_wrapper(public payload: [u8; 305], public sig: [u8; 65], public hash: [u8; 32], secret: scalar, recipient: address) -> (stablecoin_program.aleo::Token, Final) {
        // Extract the hookData from the deposit payload.
        let hook_data: [u8; 32] = [0u8; 32];
        for i in 0u32..32u32 {
            hook_data[i] = payload[241u32 + i];
        }
        
        // Ensure that the hookData is reproduced correctly from the hash of the recipient's address and the secret.
        let hashed_data = BHP256::commit_to_field(recipient, secret);
        let field_bits = Serialize::to_bits_raw(hashed_data);
        let padded_bits = [false; 256];
        for i in 0u8..253u8 {
            padded_bits[i] = field_bits[i];
        }

        let field_bytes = Deserialize::from_bits_raw::[[u8; 32]](padded_bits);
        assert_eq(hook_data, field_bytes);

        let (recipient_address, amount, mint_to_wrapper_final): (address, u128, Final) = stablecoin_bridge.aleo::mint_public_v2(payload, sig, hash);
        // Ensure that the recipient address extracted from the payload is the wrapper program's address.
        assert_eq(recipient_address, self.address);

        // Transfer the public funds from the wrapper program as a record to the recipient's address.
        let (receipt, token_record, transfer_final) = stablecoin_program.aleo::transfer_public_to_private(recipient, amount);
        return (token_record, final {
            mint_to_wrapper_final.run();
            transfer_final.run();
        });
    }

    fn burn_private(user_record: stablecoin_program.aleo::Token, amount: u128, native_domain: u32, native_recipient: [u8; 32], merkle_proof: [stablecoin_program.aleo::MerkleProof; 2]) -> Final {
        let (receipt, return_token, transfer_final) = stablecoin_program.aleo::transfer_private_to_public(self.address, amount, user_record, merkle_proof);
        let burn_final = stablecoin_bridge.aleo::burn_public(amount, native_domain, native_recipient);
        return final {
            transfer_final.run();
            burn_final.run();
        };
    }
}