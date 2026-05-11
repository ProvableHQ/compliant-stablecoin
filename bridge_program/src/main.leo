import merkle_tree.aleo;
import multisig_core.aleo;
import freezelist_program.aleo;
import stablecoin_program.aleo;

// The USDCx bridge program.
program stablecoin_bridge.aleo {
    @custom
    async constructor() {
        // Only require multisig for upgrades - initial deployment has no checks.
        if self.edition > 0u16 {
            let signing_op_id = BHP256::hash_to_field(ChecksumEdition { checksum: self.checksum, edition: self.edition });

            let wallet_signing_op_id_hash = BHP256::hash_to_field(WalletSigningOpId { wallet_id: self.address, signing_op_id: signing_op_id });
            let signing_complete = multisig_core.aleo/completed_signing_ops.contains(wallet_signing_op_id_hash);
            assert(signing_complete);
        }
    }

    const USDCX_PAUSE_KEY: address = aleo16s9af9darj0j5k7fpaxjq0u9fepd6sc4svrkr9vs4d3wlmp5lqyq4h3fpl;
    const USDCX_MANAGER_KEY: address = aleo13zt4uq0u09sffnf4ctgu47k5n30txjx2w9cwcqgneapjeqsywsqqu6hspt;
    const PRIVATE_MINT_WRAPPER_ADDRESS: address = private_token_wrapper.aleo;
    const ETH_PUBLIC_KEY: [u8; 20] = [252, 83, 188, 10, 12, 182, 237, 57, 194, 0, 45, 226, 77, 10, 169, 81, 124, 122, 66, 198]; // 0xfc53bc0a0cb6ed39c2002de24d0aa9517c7a42c6
    const ARC_PUBLIC_KEY: [u8; 20] = [152, 17, 74, 154, 55, 157, 106, 190, 118, 131, 221, 148, 116, 192, 136, 32, 81, 93, 17, 186]; // 0x98114a9a379d6abe7683dd94874c08820515d11ba
    const MAGIC_VALUE: [u8; 4] = [90, 46, 10, 205]; // 0x5a2e0acd 
    const SUPPORTED_VERSION: [u8; 4] = [0, 0, 0, 1];
    const DOMAIN: [u8; 4] = [0, 0, 39, 18]; // 10002
    const MINIMUM_BURN_AMOUNT: u128 = 5000000u128;
    const MAXIMUM_BURN_AMOUNT: u128 = 5000000000000u128; // 5 million USDC limit set by Circle.
    // These constants are used to interact with the Circle freeze list program.
    const MAX_TREE_DEPTH: u32 = 15u32;
    const CURRENT_FREEZE_LIST_ROOT_INDEX: u8 = 1u8;
    const PREVIOUS_FREEZE_LIST_ROOT_INDEX: u8 = 2u8;
    const BLOCK_HEIGHT_WINDOW_INDEX: bool = true;
    const ROOT_UPDATED_HEIGHT_INDEX: bool = true;
    const ETH_DESTINATION_DOMAIN: u32 = 0u32;
    const ARC_DESTINATION_DOMAIN: u32 = 26u32;

    // A helper for calculating a signing_op_id from the program's checksum and edition.
    // By deriving the signing_op_id from both we ensure that downgrades cannot take place.
    transition get_signing_op_id_for_deploy(checksum: [u8; 32], edition: u16) -> field {
        return BHP256::hash_to_field(ChecksumEdition { checksum: checksum, edition: edition });
    }

    struct ChecksumEdition {
        checksum: [u8; 32],
        edition: u16,
    }

    mapping circle_attester: bool => [u8; 20];
    mapping circle_attesters: [u8; 32] => [u8; 20]; // Mapping of localToken address to corresponding public attester key.
    mapping maximum_burn_amount: bool => u128;
    mapping minimum_burn_amount: bool => u128;
    mapping nullifier: [u8; 32] => bool;
    mapping paused: bool => bool;

    // This method extracts the recipient address, amount, and nonce field from the payload and verifies the ECDSA signature.
    // A freeze list check is also performed before minting private tokens to the recipient address.
    async transition mint_private(deposit_input: [u8; 240], sig: [u8; 65], digest: [u8; 32], receiver_merkle_proofs: [stablecoin_program.aleo/MerkleProof; 2]) -> (stablecoin_program.aleo/ComplianceRecord, stablecoin_program.aleo/Token, Future) {
        // This method is deprecated in favor of mint_private_v2.
        assert_neq(self.caller, self.caller);
        
        // Check the invariant conditions before proceeding with the mint.
        let (amount, recipient_address, deposit_hash, nonce) = check_mint_invariants(deposit_input, digest);

        // Verify that the recipient is not frozen in the Circle freeze list.
        let root: field = verify_non_inclusion_private(recipient_address, receiver_merkle_proofs);

        // Call the mint private function from the Bridged USDC program.
        let (compliance_record, usdc_record, token_future): (stablecoin_program.aleo/ComplianceRecord, stablecoin_program.aleo/Token, Future) = stablecoin_program.aleo/mint_private(recipient_address, amount);
        
        // Perform the signature verification, freeze list check, and nullifier check.
        let verify_future: Future = finalize_verify_ecdsa_private(sig, deposit_hash, nonce, root, token_future);

        return (compliance_record, usdc_record, verify_future);
    }

    // This method extracts the recipient address, amount, and nonce field from the payload and verifies the ECDSA signature.
    // A freeze list check is also performed before minting private tokens to the recipient address.
    async transition mint_private_v2(deposit_input: [u8; 305], sig: [u8; 65], digest: [u8; 32], receiver_merkle_proofs: [stablecoin_program.aleo/MerkleProof; 2]) -> (stablecoin_program.aleo/ComplianceRecord, stablecoin_program.aleo/Token, Future) {        
        // Check the invariant conditions before proceeding with the mint.
        let (amount, recipient_address, deposit_hash, nonce, local_token) = check_mint_invariants_v2(deposit_input, digest);

        // Ensure that the flag byte is set to 1u8 for mint private.
        let flag_byte: u8 = deposit_input[240];
        assert_eq(flag_byte, 1u8);

        // Verify that the recipient is not frozen in the Circle freeze list.
        let root: field = verify_non_inclusion_private(recipient_address, receiver_merkle_proofs);

        // Call the mint private function from the Bridged USDC program.
        let (compliance_record, usdcx_record, token_future): (stablecoin_program.aleo/ComplianceRecord, stablecoin_program.aleo/Token, Future) = stablecoin_program.aleo/mint_private(recipient_address, amount);

        return (compliance_record, usdcx_record, async {
            // Check that the Admin has not paused the bridge.
            let is_paused: bool = paused.get_or_use(true, false);
            assert_eq(is_paused, false);

            // Check that the Merkle root is valid.
            let current_root: field = freezelist_program.aleo/freeze_list_root.get(CURRENT_FREEZE_LIST_ROOT_INDEX);
            let window: u32 = freezelist_program.aleo/block_height_window.get(BLOCK_HEIGHT_WINDOW_INDEX);

            if (current_root != root) {
                let previous_root: field = freezelist_program.aleo/freeze_list_root.get(PREVIOUS_FREEZE_LIST_ROOT_INDEX);
                assert_eq(root, previous_root);
                let updated_height: u32 = freezelist_program.aleo/root_updated_height.get(ROOT_UPDATED_HEIGHT_INDEX);
                assert(updated_height + window > block.height);
            }
            
            // Fetch the correct attester key based on the local token address in the deposit input.
            let circle_attester_key: [u8; 20] = circle_attesters.get(local_token);

            // Verify the ECDSA signature using the provided message and public key.
            let is_valid: bool = ECDSA::verify_digest_eth(sig, circle_attester_key, deposit_hash);
            assert(is_valid);

            // Verify that the nullifier has not been used.
            let contains_bool: bool = nullifier.contains(nonce);
            assert(contains_bool == false);
            nullifier.set(nonce, true);
            token_future.await();
        });
    }

    // This function performs the signature verification, freeze list check, and nullifier check.
    async function finalize_verify_ecdsa_private(sig: [u8; 65], deposit_hash: [u8; 32], nonce: [u8; 32], root: field, token_future: Future) {
        // Check that the Admin has not paused the bridge.
        let is_paused: bool = paused.get_or_use(true, false);
        assert_eq(is_paused, false);

        // Check that the Merkle root is valid.
        let current_root: field = freezelist_program.aleo/freeze_list_root.get(CURRENT_FREEZE_LIST_ROOT_INDEX);
        let window: u32 = freezelist_program.aleo/block_height_window.get(BLOCK_HEIGHT_WINDOW_INDEX);

        if (current_root != root) {
            let previous_root: field = freezelist_program.aleo/freeze_list_root.get(PREVIOUS_FREEZE_LIST_ROOT_INDEX);
            assert_eq(root, previous_root);
            let updated_height: u32 = freezelist_program.aleo/root_updated_height.get(ROOT_UPDATED_HEIGHT_INDEX);
            assert(updated_height + window > block.height);
        }
        
        // Check that the Circle attester is set.  If not, use the default ETH public key.
        let circle_attester_key: [u8; 20] = circle_attester.get_or_use(true, ETH_PUBLIC_KEY);
        
        // Verify the ECDSA signature using the provided message and public key.
        let is_valid: bool = ECDSA::verify_digest_eth(sig, circle_attester_key, deposit_hash);
        assert(is_valid);

        // Verify that the nullifier has not been used.
        let contains_bool: bool = nullifier.contains(nonce);
        assert(contains_bool == false);
        nullifier.set(nonce, true);
        token_future.await();
    }

    // This method extracts the recipient address, amount, and nonce field from the payload and verifies the ECDSA signature.
    // A public freeze list check is also performed before minting public tokens to the recipient address.
    async transition mint_public(deposit_input: [u8; 240], sig: [u8; 65], digest: [u8; 32]) -> (Future) {
        // This method is  deprecated in favor of mint_public_v2.
        assert_neq(self.caller, self.caller);

        // Check the invariant conditions before proceeding with the mint.
        let (amount, recipient_address, deposit_hash, nonce) = check_mint_invariants(deposit_input, digest);

        // Call the mint public function from the Bridged USDC program.
        let mint_public_future: Future = stablecoin_program.aleo/mint_public(recipient_address, amount);
        
        // Perform the signature verification, freeze list check, and nullifier check.
        let verify_future: Future = finalize_verify_ecdsa_public(sig, deposit_hash, nonce, recipient_address, mint_public_future);

        return verify_future;
    }

    // This method extracts the recipient address, amount, and nonce field from the payload and verifies the ECDSA signature.
    // A public freeze list check is also performed before minting public tokens to the recipient address.
    async transition mint_public_v2(deposit_input: [u8; 305], sig: [u8; 65], digest: [u8; 32]) -> (address, u128, Future) {
        // Check the invariant conditions before proceeding with the mint.
        let (amount, recipient_address, deposit_hash, nonce, local_token) = check_mint_invariants_v2(deposit_input, digest);

        // Check that the flag byte is set to 0u8 for mint public.
        let flag_byte: u8 = deposit_input[240];
        assert_eq(flag_byte, 0u8);

        // Call the mint public function from the Bridged USDC program.
        let mint_public_future: Future = stablecoin_program.aleo/mint_public(recipient_address, amount);
        
        // Perform the signature verification, freeze list check, and nullifier check.
        return (recipient_address, amount, async {
            // Check that the Admin has not paused the bridge.
            let is_paused: bool = paused.get_or_use(true, false);
            assert_eq(is_paused, false);

            // Check that the recipient is not frozen in the Circle freeze list.
            let is_recipient_frozen: bool = freezelist_program.aleo/freeze_list.get_or_use(recipient_address, false);
            assert_eq(is_recipient_frozen, false);

            // Fetch the correct attester key based on the local token address in the deposit input.
            let circle_attester_key: [u8; 20] = circle_attesters.get(local_token);

            // Verify the ECDSA signature using the provided message and public key.
            let is_valid: bool = ECDSA::verify_digest_eth(sig, circle_attester_key, deposit_hash);
            assert(is_valid);

            // Verify that the nullifier has not been used.
            let contains_bool: bool = nullifier.contains(nonce);
            assert(contains_bool == false);
            nullifier.set(nonce, true);

            // Await the mint public future to complete the minting process.
            mint_public_future.await();
        });
    }

    async function finalize_verify_ecdsa_public(sig: [u8; 65], deposit_hash: [u8; 32], nonce: [u8; 32], recipient_address: address, mint_public_future: Future) {
        // Check that the Admin has not paused the bridge.
        let is_paused: bool = paused.get_or_use(true, false);
        assert_eq(is_paused, false);

        // Check that the recipient is not frozen in the Circle freeze list.
        let is_recipient_frozen: bool = freezelist_program.aleo/freeze_list.get_or_use(recipient_address, false);
        assert_eq(is_recipient_frozen, false);
        
        // Check that the Circle attester is set.  If not, use the default ETH public key.
        let circle_attester_key: [u8; 20] = circle_attester.get_or_use(true, ETH_PUBLIC_KEY);
        
        // Verify the ECDSA signature using the provided message and public key.
        let is_valid: bool = ECDSA::verify_digest_eth(sig, circle_attester_key, deposit_hash);
        assert(is_valid);

        // Verify that the nullifier has not been used.
        let contains_bool: bool = nullifier.contains(nonce);
        assert(contains_bool == false);
        nullifier.set(nonce, true);

        // Await the mint public future to complete the minting process.
        mint_public_future.await();
    }

    // Check the invariant conditions before allowing either a mint private or mint public transaction.
    inline check_mint_invariants(deposit_input: [u8; 240], digest: [u8; 32]) -> (u128, address, [u8;32], [u8; 32]) {
        // Additional invariant checks can be added here if needed in the future.
        // Ensure the deposit input starts with the expected magic value.
        let magic_value: [u8; 4] = [deposit_input[0], deposit_input[1], deposit_input[2], deposit_input[3]];
        assert(magic_value == MAGIC_VALUE);

        // // Ensure the deposit input is of the supported version.
        let version: [u8; 4] = [deposit_input[4], deposit_input[5], deposit_input[6], deposit_input[7]];
        assert(version == SUPPORTED_VERSION);

        // Extract the amount from the deposit input bytes.
        let amount_bytes: [u8; 16] = [0u8; 16];
        for i in 0u8..16u8{
            amount_bytes[i] = deposit_input[24u8 + i];
        }
        let amount: u128 = convert_bytes_to_u128(amount_bytes);
        assert(amount > 0u128);

        // Ensure the domain is correct.
        let domain: [u8; 4] = [deposit_input[40], deposit_input[41], deposit_input[42], deposit_input[43]];
        assert(domain == DOMAIN);

        // Ensure the local token contract address is not the zero address.
        let local_token_contract_address: [u8; 32] = [0u8; 32];
        for i in 0u8..32u8{
            local_token_contract_address[i] = deposit_input[108u8 + i];
        }
        assert (local_token_contract_address != [0u8; 32]);

        // Ensure the local recipient address is not the zero address.
        let local_recipient_address: [u8; 32] = [0u8; 32];
        for i in 0u8..32u8{
            local_recipient_address[i] = deposit_input[76u8 + i];
        }
        assert (local_recipient_address != [0u8; 32]);
        // Convert the local recipient address bytes to an Aleo address type.
        let recipient_address: address = convert_bytes_to_address(local_recipient_address);

        // Extract the nonce from the deposit input bytes.
        let nonce: [u8; 32] = [0u8; 32];
        for i in 0u8..32u8{
            nonce[i] = deposit_input[204u8 + i];
        }
       
        // Hash the deposit input to compare against the provided digest.
        let deposit_hash_bits = Keccak256::hash_to_bits_raw(deposit_input);
        let deposit_hash = Deserialize::from_bits_raw::[[u8; 32]](deposit_hash_bits);
        assert(deposit_hash == digest);

        return (amount, recipient_address, deposit_hash, nonce);
    }

    // Check the invariant conditions before allowing either a mint private or mint public transaction.
    inline check_mint_invariants_v2(deposit_input: [u8; 305], digest: [u8; 32]) -> (u128, address, [u8;32], [u8; 32], [u8; 32]) {
        // Additional invariant checks can be added here if needed in the future.
        // Ensure the deposit input starts with the expected magic value.
        let magic_value: [u8; 4] = [deposit_input[0], deposit_input[1], deposit_input[2], deposit_input[3]];
        assert(magic_value == MAGIC_VALUE);

        // Ensure the deposit input is of the supported version.
        let version: [u8; 4] = [deposit_input[4], deposit_input[5], deposit_input[6], deposit_input[7]];
        assert(version == SUPPORTED_VERSION);

        // Extract the amount from the deposit input bytes.
        let amount_bytes: [u8; 16] = [0u8; 16];
        
        // Check that the first 16 bytes are zero.
        for i in 0u8..16u8{
            assert_eq(deposit_input[8u8 + i], 0u8);
        }
        
        for i in 0u8..16u8{
            amount_bytes[i] = deposit_input[24u8 + i];
        }
        let amount: u128 = convert_bytes_to_u128(amount_bytes);
        assert(amount > 0u128);

        // Ensure the domain is correct.
        let domain: [u8; 4] = [deposit_input[40], deposit_input[41], deposit_input[42], deposit_input[43]];
        assert(domain == DOMAIN);

        // Ensure the local token contract address is not the zero address.
        let local_token_contract_address: [u8; 32] = [0u8; 32];
        for i in 0u8..32u8{
            local_token_contract_address[i] = deposit_input[108u8 + i];
        }
        assert (local_token_contract_address != [0u8; 32]);

        // Ensure the local recipient address is not the zero address.
        let local_recipient_address: [u8; 32] = [0u8; 32];
        for i in 0u8..32u8{
            local_recipient_address[i] = deposit_input[76u8 + i];
        }
        assert (local_recipient_address != [0u8; 32]);
        // Convert the local recipient address bytes to an Aleo address type.
        let recipient_address: address = convert_bytes_to_address(local_recipient_address);

        // Extract the nonce from the deposit input bytes.
        let nonce: [u8; 32] = [0u8; 32];
        for i in 0u8..32u8{
            nonce[i] = deposit_input[204u8 + i];
        }
       
        // Hash the deposit input to compare against the provided digest.
        let deposit_hash_bits = Keccak256::hash_to_bits_raw(deposit_input);
        let deposit_hash = Deserialize::from_bits_raw::[[u8; 32]](deposit_hash_bits);
        assert(deposit_hash == digest);

        // Ensure that the hookDataLen field is equal to 65.
        assert_eq(deposit_input[236], 0u8);
        assert_eq(deposit_input[237], 0u8);
        assert_eq(deposit_input[238], 0u8);
        assert_eq(deposit_input[239], 65u8);

        // Ensure that if the recipient address is the wrapper program for private mint,
        // then the hookData field cannot be zero.
        let hookData: [u8; 32] = [0u8; 32];
        for i in 0u32..32u32{
            hookData[i] = deposit_input[241u32 + i];
        }
        if (recipient_address == PRIVATE_MINT_WRAPPER_ADDRESS) {
            assert_eq(self.caller, PRIVATE_MINT_WRAPPER_ADDRESS);
            assert(hookData != [0u8; 32]);
        }

        return (amount, recipient_address, deposit_hash, nonce, local_token_contract_address);
    }

    // This function will no longer be used, so we force a failure with a false assertion.
    async transition burn(public amount: u128, public native_domain: u32, public native_recipient: [u8; 32]) -> Future {
        // This assert will always fail.
        assert_neq(self.caller, self.caller);
        let sender = self.caller;
        // This will make an external call to the burn_public transition in the bridged_usdc.aleo program.
        // Only the bridge program will be able to call this method on the bridged_usdc.aleo program.
        let burn_future: Future = stablecoin_program.aleo/burn_public(sender, amount);
        return async {
            // Check that the USDCX_PAUSE_KEY has not paused the bridge.
            let is_paused: bool = paused.get_or_use(true, false);
            assert_eq(is_paused, false);

            // Check that the address is not on the freeze list.
            let is_sender_frozen: bool = freezelist_program.aleo/freeze_list.get_or_use(sender, false);
            assert_eq(is_sender_frozen, false);
            burn_future.await();
        };
    }

    // Burn transactions will be fully public.  The native domain and native recipient fields are required for Circle compliance.
    async transition burn_public(public amount: u128, public native_domain: u32, public native_recipient: [u8; 32]) -> Future {
        assert(native_domain == ETH_DESTINATION_DOMAIN || native_domain == ARC_DESTINATION_DOMAIN);
        let sender = self.caller;
        // This will make an external call to the burn_public transition in the bridged_usdc.aleo program.
        // Only the bridge program will be able to call this method on the bridged_usdc.aleo program.
        let burn_future: Future = stablecoin_program.aleo/burn_public(sender, amount);
        return async {
            // Check that the USDCX_PAUSE_KEY has not paused the bridge.
            let is_paused: bool = paused.get_or_use(true, false);
            assert_eq(is_paused, false);

            // Check that the amount is above the minimum burn amount.
            let burn_threshold: u128 = minimum_burn_amount.get_or_use(true, MINIMUM_BURN_AMOUNT);
            assert(amount >= burn_threshold);

            // Check that the amount is below the maximum burn amount.
            let max_burn_amount: u128 = maximum_burn_amount.get_or_use(true, MAXIMUM_BURN_AMOUNT);
            assert(amount <= max_burn_amount);

            // Check that the address is not on the freeze list.
            let is_sender_frozen: bool = freezelist_program.aleo/freeze_list.get_or_use(sender, false);
            assert_eq(is_sender_frozen, false);
            burn_future.await();
        };
    }

    // Burn transactions will be fully public.  The native domain and native recipient fields are required for Circle compliance.
    async transition burn_public_as_signer(public amount: u128, public native_domain: u32, public native_recipient: [u8; 32]) -> Future {
        assert(native_domain == ETH_DESTINATION_DOMAIN || native_domain == ARC_DESTINATION_DOMAIN);
        let sender = self.signer;
        // This will make an external call to the burn_public transition in the bridged_usdc.aleo program.
        // Only the bridge program will be able to call this method on the bridged_usdc.aleo program.
        let burn_future: Future = stablecoin_program.aleo/burn_public(sender, amount);
        return async {
            // Check that the USDCX_PAUSE_KEY has not paused the bridge.
            let is_paused: bool = paused.get_or_use(true, false);
            assert_eq(is_paused, false);

            // Check that the amount is above the minimum burn amount.
            let burn_threshold: u128 = minimum_burn_amount.get_or_use(true, MINIMUM_BURN_AMOUNT);
            assert(amount >= burn_threshold);

            // Check that the amount is below the maximum burn amount.
            let max_burn_amount: u128 = maximum_burn_amount.get_or_use(true, MAXIMUM_BURN_AMOUNT);
            assert(amount <= max_burn_amount);

            // Check that the address is not on the freeze list.
            let is_sender_frozen: bool = freezelist_program.aleo/freeze_list.get_or_use(sender, false);
            assert_eq(is_sender_frozen, false);
            burn_future.await();
        };
    }

    async transition set_pause_status(new_status: bool) -> Future {
        assert_eq(self.caller, USDCX_PAUSE_KEY);
        return async {
            paused.set(true, new_status);
        };
    }

    async transition set_circle_attester(new_attester: [u8; 20]) -> Future {
        assert_eq(self.caller, USDCX_MANAGER_KEY);
        return async {
            circle_attester.set(true, new_attester);
        };
    }

    async transition set_attesters(local_token_address: [u8; 32], attester_public_key: [u8; 20]) -> Future {
        assert_eq(self.caller, USDCX_MANAGER_KEY);
        return async {
            circle_attesters.set(local_token_address, attester_public_key);
        };
    }

    async transition set_minimum_burn_amount(new_minimum: u128) -> Future {
        assert_eq(self.caller, USDCX_MANAGER_KEY);
        return async {
            minimum_burn_amount.set(true, new_minimum);
        };
    }

    async transition set_maximum_burn_amount(new_maximum: u128) -> Future {
        assert_eq(self.caller, USDCX_MANAGER_KEY);
        return async {
            maximum_burn_amount.set(true, new_maximum);
        };
    }

    inline convert_bytes_to_u128(amount: [u8; 16]) -> u128 {
        let sum: u128 = 0;
        for i in 0u8..16u8 {
            sum = sum + (amount[i] as u128) * (2u128.pow(8u32 * (15u32 - (i as u32))) as u128);
        }
        return sum;
    }

    inline convert_bytes_to_address(address_bytes: [u8; 32]) -> address {
        let address_bits = Serialize::to_bits_raw(address_bytes);
        let sliced_bits = [false; 253];
        for i in 0u8..253u8 {
            sliced_bits[i] = address_bits[i];
        }
        for i in 0u8..3u8 {
            assert_eq(address_bits[253u8 + i], false);
        }
        let recipient_address: address = Deserialize::from_bits_raw::[address](sliced_bits);
        return recipient_address;
    }

    transition address_to_bytes_raw(a: address) -> [u8; 32] {
        let bits = Serialize::to_bits_raw(a);
        let padded_bits = [false; 256];
        for i in 0u8..253u8 {
            padded_bits[i] = bits[i];
        }
        return Deserialize::from_bits_raw::[[u8; 32]](padded_bits);
    }

    // Calculates the hash of two sibling nodes in a Merkle tree.
    // The order of the siblings depends on the index bit (0 = left, 1 = right).
    // Uses Poseidon hash to compute the result.
    inline calculate_hash_for_nodes(sibling1: field, sibling2: field, indexbit: u32) -> field {
        let poseidon_params: [field; 3] = indexbit == 0u32 ? [0field, sibling1, sibling2] : [0field, sibling2, sibling1];
        return Poseidon4::hash_to_field(poseidon_params);
    }

    inline calculate_hash_for_leaves(sibling1: field, sibling2: field, indexbit: u32) -> field {
        let poseidon_params: [field; 3] = indexbit == 0u32 ? [1field, sibling1, sibling2] : [1field, sibling2, sibling1];
        return Poseidon4::hash_to_field(poseidon_params);
    }

    // Calculates the Merkle root and the depth of a Merkle proof path.
    // Iteratively hashes the sibling path based on the leaf index to reconstruct the root.
    // Stops when a zero field is encountered in the siblings array, indicating the end of the valid path.
    // Returns the calculated root and the actual depth reached.
    inline calculate_root_depth_siblings(merkle_proof: stablecoin_program.aleo/MerkleProof) -> (public field, public u32) {
        let root: field = calculate_hash_for_leaves(merkle_proof.siblings[0u8], merkle_proof.siblings[1u8],  merkle_proof.leaf_index % 2u32);
        for i: u32 in 2u32..MAX_TREE_DEPTH + 1u32 {
            if (merkle_proof.siblings[i] == 0field) {
                return (root, i - 1u32);
            }
            root = calculate_hash_for_nodes(root, merkle_proof.siblings[i], (merkle_proof.leaf_index / (2u32**(i-1u32))) % 2u32);
        }
        return (root, MAX_TREE_DEPTH);
    }

    // Verifies non-inclusion of an address in a Merkle tree sorted in ascending order by address (as field).
    // Accepts two Merkle proofs representing the neighboring leaves around the missing address.
    // Returns the common Merkle root if the address is proven to be outside the tree.
    // If the tree is not sorted correctly, this function may return incorrect results.
    inline verify_non_inclusion_private(addr: address, merkle_proofs: [stablecoin_program.aleo/MerkleProof;2]) -> field {
        let (root1, depth1): (field, u32)= calculate_root_depth_siblings(merkle_proofs[0u32]);
        let (root2, depth2): (field, u32) = calculate_root_depth_siblings(merkle_proofs[1u32]);

        // Ensure the roots from the merkle proofs are the same.
        assert_eq(root1, root2);
        // Ensure the depth of the merkle proofs is the same
        assert_eq(depth1, depth2);
        
        let addr_field: field = addr as field;
        if (merkle_proofs[0u32].leaf_index == merkle_proofs[1u32].leaf_index) {
            // Ensure that if the address is the most left leaf, it is less than the first sibling.
            if (merkle_proofs[0u32].leaf_index == 0u32) {
                assert(addr_field < merkle_proofs[0u32].siblings[0u32]);
            } else {
                // Ensure that if the address is the most right leaf.
                let last_index_leaf: u32 = 2u32 ** depth1 - 1u32;
                assert_eq(merkle_proofs[0u32].leaf_index, last_index_leaf);
                // Ensure that the address is bigger than the first sibling.
                assert(addr_field > merkle_proofs[0u32].siblings[0u32]);
            }
        } else {
            // Ensure the address is in between the provided leaves.
            assert(addr_field > merkle_proofs[0u32].siblings[0u32]);
            assert(addr_field < merkle_proofs[1u32].siblings[0u32]);
            // Ensure that the leaf indexes are not greater than the last possible leaf index.
            let last_index_leaf: u32 = 2u32 ** depth1 - 1u32;
            assert(merkle_proofs[1u32].leaf_index <= last_index_leaf);
            // Ensure the leaves are adjacent.
            assert_eq(merkle_proofs[0u32].leaf_index + 1u32, merkle_proofs[1u32].leaf_index);
        }
        
        return root1;
    }
}