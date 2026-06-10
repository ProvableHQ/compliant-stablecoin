import multisig_core.aleo;
import merkle_tree.aleo;
import freezelist_program.aleo;
import stablecoin_program.aleo;
program stablecoin_bridge.aleo;

struct ChecksumEdition:
    checksum as [u8; 32u32];
    edition as u16;

mapping circle_attester:
    key as boolean.public;
    value as [u8; 20u32].public;

mapping minimum_burn_amount:
    key as boolean.public;
    value as u128.public;

mapping nullifier:
    key as [u8; 32u32].public;
    value as boolean.public;

mapping paused:
    key as boolean.public;
    value as boolean.public;

function get_signing_op_id_for_deploy:
    input r0 as [u8; 32u32].private;
    input r1 as u16.private;
    cast r0 r1 into r2 as ChecksumEdition;
    hash.bhp256 r2 into r3 as field;
    output r3 as field.private;

closure check_mint_invariants:
    input r0 as [u8; 240u32];
    input r1 as [u8; 32u32];
    cast r0[0u32] r0[1u32] r0[2u32] r0[3u32] into r2 as [u8; 4u32];
    cast 90u8 46u8 10u8 205u8 into r3 as [u8; 4u32];
    is.eq r2 r3 into r4;
    assert.eq r4 true;
    cast r0[4u32] r0[5u32] r0[6u32] r0[7u32] into r5 as [u8; 4u32];
    cast 0u8 0u8 0u8 1u8 into r6 as [u8; 4u32];
    is.eq r5 r6 into r7;
    assert.eq r7 true;
    cast r0[24u32] r0[25u32] r0[26u32] r0[27u32] r0[28u32] r0[29u32] r0[30u32] r0[31u32] r0[32u32] r0[33u32] r0[34u32] r0[35u32] r0[36u32] r0[37u32] r0[38u32] r0[39u32] into r8 as [u8; 16u32];
    cast r8[0u32] into r9 as u128;
    mul r9 1329227995784915872903807060280344576u128 into r10;
    cast r8[1u32] into r11 as u128;
    mul r11 5192296858534827628530496329220096u128 into r12;
    add r10 r12 into r13;
    cast r8[2u32] into r14 as u128;
    mul r14 20282409603651670423947251286016u128 into r15;
    add r13 r15 into r16;
    cast r8[3u32] into r17 as u128;
    mul r17 79228162514264337593543950336u128 into r18;
    add r16 r18 into r19;
    cast r8[4u32] into r20 as u128;
    mul r20 309485009821345068724781056u128 into r21;
    add r19 r21 into r22;
    cast r8[5u32] into r23 as u128;
    mul r23 1208925819614629174706176u128 into r24;
    add r22 r24 into r25;
    cast r8[6u32] into r26 as u128;
    mul r26 4722366482869645213696u128 into r27;
    add r25 r27 into r28;
    cast r8[7u32] into r29 as u128;
    mul r29 18446744073709551616u128 into r30;
    add r28 r30 into r31;
    cast r8[8u32] into r32 as u128;
    mul r32 72057594037927936u128 into r33;
    add r31 r33 into r34;
    cast r8[9u32] into r35 as u128;
    mul r35 281474976710656u128 into r36;
    add r34 r36 into r37;
    cast r8[10u32] into r38 as u128;
    mul r38 1099511627776u128 into r39;
    add r37 r39 into r40;
    cast r8[11u32] into r41 as u128;
    mul r41 4294967296u128 into r42;
    add r40 r42 into r43;
    cast r8[12u32] into r44 as u128;
    mul r44 16777216u128 into r45;
    add r43 r45 into r46;
    cast r8[13u32] into r47 as u128;
    mul r47 65536u128 into r48;
    add r46 r48 into r49;
    cast r8[14u32] into r50 as u128;
    mul r50 256u128 into r51;
    add r49 r51 into r52;
    cast r8[15u32] into r53 as u128;
    add r52 r53 into r54;
    gt r54 0u128 into r55;
    assert.eq r55 true;
    cast r0[40u32] r0[41u32] r0[42u32] r0[43u32] into r56 as [u8; 4u32];
    cast 0u8 0u8 39u8 18u8 into r57 as [u8; 4u32];
    is.eq r56 r57 into r58;
    assert.eq r58 true;
    cast 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 into r59 as [u8; 32u32];
    cast r0[108u32] r0[109u32] r0[110u32] r0[111u32] r0[112u32] r0[113u32] r0[114u32] r0[115u32] r0[116u32] r0[117u32] r0[118u32] r0[119u32] r0[120u32] r0[121u32] r0[122u32] r0[123u32] r0[124u32] r0[125u32] r0[126u32] r0[127u32] r0[128u32] r0[129u32] r0[130u32] r0[131u32] r0[132u32] r0[133u32] r0[134u32] r0[135u32] r0[136u32] r0[137u32] r0[138u32] r0[139u32] into r60 as [u8; 32u32];
    is.neq r60 r59 into r61;
    assert.eq r61 true;
    cast r0[76u32] r0[77u32] r0[78u32] r0[79u32] r0[80u32] r0[81u32] r0[82u32] r0[83u32] r0[84u32] r0[85u32] r0[86u32] r0[87u32] r0[88u32] r0[89u32] r0[90u32] r0[91u32] r0[92u32] r0[93u32] r0[94u32] r0[95u32] r0[96u32] r0[97u32] r0[98u32] r0[99u32] r0[100u32] r0[101u32] r0[102u32] r0[103u32] r0[104u32] r0[105u32] r0[106u32] r0[107u32] into r62 as [u8; 32u32];
    is.neq r62 r59 into r63;
    assert.eq r63 true;
    serialize.bits.raw r62 ([u8; 32u32]) into r64 ([boolean; 256u32]);
    cast r64[0u32] r64[1u32] r64[2u32] r64[3u32] r64[4u32] r64[5u32] r64[6u32] r64[7u32] r64[8u32] r64[9u32] r64[10u32] r64[11u32] r64[12u32] r64[13u32] r64[14u32] r64[15u32] r64[16u32] r64[17u32] r64[18u32] r64[19u32] r64[20u32] r64[21u32] r64[22u32] r64[23u32] r64[24u32] r64[25u32] r64[26u32] r64[27u32] r64[28u32] r64[29u32] r64[30u32] r64[31u32] r64[32u32] r64[33u32] r64[34u32] r64[35u32] r64[36u32] r64[37u32] r64[38u32] r64[39u32] r64[40u32] r64[41u32] r64[42u32] r64[43u32] r64[44u32] r64[45u32] r64[46u32] r64[47u32] r64[48u32] r64[49u32] r64[50u32] r64[51u32] r64[52u32] r64[53u32] r64[54u32] r64[55u32] r64[56u32] r64[57u32] r64[58u32] r64[59u32] r64[60u32] r64[61u32] r64[62u32] r64[63u32] r64[64u32] r64[65u32] r64[66u32] r64[67u32] r64[68u32] r64[69u32] r64[70u32] r64[71u32] r64[72u32] r64[73u32] r64[74u32] r64[75u32] r64[76u32] r64[77u32] r64[78u32] r64[79u32] r64[80u32] r64[81u32] r64[82u32] r64[83u32] r64[84u32] r64[85u32] r64[86u32] r64[87u32] r64[88u32] r64[89u32] r64[90u32] r64[91u32] r64[92u32] r64[93u32] r64[94u32] r64[95u32] r64[96u32] r64[97u32] r64[98u32] r64[99u32] r64[100u32] r64[101u32] r64[102u32] r64[103u32] r64[104u32] r64[105u32] r64[106u32] r64[107u32] r64[108u32] r64[109u32] r64[110u32] r64[111u32] r64[112u32] r64[113u32] r64[114u32] r64[115u32] r64[116u32] r64[117u32] r64[118u32] r64[119u32] r64[120u32] r64[121u32] r64[122u32] r64[123u32] r64[124u32] r64[125u32] r64[126u32] r64[127u32] r64[128u32] r64[129u32] r64[130u32] r64[131u32] r64[132u32] r64[133u32] r64[134u32] r64[135u32] r64[136u32] r64[137u32] r64[138u32] r64[139u32] r64[140u32] r64[141u32] r64[142u32] r64[143u32] r64[144u32] r64[145u32] r64[146u32] r64[147u32] r64[148u32] r64[149u32] r64[150u32] r64[151u32] r64[152u32] r64[153u32] r64[154u32] r64[155u32] r64[156u32] r64[157u32] r64[158u32] r64[159u32] r64[160u32] r64[161u32] r64[162u32] r64[163u32] r64[164u32] r64[165u32] r64[166u32] r64[167u32] r64[168u32] r64[169u32] r64[170u32] r64[171u32] r64[172u32] r64[173u32] r64[174u32] r64[175u32] r64[176u32] r64[177u32] r64[178u32] r64[179u32] r64[180u32] r64[181u32] r64[182u32] r64[183u32] r64[184u32] r64[185u32] r64[186u32] r64[187u32] r64[188u32] r64[189u32] r64[190u32] r64[191u32] r64[192u32] r64[193u32] r64[194u32] r64[195u32] r64[196u32] r64[197u32] r64[198u32] r64[199u32] r64[200u32] r64[201u32] r64[202u32] r64[203u32] r64[204u32] r64[205u32] r64[206u32] r64[207u32] r64[208u32] r64[209u32] r64[210u32] r64[211u32] r64[212u32] r64[213u32] r64[214u32] r64[215u32] r64[216u32] r64[217u32] r64[218u32] r64[219u32] r64[220u32] r64[221u32] r64[222u32] r64[223u32] r64[224u32] r64[225u32] r64[226u32] r64[227u32] r64[228u32] r64[229u32] r64[230u32] r64[231u32] r64[232u32] r64[233u32] r64[234u32] r64[235u32] r64[236u32] r64[237u32] r64[238u32] r64[239u32] r64[240u32] r64[241u32] r64[242u32] r64[243u32] r64[244u32] r64[245u32] r64[246u32] r64[247u32] r64[248u32] r64[249u32] r64[250u32] r64[251u32] r64[252u32] into r65 as [boolean; 253u32];
    deserialize.bits.raw r65 ([boolean; 253u32]) into r66 (address);
    hash.keccak256.native.raw r0 into r67 as [boolean; 256u32];
    deserialize.bits.raw r67 ([boolean; 256u32]) into r68 ([u8; 32u32]);
    is.eq r68 r1 into r69;
    assert.eq r69 true;
    cast r0[204u32] r0[205u32] r0[206u32] r0[207u32] r0[208u32] r0[209u32] r0[210u32] r0[211u32] r0[212u32] r0[213u32] r0[214u32] r0[215u32] r0[216u32] r0[217u32] r0[218u32] r0[219u32] r0[220u32] r0[221u32] r0[222u32] r0[223u32] r0[224u32] r0[225u32] r0[226u32] r0[227u32] r0[228u32] r0[229u32] r0[230u32] r0[231u32] r0[232u32] r0[233u32] r0[234u32] r0[235u32] into r70 as [u8; 32u32];
    output r54 as u128;
    output r66 as address;
    output r68 as [u8; 32u32];
    output r70 as [u8; 32u32];

function mint_private:
    input r0 as [u8; 240u32].private;
    input r1 as [u8; 65u32].private;
    input r2 as [u8; 32u32].private;
    input r3 as [merkle_tree.aleo/MerkleProof; 2u32].private;
    call check_mint_invariants r0 r2 into r4 r5 r6 r7;
    call merkle_tree.aleo/verify_non_inclusion r5 r3 into r8;
    call stablecoin_program.aleo/mint_private r5 r4 into r9 r10 r11;
    async mint_private r1 r6 r7 r8 r11 into r12;
    output r9 as stablecoin_program.aleo/ComplianceRecord.record;
    output r10 as stablecoin_program.aleo/Token.record;
    output r12 as stablecoin_bridge.aleo/mint_private.future;

finalize mint_private:
    input r0 as [u8; 65u32].public;
    input r1 as [u8; 32u32].public;
    input r2 as [u8; 32u32].public;
    input r3 as field.public;
    input r4 as stablecoin_program.aleo/mint_private.future;
    get.or_use paused[true] false into r5;
    assert.eq r5 false;
    get freezelist_program.aleo/freeze_list_root[1u8] into r6;
    get freezelist_program.aleo/block_height_window[true] into r7;
    is.neq r6 r3 into r8;
    branch.eq r8 false to end_then_0_0;
    get freezelist_program.aleo/freeze_list_root[2u8] into r9;
    assert.eq r3 r9;
    get freezelist_program.aleo/root_updated_height[true] into r10;
    add r10 r7 into r11;
    gt r11 block.height into r12;
    assert.eq r12 true;
    branch.eq true true to end_otherwise_0_1;
    position end_then_0_0;
    position end_otherwise_0_1;
    cast 252u8 83u8 188u8 10u8 12u8 182u8 237u8 57u8 194u8 0u8 45u8 226u8 77u8 10u8 169u8 81u8 124u8 122u8 66u8 198u8 into r13 as [u8; 20u32];
    get.or_use circle_attester[true] r13 into r14;
    ecdsa.verify.digest.eth r0 r14 r1 into r15;
    assert.eq r15 true;
    contains nullifier[r2] into r16;
    is.eq r16 false into r17;
    assert.eq r17 true;
    set true into nullifier[r2];
    await r4;

function mint_public:
    input r0 as [u8; 240u32].private;
    input r1 as [u8; 65u32].private;
    input r2 as [u8; 32u32].private;
    call check_mint_invariants r0 r2 into r3 r4 r5 r6;
    call stablecoin_program.aleo/mint_public r4 r3 into r7;
    async mint_public r1 r5 r6 r4 r7 into r8;
    output r8 as stablecoin_bridge.aleo/mint_public.future;

finalize mint_public:
    input r0 as [u8; 65u32].public;
    input r1 as [u8; 32u32].public;
    input r2 as [u8; 32u32].public;
    input r3 as address.public;
    input r4 as stablecoin_program.aleo/mint_public.future;
    get.or_use paused[true] false into r5;
    assert.eq r5 false;
    get.or_use freezelist_program.aleo/freeze_list[r3] false into r6;
    assert.eq r6 false;
    cast 252u8 83u8 188u8 10u8 12u8 182u8 237u8 57u8 194u8 0u8 45u8 226u8 77u8 10u8 169u8 81u8 124u8 122u8 66u8 198u8 into r7 as [u8; 20u32];
    get.or_use circle_attester[true] r7 into r8;
    ecdsa.verify.digest.eth r0 r8 r1 into r9;
    assert.eq r9 true;
    contains nullifier[r2] into r10;
    is.eq r10 false into r11;
    assert.eq r11 true;
    set true into nullifier[r2];
    await r4;

function burn:
    input r0 as u128.public;
    input r1 as u32.public;
    input r2 as [u8; 32u32].public;
    assert.neq self.caller self.caller;
    call stablecoin_program.aleo/burn_public self.caller r0 into r3;
    async burn self.caller r3 into r4;
    output r4 as stablecoin_bridge.aleo/burn.future;

finalize burn:
    input r0 as address.public;
    input r1 as stablecoin_program.aleo/burn_public.future;
    get.or_use paused[true] false into r2;
    assert.eq r2 false;
    get.or_use freezelist_program.aleo/freeze_list[r0] false into r3;
    assert.eq r3 false;
    await r1;

function burn_public:
    input r0 as u128.public;
    input r1 as u32.public;
    input r2 as [u8; 32u32].public;
    call stablecoin_program.aleo/burn_public self.caller r0 into r3;
    async burn_public r0 self.caller r3 into r4;
    output r4 as stablecoin_bridge.aleo/burn_public.future;

finalize burn_public:
    input r0 as u128.public;
    input r1 as address.public;
    input r2 as stablecoin_program.aleo/burn_public.future;
    get.or_use paused[true] false into r3;
    assert.eq r3 false;
    get.or_use minimum_burn_amount[true] 5000000u128 into r4;
    gte r0 r4 into r5;
    assert.eq r5 true;
    get.or_use freezelist_program.aleo/freeze_list[r1] false into r6;
    assert.eq r6 false;
    await r2;

function set_pause_status:
    input r0 as boolean.private;
    assert.eq self.caller aleo16s9af9darj0j5k7fpaxjq0u9fepd6sc4svrkr9vs4d3wlmp5lqyq4h3fpl;
    async set_pause_status r0 into r1;
    output r1 as stablecoin_bridge.aleo/set_pause_status.future;

finalize set_pause_status:
    input r0 as boolean.public;
    set r0 into paused[true];

function set_circle_attester:
    input r0 as [u8; 20u32].private;
    assert.eq self.caller aleo13zt4uq0u09sffnf4ctgu47k5n30txjx2w9cwcqgneapjeqsywsqqu6hspt;
    async set_circle_attester r0 into r1;
    output r1 as stablecoin_bridge.aleo/set_circle_attester.future;

finalize set_circle_attester:
    input r0 as [u8; 20u32].public;
    set r0 into circle_attester[true];

function set_minimum_burn_amount:
    input r0 as u128.private;
    assert.eq self.caller aleo13zt4uq0u09sffnf4ctgu47k5n30txjx2w9cwcqgneapjeqsywsqqu6hspt;
    async set_minimum_burn_amount r0 into r1;
    output r1 as stablecoin_bridge.aleo/set_minimum_burn_amount.future;

finalize set_minimum_burn_amount:
    input r0 as u128.public;
    set r0 into minimum_burn_amount[true];

constructor:
    gt edition 0u16 into r0;
    branch.eq r0 false to end_then_0_0;
    cast checksum edition into r1 as ChecksumEdition;
    hash.bhp256 r1 into r2 as field;
    cast stablecoin_bridge.aleo r2 into r3 as multisig_core.aleo/WalletSigningOpId;
    hash.bhp256 r3 into r4 as field;
    contains multisig_core.aleo/completed_signing_ops[r4] into r5;
    assert.eq r5 true;
    branch.eq true true to end_otherwise_0_1;
    position end_then_0_0;
    position end_otherwise_0_1;
