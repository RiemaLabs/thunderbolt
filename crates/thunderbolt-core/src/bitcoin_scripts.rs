#[allow(unused_imports)]
use bitcoin::{
    key::Secp256k1,
    opcodes::{
        all::{
            OP_CHECKMULTISIG, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_DUP, OP_GREATERTHANOREQUAL, OP_ROLL, OP_ROT, OP_SWAP,
            OP_VERIFY,
        },
        OP_TRUE,
    },
    taproot::{ControlBlock, LeafVersion, TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf, XOnlyPublicKey,
};
use bitcoin::{opcodes::all::OP_CHECKSIGADD, script::Builder};
use std::{str::FromStr, sync::LazyLock};

// TODO: Generate this key using a public method to prove it is not held by Nubit team.
// Refer to: https://github.com/BitVM/BitVM/blob/main/bridge/src/scripts.rs#L15
pub static UNSPENDABLE_TAPROOT_PUBLIC_KEY: LazyLock<XOnlyPublicKey> = LazyLock::new(|| {
    XOnlyPublicKey::from_str("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0").unwrap()
});

pub fn gen_prepare_lock_script(user_pubkey: &XOnlyPublicKey, committee_pubkey: &XOnlyPublicKey) -> ScriptBuf {
    let mut builder = Builder::new();
    builder = builder
        .push_int(0) // 0
        .push_x_only_key(user_pubkey)
        .push_opcode(OP_CHECKSIGADD)
        .push_x_only_key(committee_pubkey)
        .push_opcode(OP_CHECKSIGADD)
        .push_int(2)
        .push_opcode(OP_GREATERTHANOREQUAL);
    builder.into_script()
}

pub fn gen_prepare_taproot(
    user_pubkey: &XOnlyPublicKey,
    committee_pubkey: &XOnlyPublicKey,
) -> (TaprootSpendInfo, ScriptBuf, ControlBlock) {
    let branch_0 = gen_prepare_lock_script(user_pubkey, committee_pubkey);
    let taproot = TaprootBuilder::new()
        .add_leaf(0, branch_0.clone())
        .expect("Unable to add leaf 0")
        .finalize(&Secp256k1::new(), UNSPENDABLE_TAPROOT_PUBLIC_KEY.clone())
        .expect("Unable to finalize taproot");
    let control_block_0 = taproot
        .control_block(&(branch_0.clone(), LeafVersion::TapScript))
        .expect("Unable to create control block");
    (taproot, branch_0, control_block_0)
}
