// SPDX-License-Identifier: CC0-1.0

use std::str::FromStr;

use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Keypair, PublicKey as SecpPublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::{
    absolute, transaction, Amount, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
};
use miniscript::plan::Assets;
use miniscript::psbt::{self, InputError, PsbtExt, PsbtInputExt};
use miniscript::{DefiniteDescriptorKey, Descriptor, DescriptorPublicKey, Error};

fn signing_keys(count: u8) -> Vec<(SecretKey, PublicKey)> {
    let secp = Secp256k1::new();
    (1..=count)
        .map(|index| {
            let secret = SecretKey::from_slice(&[index; 32]).unwrap();
            let public = PublicKey::new(SecpPublicKey::from_secret_key(&secp, &secret));
            (secret, public)
        })
        .collect()
}

fn signature_chain(keys: &[(SecretKey, PublicKey)]) -> String {
    let mut script = format!("pk({})", keys.last().unwrap().1);
    for (_, key) in keys[..keys.len() - 1].iter().rev() {
        script = format!("and_v(v:pk({}),{})", key, script);
    }
    script
}

fn psbt_for_descriptor(descriptor: &Descriptor<DefiniteDescriptorKey>) -> Psbt {
    let transaction = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn { sequence: Sequence::from_height(1), ..Default::default() }],
        output: vec![TxOut { value: Amount::from_sat(9_000), script_pubkey: ScriptBuf::new() }],
    };
    let mut psbt = Psbt::from_unsigned_tx(transaction).unwrap();
    psbt.inputs[0].witness_utxo =
        Some(TxOut { value: Amount::from_sat(10_000), script_pubkey: descriptor.script_pubkey() });
    psbt.inputs[0]
        .update_with_descriptor_unchecked(descriptor)
        .unwrap();
    psbt
}

#[test]
fn descriptor_plans_deep_signature_chains() {
    for (taproot, depth) in [(false, 32), (true, 100)] {
        let keys = signing_keys((depth + 2) as u8);
        let script = signature_chain(&keys[..depth + 1]);
        let descriptor = if taproot {
            format!("tr({},{})", keys[depth + 1].1, script)
        } else {
            format!("wsh({})", script)
        };
        let descriptor = Descriptor::<DefiniteDescriptorKey>::from_str(&descriptor).unwrap();
        descriptor.sanity_check().unwrap();
        let assets = Assets::new().add(
            keys[..depth + 1]
                .iter()
                .map(|(_, key)| DescriptorPublicKey::from_str(&key.to_string()).unwrap())
                .collect::<Vec<_>>(),
        );

        assert_eq!(descriptor.clone().plan(&Assets::new()).unwrap_err(), descriptor);
        assert_eq!(descriptor.clone().plan_mall(&Assets::new()).unwrap_err(), descriptor);
        for plan in [
            descriptor.clone().plan(&assets),
            descriptor.clone().plan_mall(&assets),
        ] {
            let plan = plan.unwrap();
            assert_eq!(plan.witness_template().len(), depth + 1 + if taproot { 2 } else { 0 });
            assert_eq!(plan.absolute_timelock, None);
            assert_eq!(plan.relative_timelock, None);
            let mut input = bitcoin::psbt::Input::default();
            plan.update_psbt_input(&mut input);
            if taproot {
                assert_eq!(input.tap_scripts.len(), 1);
                assert!(input.tap_internal_key.is_none());
            } else {
                assert_eq!(input.witness_script, Some(descriptor.explicit_script().unwrap()));
            }
        }
    }
}

#[test]
fn descriptor_plans_bounded_branching_chain() {
    let keys = signing_keys(10);
    let mut script = format!("pk({})", keys[8].1);
    for (_, key) in keys[..8].iter().rev() {
        script = format!("or_d(pk({}),{})", key, script);
    }
    for descriptor in [
        format!("wsh({})", script),
        format!("tr({},{})", keys[9].1, script),
    ] {
        let descriptor = Descriptor::<DefiniteDescriptorKey>::from_str(&descriptor).unwrap();
        let assets =
            Assets::new().add(DescriptorPublicKey::from_str(&keys[0].1.to_string()).unwrap());
        assert_eq!(descriptor.clone().plan(&Assets::new()).unwrap_err(), descriptor);
        assert_eq!(descriptor.clone().plan_mall(&Assets::new()).unwrap_err(), descriptor);
        let plan = descriptor.clone().plan(&assets).unwrap();
        let malleable_plan = descriptor.plan_mall(&assets).unwrap();
        assert_eq!(plan.witness_template(), malleable_plan.witness_template());
        assert_eq!(
            plan.witness_template().len(),
            if plan.witness_version() == Some(bitcoin::WitnessVersion::V1) {
                3
            } else {
                1
            }
        );
    }
}

#[test]
fn psbt_finalize_deep_signed_chains() {
    let secp = Secp256k1::new();
    for (taproot, depth) in [(false, 32), (true, 100)] {
        let keys = signing_keys((depth + 2) as u8);
        let script = signature_chain(&keys[..depth + 1]);
        let descriptor = if taproot {
            format!("tr({},{})", keys[depth + 1].1, script)
        } else {
            format!("wsh({})", script)
        };
        let descriptor = Descriptor::<DefiniteDescriptorKey>::from_str(&descriptor).unwrap();
        let mut psbt = psbt_for_descriptor(&descriptor);
        let (script, control_block) = if taproot {
            let (control_block, (script, version)) =
                psbt.inputs[0].tap_scripts.iter().next().unwrap();
            assert_eq!(*version, LeafVersion::TapScript);
            (script.clone(), Some(control_block.serialize()))
        } else {
            (psbt.inputs[0].witness_script.clone().unwrap(), None)
        };
        let leaf_hash = if taproot {
            Some(TapLeafHash::from_script(&script, LeafVersion::TapScript))
        } else {
            None
        };

        let (unfinalized, errors) = psbt.clone().finalize(&secp).unwrap_err();
        assert_eq!(unfinalized, psbt);
        assert_eq!(errors.len(), 1);
        if taproot {
            assert!(matches!(errors[0], psbt::Error::InputError(InputError::CouldNotSatisfyTr, 0)));
        } else {
            assert!(matches!(
                errors[0],
                psbt::Error::InputError(InputError::MiniscriptError(Error::CouldNotSatisfy), 0)
            ));
        }

        let message = psbt
            .sighash_msg(0, &mut SighashCache::new(&psbt.unsigned_tx), leaf_hash)
            .unwrap()
            .to_secp_msg();
        let mut signatures = Vec::new();
        for (secret, public) in &keys[..depth + 1] {
            let signature = if let Some(leaf_hash) = leaf_hash {
                let keypair = Keypair::from_secret_key(&secp, secret);
                let signature = bitcoin::taproot::Signature {
                    signature: secp.sign_schnorr_no_aux_rand(&message, &keypair),
                    sighash_type: TapSighashType::Default,
                };
                psbt.inputs[0]
                    .tap_script_sigs
                    .insert((public.inner.x_only_public_key().0, leaf_hash), signature);
                signature.to_vec()
            } else {
                let signature = bitcoin::ecdsa::Signature {
                    signature: secp.sign_ecdsa(&message, secret),
                    sighash_type: EcdsaSighashType::All,
                };
                psbt.inputs[0].partial_sigs.insert(*public, signature);
                signature.to_vec()
            };
            signatures.push(signature);
        }
        signatures.reverse();
        signatures.push(script.into_bytes());
        if let Some(control_block) = control_block {
            signatures.push(control_block);
        }

        for finalized in [psbt.clone().finalize(&secp), psbt.finalize_mall(&secp)] {
            let finalized = finalized.unwrap();
            assert!(finalized.inputs[0].final_script_sig.is_none());
            assert_eq!(
                finalized.inputs[0]
                    .final_script_witness
                    .as_ref()
                    .unwrap()
                    .to_vec(),
                signatures
            );
            finalized.extract(&secp).unwrap();
        }
    }
}

#[test]
fn over_op_limit_wsh_is_rejected_with_sufficient_assets() {
    let keys = signing_keys(1);
    let mut script = format!("pk({})", keys[0].1);
    // Each verified CSV adds two counted opcodes; the final CHECKSIG adds one.
    for _ in 0..101 {
        script = format!("and_v(v:older(1),{})", script);
    }
    let descriptor =
        Descriptor::<DefiniteDescriptorKey>::from_str(&format!("wsh({})", script)).unwrap();
    let assets = Assets::new()
        .add(DescriptorPublicKey::from_str(&keys[0].1.to_string()).unwrap())
        .older(Sequence::from_height(1).to_relative_lock_time().unwrap());
    assert_eq!(descriptor.clone().plan(&assets).unwrap_err(), descriptor);
    assert_eq!(descriptor.clone().plan_mall(&assets).unwrap_err(), descriptor);

    let secp = Secp256k1::new();
    let mut psbt = psbt_for_descriptor(&descriptor);
    let message = psbt
        .sighash_msg(0, &mut SighashCache::new(&psbt.unsigned_tx), None)
        .unwrap()
        .to_secp_msg();
    psbt.inputs[0].partial_sigs.insert(
        keys[0].1,
        bitcoin::ecdsa::Signature {
            signature: secp.sign_ecdsa(&message, &keys[0].0),
            sighash_type: EcdsaSighashType::All,
        },
    );
    for result in [
        psbt.clone().finalize(&secp),
        psbt.clone().finalize_mall(&secp),
    ] {
        let (unfinalized, errors) = result.unwrap_err();
        assert_eq!(unfinalized, psbt);
        assert_eq!(errors.len(), 1);
        assert!(matches!(
            errors[0],
            psbt::Error::InputError(InputError::MiniscriptError(Error::ContextError(_)), 0)
        ));
    }
}

#[test]
fn repeated_subtree_consumers_report_missing_signatures() {
    let keys = signing_keys(8);
    let mut script = format!("pk({})", keys[0].1);
    // Keep the consumer fixture small; provider-call tests enforce the complexity bound.
    for (_, key) in &keys[1..7] {
        script = format!("or_b(utv:{},s:pk({}))", script, key);
    }
    let secp = Secp256k1::verification_only();
    for (taproot, descriptor) in [
        (false, format!("wsh({})", script)),
        (true, format!("tr({},{})", keys[7].1, script)),
    ] {
        let descriptor = Descriptor::<DefiniteDescriptorKey>::from_str(&descriptor).unwrap();
        descriptor.sanity_check().unwrap();
        assert_eq!(descriptor.clone().plan(&Assets::new()).unwrap_err(), descriptor);
        assert_eq!(descriptor.clone().plan_mall(&Assets::new()).unwrap_err(), descriptor);

        let psbt = psbt_for_descriptor(&descriptor);
        assert!(psbt.inputs[0].partial_sigs.is_empty());
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());
        if taproot {
            assert_eq!(psbt.inputs[0].tap_scripts.len(), 1);
        } else {
            assert_eq!(psbt.inputs[0].witness_script, Some(descriptor.explicit_script().unwrap()));
        }
        for result in [
            psbt.clone().finalize(&secp),
            psbt.clone().finalize_mall(&secp),
        ] {
            let (unfinalized, errors) = result.unwrap_err();
            assert_eq!(unfinalized, psbt);
            assert_eq!(errors.len(), 1);
            if taproot {
                assert!(matches!(
                    errors[0],
                    psbt::Error::InputError(InputError::CouldNotSatisfyTr, 0)
                ));
            } else {
                assert!(matches!(
                    errors[0],
                    psbt::Error::InputError(InputError::MiniscriptError(Error::CouldNotSatisfy), 0)
                ));
            }
        }
    }
}
