use std::sync::Arc;

use axon_protocol::types::{Bytes, Hasher as AxonHasher};
use cita_trie::{MemoryDB, PatriciaTrie, Trie, DB};
use common_crypto::{BlsPublicKey, BlsSignature, BlsSignatureVerify, HashValue};
use hasher::{Hasher, HasherKeccak};
use ibc::core::{
    ics02_client::error::Error as Ics02Error,
    ics23_commitment::commitment::{CommitmentPrefix, CommitmentProofBytes, CommitmentRoot},
    ics24_host::Path,
};
use ibc_proto::ibc::core::commitment::v1::MerkleProof as RawMerkleProof;
use ibc_proto::ics23::commitment_proof::Proof;
use overlord::types::{Vote, VoteType};

use crate::header::Header;

// core/consensus/src/adapter.rs: 431L
pub(crate) fn verify_header(header: &Header) -> Result<(), Ics02Error> {
    let block_hash = header.get_proof_block_hash();
    let vote = Vote {
        height: header.get_proof_height(),
        round: header.get_proof_round(),
        vote_type: VoteType::Precommit,
        block_hash: Bytes::from(block_hash.as_bytes().to_vec()),
    };
    let msg = Bytes::from(rlp::encode(&vote));
    let vote_hash = Bytes::from(AxonHasher::digest(msg).as_bytes().to_vec());
    let hex_pubkey = header
        .get_pub_keys()
        .iter()
        .map(|hex| {
            let pubkey = hex.as_bytes();
            let ret = BlsPublicKey::try_from(pubkey.as_ref())
                .map_err(|e| Ics02Error::client_specific(e.to_string()));
            ret
        })
        .collect::<Result<Vec<_>, _>>()?;

    let aggregate_key = BlsPublicKey::aggregate(hex_pubkey)
        .map_err(|e| Ics02Error::client_specific(e.to_string()))?;
    let aggregated_signature = BlsSignature::try_from(header.get_proof_signature())
        .map_err(|e| Ics02Error::client_specific(e.to_string()))?;
    let hash = HashValue::try_from(vote_hash.as_ref())
        .map_err(|e| Ics02Error::client_specific(e.to_string()))?;

    aggregated_signature
        .verify(&hash, &aggregate_key, &String::from("")) // todo
        .map_err(|e| Ics02Error::client_specific(format!("{}", e.to_string())))?;
    Ok(())
}

pub(crate) fn verify_membership(
    prefix: &CommitmentPrefix,
    proof: &CommitmentProofBytes,
    root: &CommitmentRoot,
    path: impl Into<Path>,
    value: Vec<u8>,
) -> Result<(), Ics02Error> {
    let mut key = prefix.as_bytes().to_vec();
    let path: Vec<u8> = path.into().into_bytes();
    key.extend(path);
    let merkle_proof =
        RawMerkleProof::try_from(proof.clone()).map_err(Ics02Error::invalid_commitment_proof)?;

    // cita-trie src/trie.rs:L366
    let memdb = Arc::new(MemoryDB::new(true));
    let hasher = HasherKeccak {};
    for node_encoded in merkle_proof.proofs.into_iter() {
        if let Some(Proof::Exist(proof)) = node_encoded.proof {
            let v = proof.value;
            let hash = hasher.digest(&v);
            memdb.insert(hash, v).unwrap();
        }
    }
    let trie = PatriciaTrie::from(memdb, Arc::new(hasher), root.as_bytes()).or(Err(
        Ics02Error::client_specific("invalid proof".to_string()),
    ))?;
    let actual_value = trie.get(&key).or(Err(Ics02Error::client_specific(
        "invalid proof".to_string(),
    )))?;
    if let Some(v) = actual_value {
        if v == value {
            return Ok(());
        }
    }
    Err(Ics02Error::client_specific("invalid proof".to_string()))
}
