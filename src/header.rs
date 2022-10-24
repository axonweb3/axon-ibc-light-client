use axon_protocol::types::{Bytes, Hash, Header as AxonHeader, Hex, Signature};
use ibc::core::{
    ics02_client::error::Error as Ics02Error, ics23_commitment::commitment::CommitmentRoot,
};
use ibc_proto::google::protobuf::Any;
use serde::{Deserialize, Serialize};

use crate::base::AxonHash;

pub const AXON_HEADER_TYPE_URL: &str = "/ibc.lightclients.axon.v1.Header";

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Header {
    raw:      AxonHeader,
    pub_keys: Vec<Hex>,
}

impl Header {
    pub fn get_height(&self) -> u64 {
        self.raw.number
    }

    pub fn get_proof_height(&self) -> u64 {
        self.raw.proof.number
    }

    pub fn get_proof_round(&self) -> u64 {
        self.raw.proof.round
    }

    pub fn get_proof_block_hash(&self) -> Hash {
        self.raw.proof.block_hash
    }

    pub fn get_proof_signature(&self) -> &[u8] {
        self.raw.proof.signature.as_ref()
    }

    pub fn get_prev_hash(&self) -> Hash {
        self.raw.prev_hash
    }

    pub fn get_commitment_root(&self) -> CommitmentRoot {
        CommitmentRoot::from(AxonHash::from(self.raw.state_root.clone()))
    }

    pub fn get_pub_keys(&self) -> &Vec<Hex> {
        &self.pub_keys
    }
}

impl TryFrom<Any> for Header {
    type Error = Ics02Error;

    fn try_from(value: Any) -> Result<Self, Self::Error> {
        todo!()
    }
}
