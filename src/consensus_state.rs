use ibc::{
    core::{
        ics02_client::{
            client_type::ClientType, consensus_state::ConsensusState, error::Error as Ics02Error,
        },
        ics23_commitment::commitment::CommitmentRoot,
    },
    timestamp::Timestamp,
};
use ibc_proto::{google::protobuf::Any, protobuf::Protobuf};
use serde::{Deserialize, Serialize};
use tendermint::Time;

use crate::{base::AXON_CLIENT_TYPE, header::Header};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AxonConsensusState {
    pub timestamp: Time,
    pub root: CommitmentRoot,
}

impl ConsensusState for AxonConsensusState {
    fn client_type(&self) -> ClientType {
        ClientType::new(AXON_CLIENT_TYPE)
    }

    fn root(&self) -> &CommitmentRoot {
        &self.root
    }

    fn timestamp(&self) -> Timestamp {
        self.timestamp.into()
    }
}

impl Protobuf<Any> for AxonConsensusState {}

impl TryFrom<Any> for AxonConsensusState {
    type Error = Ics02Error;

    fn try_from(value: Any) -> Result<Self, Self::Error> {
        todo!()
    }
}

impl From<AxonConsensusState> for Any {
    fn from(_: AxonConsensusState) -> Self {
        todo!()
    }
}

impl From<Header> for AxonConsensusState {
    fn from(_: Header) -> Self {
        todo!()
    }
}
