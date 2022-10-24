mod base;
mod consensus_state;
mod header;
mod verification;

use std::time::Duration;

use base::{AxonHash, AxonHeight};
use ibc::core::ics02_client::client_state::{ClientState, UpdatedState, UpgradeOptions};
use ibc::core::ics02_client::client_type::ClientType;
use ibc::core::ics02_client::consensus_state::ConsensusState;
use ibc::core::ics02_client::context::ClientReader;
use ibc::core::ics02_client::error::Error as Ics02Error;
use ibc::core::ics03_connection::connection::ConnectionEnd;
use ibc::core::ics04_channel::channel::ChannelEnd;
use ibc::core::ics04_channel::commitment::{AcknowledgementCommitment, PacketCommitment};
use ibc::core::ics04_channel::context::ChannelReader;
use ibc::core::ics04_channel::packet::Sequence;
use ibc::core::ics23_commitment::commitment::{
    CommitmentPrefix, CommitmentProofBytes, CommitmentRoot,
};
use ibc::core::ics24_host::identifier::{ChannelId, ClientId, ConnectionId, PortId};
use ibc::core::ics24_host::path::{
    AcksPath, ChannelEndsPath, ClientConsensusStatePath, ClientStatePath, CommitmentsPath,
    ConnectionsPath, ReceiptsPath, SeqRecvsPath,
};
use ibc::{core::ics24_host::identifier::ChainId, Height};
use ibc_proto::google::protobuf::Any;
use ibc_proto::ibc::core::commitment::v1::MerkleProof;
use ibc_proto::protobuf::Protobuf;
use prost::Message;
use serde::{Deserialize, Serialize};
use verification::verify_membership;

use crate::consensus_state::AxonConsensusState;
use crate::header::Header;
use crate::verification::verify_header;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AxonClient {
    pub chain_id: ChainId,
    pub latest_height: Height,
    pub frozen_height: Option<Height>,
    pub trusting_period: Duration,
}

impl AxonClient {
    pub fn verify_height(&self, height: Height) -> Result<(), Ics02Error> {
        if self.latest_height < height {
            return Err(Ics02Error::invalid_height());
        }

        match self.frozen_height {
            Some(frozen_height) if frozen_height < height => {
                Err(Ics02Error::client_specific("frozen height".to_string()))
            }
            _ => Ok(()),
        }
    }
}

impl ClientState for AxonClient {
    fn chain_id(&self) -> ChainId {
        self.chain_id.clone()
    }

    fn client_type(&self) -> ClientType {
        // Fix after this issue finish: https://github.com/cosmos/ibc-rs/issues/188
        ClientType::Tendermint
    }

    fn latest_height(&self) -> Height {
        self.latest_height
    }

    fn frozen_height(&self) -> Option<Height> {
        self.frozen_height
    }

    fn expired(&self, elapsed: Duration) -> bool {
        elapsed > self.trusting_period
    }

    fn upgrade(
        &mut self,
        _upgrade_height: Height,
        _upgrade_options: &dyn UpgradeOptions,
        _chain_id: ChainId,
    ) {
        todo!()
    }

    fn initialise(&self, consensus_state: Any) -> Result<Box<dyn ConsensusState>, Ics02Error> {
        AxonConsensusState::try_from(consensus_state).map(AxonConsensusState::into_box)
    }

    fn check_header_and_update_state(
        &self,
        ctx: &dyn ClientReader,
        client_id: ClientId,
        header: Any,
    ) -> Result<UpdatedState, Ics02Error> {
        let axon_header = Header::try_from(header)?;
        let axon_height = AxonHeight::from(axon_header.get_height());
        let prev_header_hash = axon_header.get_prev_hash();
        let prev_height = axon_height.prev(1);
        let prev_consensus_state = ctx.consensus_state(&client_id, prev_height.into())?;
        let expect_prev_root = CommitmentRoot::from(AxonHash::from(prev_header_hash));
        if &expect_prev_root != prev_consensus_state.root() {
            return Err(Ics02Error::client_specific(
                "prev hash mismatch".to_string(),
            ));
        }
        verify_header(&axon_header)?;
        let consensus_state = AxonConsensusState::from(axon_header);
        let mut client_state = self.clone();
        client_state.latest_height = axon_height.into();
        Ok(UpdatedState {
            client_state: client_state.into_box(),
            consensus_state: consensus_state.into_box(),
        })
    }

    fn verify_upgrade_and_update_state(
        &self,
        _consensus_state: Any,
        _proof_upgrade_client: MerkleProof,
        _proof_upgrade_consensus_state: MerkleProof,
    ) -> Result<UpdatedState, Ics02Error> {
        unimplemented!()
    }

    fn verify_client_consensus_state(
        &self,
        height: Height,
        prefix: &CommitmentPrefix,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        client_id: &ClientId,
        consensus_height: Height,
        expected_consensus_state: &dyn ConsensusState,
    ) -> Result<(), Ics02Error> {
        let client_state = downcast_axon_client_state(self)?;
        client_state.verify_height(height)?;

        let path = ClientConsensusStatePath {
            client_id: client_id.clone(),
            epoch: consensus_height.revision_number(),
            height: consensus_height.revision_height(),
        };
        let value = expected_consensus_state
            .encode_vec()
            .map_err(Ics02Error::invalid_any_consensus_state)?;
        verify_membership(prefix, proof, root, path, value)
    }

    fn verify_connection_state(
        &self,
        height: Height,
        prefix: &CommitmentPrefix,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        connection_id: &ConnectionId,
        expected_connection_end: &ConnectionEnd,
    ) -> Result<(), Ics02Error> {
        let client_state = downcast_axon_client_state(self)?;
        client_state.verify_height(height)?;

        let path = ConnectionsPath(connection_id.clone());
        let value = expected_connection_end
            .encode_vec()
            .map_err(Ics02Error::invalid_connection_end)?;
        verify_membership(prefix, proof, root, path, value)
    }

    fn verify_channel_state(
        &self,
        height: Height,
        prefix: &CommitmentPrefix,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        port_id: &PortId,
        channel_id: &ChannelId,
        expected_channel_end: &ChannelEnd,
    ) -> Result<(), Ics02Error> {
        let client_state = downcast_axon_client_state(self)?;
        client_state.verify_height(height)?;

        let path = ChannelEndsPath(port_id.clone(), channel_id.clone());
        let value = expected_channel_end
            .encode_vec()
            .map_err(Ics02Error::invalid_channel_end)?;
        verify_membership(prefix, proof, root, path, value)
    }

    fn verify_client_full_state(
        &self,
        height: Height,
        prefix: &CommitmentPrefix,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        client_id: &ClientId,
        expected_client_state: Any,
    ) -> Result<(), Ics02Error> {
        let client_state = downcast_axon_client_state(self)?;
        client_state.verify_height(height)?;

        let path = ClientStatePath(client_id.clone());
        let value = expected_client_state.encode_to_vec();
        verify_membership(prefix, proof, root, path, value)
    }

    fn verify_packet_data(
        &self,
        _ctx: &dyn ChannelReader,
        height: Height,
        connection_end: &ConnectionEnd,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
        commitment: PacketCommitment,
    ) -> Result<(), Ics02Error> {
        let client_state = downcast_axon_client_state(self)?;
        client_state.verify_height(height)?;
        // todo: verify delay passed

        let path = CommitmentsPath {
            port_id: port_id.clone(),
            channel_id: channel_id.clone(),
            sequence,
        };
        let value = commitment.into_vec();
        verify_membership(
            connection_end.counterparty().prefix(),
            proof,
            root,
            path,
            value,
        )
    }

    fn verify_packet_acknowledgement(
        &self,
        _ctx: &dyn ChannelReader,
        height: Height,
        connection_end: &ConnectionEnd,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
        ack: AcknowledgementCommitment,
    ) -> Result<(), Ics02Error> {
        let client_state = downcast_axon_client_state(self)?;
        client_state.verify_height(height)?;
        // todo: verify delay passed

        let ack_path = AcksPath {
            port_id: port_id.clone(),
            channel_id: channel_id.clone(),
            sequence,
        };
        let value = ack.into_vec();
        verify_membership(
            connection_end.counterparty().prefix(),
            proof,
            root,
            ack_path,
            value,
        )
    }

    fn verify_next_sequence_recv(
        &self,
        _ctx: &dyn ChannelReader,
        height: Height,
        connection_end: &ConnectionEnd,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
    ) -> Result<(), Ics02Error> {
        let client_state = downcast_axon_client_state(self)?;
        client_state.verify_height(height)?;
        // todo: verify delay passed
        let mut seq_bytes = Vec::new();
        u64::from(sequence)
            .encode(&mut seq_bytes)
            .expect("buffer size too small");

        let seq_path = SeqRecvsPath(port_id.clone(), channel_id.clone());
        verify_membership(
            connection_end.counterparty().prefix(),
            proof,
            root,
            seq_path,
            seq_bytes,
        )
    }

    fn verify_packet_receipt_absence(
        &self,
        _ctx: &dyn ChannelReader,
        height: Height,
        connection_end: &ConnectionEnd,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
    ) -> Result<(), Ics02Error> {
        let client_state = downcast_axon_client_state(self)?;
        client_state.verify_height(height)?;
        // todo: verify delay passed

        let path = ReceiptsPath {
            port_id: port_id.clone(),
            channel_id: channel_id.clone(),
            sequence,
        };
        todo!()
    }
}

impl Protobuf<Any> for AxonClient {}

impl TryFrom<Any> for AxonClient {
    type Error = Ics02Error;

    fn try_from(value: Any) -> Result<Self, Self::Error> {
        todo!()
    }
}

impl From<AxonClient> for Any {
    fn from(_: AxonClient) -> Self {
        todo!()
    }
}

fn downcast_axon_client_state(cs: &dyn ClientState) -> Result<&AxonClient, Ics02Error> {
    cs.as_any()
        .downcast_ref::<AxonClient>()
        .ok_or_else(|| Ics02Error::client_args_type_mismatch(ClientType::Tendermint))
}

fn downcast_axon_consensus_state(
    cs: &dyn ConsensusState,
) -> Result<AxonConsensusState, Ics02Error> {
    cs.as_any()
        .downcast_ref::<AxonConsensusState>()
        .ok_or_else(|| Ics02Error::client_args_type_mismatch(ClientType::Tendermint))
        .map(Clone::clone)
}
