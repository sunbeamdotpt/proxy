// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use crate::cluster::gateway_topics::{GatewayResourceNotify, GatewayStateDigest};

/// Envelope for all cluster gossip messages.
/// Serialized with bincode before broadcast.
#[derive(Debug, Serialize, Deserialize)]
pub struct ClusterMessage {
    /// Version.
    pub version: u8,
    /// Sender.
    pub sender: [u8; 32],
    /// Payload.
    pub payload: Payload,
}

#[derive(Debug, Serialize, Deserialize)]
/// Payload.
pub enum Payload {
    /// Bandwidthreport.
    BandwidthReport {
        timestamp: u64,
        bytes_in: u64,
        bytes_out: u64,
        request_count: u64,
        cumulative_in: u64,
        cumulative_out: u64,
    },
    /// Modelannounce.
    ModelAnnounce {
        model_type: String,
        hash: [u8; 32],
        total_size: u64,
        chunk_count: u32,
    },
    /// Modelchunk.
    ModelChunk {
        hash: [u8; 32],
        chunk_index: u32,
        data: Vec<u8>,
    },
    /// Leaderheartbeat.
    LeaderHeartbeat {
        term: u64,
        leader_id: [u8; 32],
    },
    /// Licensequota.
    LicenseQuota {
        max_bytes: u64,
        current_bytes: u64,
    },
    /// Gateway state digest broadcast (Gateway API controller).
    GatewayStateDigest(GatewayStateDigest),
    /// Gateway resource change notification (Gateway API controller).
    GatewayResourceNotify(GatewayResourceNotify),
}

impl ClusterMessage {
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn decode(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_bandwidth_report() {
        let msg = ClusterMessage {
            version: 1,
            sender: [42u8; 32],
            payload: Payload::BandwidthReport {
                timestamp: 1234567890,
                bytes_in: 1000,
                bytes_out: 2000,
                request_count: 50,
                cumulative_in: 100_000,
                cumulative_out: 200_000,
            },
        };
        let encoded = msg.encode().unwrap();
        let decoded = ClusterMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.sender, [42u8; 32]);
        match decoded.payload {
            Payload::BandwidthReport {
                timestamp,
                bytes_in,
                bytes_out,
                request_count,
                cumulative_in,
                cumulative_out,
            } => {
                assert_eq!(timestamp, 1234567890);
                assert_eq!(bytes_in, 1000);
                assert_eq!(bytes_out, 2000);
                assert_eq!(request_count, 50);
                assert_eq!(cumulative_in, 100_000);
                assert_eq!(cumulative_out, 200_000);
            }
            _ => panic!("wrong payload variant"),
        }
    }

    #[test]
    fn roundtrip_model_announce() {
        let msg = ClusterMessage {
            version: 1,
            sender: [1u8; 32],
            payload: Payload::ModelAnnounce {
                model_type: "scanner".to_string(),
                hash: [0xAA; 32],
                total_size: 1_000_000,
                chunk_count: 16,
            },
        };
        let encoded = msg.encode().unwrap();
        let decoded = ClusterMessage::decode(&encoded).unwrap();
        match decoded.payload {
            Payload::ModelAnnounce {
                model_type,
                total_size,
                chunk_count,
                ..
            } => {
                assert_eq!(model_type, "scanner");
                assert_eq!(total_size, 1_000_000);
                assert_eq!(chunk_count, 16);
            }
            _ => panic!("wrong payload variant"),
        }
    }

    #[test]
    fn roundtrip_leader_heartbeat() {
        let msg = ClusterMessage {
            version: 1,
            sender: [7u8; 32],
            payload: Payload::LeaderHeartbeat {
                term: 3,
                leader_id: [7u8; 32],
            },
        };
        let encoded = msg.encode().unwrap();
        let decoded = ClusterMessage::decode(&encoded).unwrap();
        match decoded.payload {
            Payload::LeaderHeartbeat { term, leader_id } => {
                assert_eq!(term, 3);
                assert_eq!(leader_id, [7u8; 32]);
            }
            _ => panic!("wrong payload variant"),
        }
    }
}
