//! Tests for the extensions advertisement and the gossipsub v1.4 Large Message
//! Handling capability.

use std::{collections::HashMap, time::Duration};

use asynchronous_codec::{Decoder, Encoder};
use bytes::BytesMut;
use futures_timer::Delay;
use libp2p_core::{Multiaddr, PeerId};
use libp2p_swarm::{ConnectionId, NetworkBehaviour};

use super::DefaultBehaviourTestBuilder;
use crate::{
    Behaviour, DataTransform, IdentTopic as Topic, TopicSubscriptionFilter, ValidationMode,
    config::ConfigBuilder,
    error::ConfigBuilderError,
    handler::HandlerEvent,
    protocol::GossipsubCodec,
    queue::Queue,
    rpc_proto::proto,
    types::{
        ControlAction, Extensions, ImReceiving, LargeMessageFragment, MessageId, Preamble, RpcIn,
        RpcOut,
    },
};

/// Pops messages from a peer's queue until it finds the extensions
/// advertisement sent on connect.
fn advertised_extensions(queue: &mut Queue) -> Extensions {
    std::iter::from_fn(|| queue.try_pop())
        .find_map(|rpc| {
            if let RpcOut::Extensions(extensions) = rpc {
                Some(extensions)
            } else {
                None
            }
        })
        .expect("Extensions message should be sent on connect")
}

/// Verifies that a peer advertising `largeMessageHandling` is tracked as
/// supporting it, independently of any topic subscriptions.
#[test]
fn test_peer_advertised_extensions_are_tracked() {
    let (mut gs, peers, _, _) = DefaultBehaviourTestBuilder::default()
        .peer_no(1)
        .create_network();
    let peer_id = peers[0];
    assert_eq!(gs.connected_peers.get(&peer_id).unwrap().extensions, None);

    let extensions = Extensions {
        partial_messages: None,
        large_message_handling: Some(true),
    };
    gs.on_connection_handler_event(
        peer_id,
        ConnectionId::new_unchecked(0),
        HandlerEvent::Message {
            rpc: RpcIn {
                messages: vec![],
                subscriptions: vec![],
                control_msgs: vec![ControlAction::Extensions(Some(extensions))],
                large_message_fragments: vec![],
                #[cfg(feature = "partial-messages")]
                partial_message: None,
            },
            invalid_messages: vec![],
        },
    );

    assert_eq!(
        gs.connected_peers.get(&peer_id).unwrap().extensions,
        Some(extensions)
    );
}

/// Verifies that with the config option unset the extensions advertisement
/// does not include the `largeMessageHandling` flag.
#[test]
fn test_large_message_handling_not_advertised_by_default() {
    let (mut gs, _, _, _) = DefaultBehaviourTestBuilder::default().create_network();
    let peer_id = PeerId::random();
    gs.handle_established_inbound_connection(
        ConnectionId::new_unchecked(0),
        peer_id,
        &Multiaddr::empty(),
        &Multiaddr::empty(),
    )
    .unwrap();

    let mut queue = gs.connected_peers.get(&peer_id).unwrap().messages.clone();
    let extensions = advertised_extensions(&mut queue);
    assert_eq!(extensions.large_message_handling, None);
}

/// Verifies that with the config option set the extensions advertisement
/// includes `largeMessageHandling`.
#[test]
fn test_large_message_handling_advertised_when_enabled() {
    let config = ConfigBuilder::default()
        .max_transmit_size(1 << 17)
        .large_message_handling(true)
        .build()
        .unwrap();
    let (mut gs, _, _, _) = DefaultBehaviourTestBuilder::default()
        .gs_config(config)
        .create_network();
    let peer_id = PeerId::random();
    gs.handle_established_inbound_connection(
        ConnectionId::new_unchecked(0),
        peer_id,
        &Multiaddr::empty(),
        &Multiaddr::empty(),
    )
    .unwrap();

    let mut queue = gs.connected_peers.get(&peer_id).unwrap().messages.clone();
    let extensions = advertised_extensions(&mut queue);
    assert_eq!(extensions.large_message_handling, Some(true));
}

/// Verifies that an RPC carrying PREAMBLE, IMRECEIVING and large message
/// fragment entries decodes without error and produces no events.
#[test]
fn test_large_message_rpc_decodes_and_produces_no_events() {
    let message_id = MessageId::new(&[1, 2, 3, 4]);
    let topic_hash = Topic::new("large-message-topic").hash();

    let rpc = proto::Rpc {
        publish: vec![],
        subscriptions: vec![],
        control: Some(proto::ControlMessage {
            ihave: vec![],
            iwant: vec![],
            graft: vec![],
            prune: vec![],
            idontwant: vec![],
            extensions: None,
            preamble: vec![proto::ControlPreamble {
                message_id: Some(message_id.0.clone()),
                message_size: Some(1 << 20),
                topic_id: Some(topic_hash.clone().into_string()),
            }],
            imreceiving: vec![proto::ControlImReceiving {
                message_id: Some(message_id.0.clone()),
            }],
        }),
        partial: None,
        large_message_fragments: vec![proto::LargeMessageFragment {
            message_id: Some(message_id.0.clone()),
            fragment_index: Some(0),
            total_fragments: Some(4),
            fragment_data: Some(vec![7u8; 128]),
            topic_id: Some(topic_hash.clone().into_string()),
        }],
    };

    let mut codec = GossipsubCodec::new(
        u32::MAX as usize,
        ValidationMode::Strict,
        HashMap::new(),
        5000,
        5000,
        5000,
    );
    let mut buf = BytesMut::new();
    codec.encode(rpc, &mut buf).unwrap();
    let event = codec.decode(&mut buf).unwrap().unwrap();

    let HandlerEvent::Message {
        rpc,
        invalid_messages,
    } = event
    else {
        panic!("Expected message event");
    };
    assert!(invalid_messages.is_empty());
    assert!(
        rpc.control_msgs
            .contains(&ControlAction::Preamble(Preamble {
                message_id: message_id.clone(),
                message_size: 1 << 20,
                topic_hash: topic_hash.clone(),
            }))
    );
    assert!(
        rpc.control_msgs
            .contains(&ControlAction::ImReceiving(ImReceiving {
                message_id: message_id.clone(),
            }))
    );
    assert_eq!(
        rpc.large_message_fragments,
        vec![LargeMessageFragment {
            message_id,
            fragment_index: 0,
            total_fragments: 4,
            fragment_data: vec![7u8; 128],
            topic_hash,
        }]
    );

    // Delivering the decoded RPC to the behaviour is a no-op for now.
    let (mut gs, peers, _, _) = DefaultBehaviourTestBuilder::default()
        .peer_no(1)
        .create_network();
    gs.events.clear();
    gs.on_connection_handler_event(
        peers[0],
        ConnectionId::new_unchecked(0),
        HandlerEvent::Message {
            rpc,
            invalid_messages: vec![],
        },
    );
    assert!(gs.events.is_empty());
}

/// Builds a codec suitable for round-tripping v1.4 RPCs in tests.
fn large_message_codec() -> GossipsubCodec {
    GossipsubCodec::new(
        u32::MAX as usize,
        ValidationMode::Strict,
        HashMap::new(),
        5000,
        5000,
        5000,
    )
}

/// Marks the peer as having advertised the Large Message Handling extension.
fn advertise_large_messages<D, F>(gs: &mut Behaviour<D, F>, peer_id: PeerId)
where
    D: DataTransform + Send + 'static,
    F: TopicSubscriptionFilter + Send + 'static,
{
    gs.on_connection_handler_event(
        peer_id,
        ConnectionId::new_unchecked(0),
        HandlerEvent::Message {
            rpc: RpcIn {
                messages: vec![],
                subscriptions: vec![],
                control_msgs: vec![ControlAction::Extensions(Some(Extensions {
                    partial_messages: None,
                    large_message_handling: Some(true),
                }))],
                large_message_fragments: vec![],
                #[cfg(feature = "partial-messages")]
                partial_message: None,
            },
            invalid_messages: vec![],
        },
    );
}

/// Verifies the documented defaults of the large message configuration.
#[test]
fn test_large_message_config_defaults() {
    let config = ConfigBuilder::default()
        .max_transmit_size(1 << 17)
        .large_message_handling(true)
        .build()
        .unwrap();
    assert_eq!(config.fragment_size(), 61440);
    assert_eq!(config.fragmentation_threshold(), 65536);
    assert_eq!(config.preamble_threshold(), 409600);
    assert_eq!(config.stagger_threshold(), 65536);
    assert_eq!(config.stagger_interval(), Duration::from_millis(200));
    assert_eq!(config.fragment_timeout(), Duration::from_secs(30));
    assert_eq!(config.max_pending_fragments(), 16);
    assert_eq!(config.max_reassembly_bytes_per_peer(), 4 * 1024 * 1024);
    assert_eq!(config.max_reassembly_bytes_total(), 64 * 1024 * 1024);
    assert_eq!(config.max_queued_fragments_per_peer(), 128);
    assert_eq!(config.max_preamble_announcements_per_peer(), 16);
}

/// Verifies that a fragment RPC (fragment plus overhead) must fit within
/// `max_transmit_size`.
#[test]
fn test_fragment_size_must_fit_max_transmit_size() {
    let result = ConfigBuilder::default()
        .max_transmit_size(1 << 17)
        .large_message_handling(true)
        .fragment_size(131_000)
        .fragmentation_threshold(131_072)
        .build();
    assert!(matches!(
        result,
        Err(ConfigBuilderError::FragmentSizeTooLarge)
    ));
}

/// Verifies that inconsistent large message parameters are accepted while the
/// extension is disabled.
#[test]
fn test_large_message_config_unvalidated_when_disabled() {
    let config = ConfigBuilder::default()
        .fragment_size(0)
        .max_pending_fragments(0)
        .max_reassembly_bytes_total(0)
        .build()
        .unwrap();
    assert!(!config.large_message_handling());
}

/// Verifies that a PREAMBLE `RpcOut` round-trips through the codec.
#[test]
fn test_preamble_rpc_out_roundtrip() {
    let message_id = MessageId::new(&[9, 8, 7]);
    let topic_hash = Topic::new("large-message-topic").hash();
    let rpc_out = RpcOut::Preamble(Preamble {
        message_id: message_id.clone(),
        message_size: 4 << 20,
        topic_hash: topic_hash.clone(),
    });

    let mut codec = large_message_codec();
    let mut buf = BytesMut::new();
    codec.encode(rpc_out.into_protobuf(), &mut buf).unwrap();
    let event = codec.decode(&mut buf).unwrap().unwrap();

    let HandlerEvent::Message {
        rpc,
        invalid_messages,
    } = event
    else {
        panic!("Expected message event");
    };
    assert!(invalid_messages.is_empty());
    // The codec emits an empty `Extensions` entry for every decoded RPC.
    assert_eq!(
        rpc.control_msgs,
        vec![
            ControlAction::Extensions(None),
            ControlAction::Preamble(Preamble {
                message_id,
                message_size: 4 << 20,
                topic_hash,
            })
        ]
    );
}

/// Verifies that an IMRECEIVING `RpcOut` round-trips through the codec.
#[test]
fn test_imreceiving_rpc_out_roundtrip() {
    let message_id = MessageId::new(&[5, 5, 5]);
    let rpc_out = RpcOut::ImReceiving(ImReceiving {
        message_id: message_id.clone(),
    });

    let mut codec = large_message_codec();
    let mut buf = BytesMut::new();
    codec.encode(rpc_out.into_protobuf(), &mut buf).unwrap();
    let event = codec.decode(&mut buf).unwrap().unwrap();

    let HandlerEvent::Message {
        rpc,
        invalid_messages,
    } = event
    else {
        panic!("Expected message event");
    };
    assert!(invalid_messages.is_empty());
    // The codec emits an empty `Extensions` entry for every decoded RPC.
    assert_eq!(
        rpc.control_msgs,
        vec![
            ControlAction::Extensions(None),
            ControlAction::ImReceiving(ImReceiving { message_id })
        ]
    );
}

/// Verifies that a fragment `RpcOut` round-trips through the codec.
#[test]
fn test_fragment_rpc_out_roundtrip() {
    let message_id = MessageId::new(&[4, 4, 4]);
    let topic_hash = Topic::new("large-message-topic").hash();
    let rpc_out = RpcOut::LargeMessageFragment {
        fragment: LargeMessageFragment {
            message_id: message_id.clone(),
            fragment_index: 2,
            total_fragments: 4,
            fragment_data: vec![3u8; 256],
            topic_hash: topic_hash.clone(),
        },
        timeout: Delay::new(Duration::from_secs(5)),
    };

    let mut codec = large_message_codec();
    let mut buf = BytesMut::new();
    codec.encode(rpc_out.into_protobuf(), &mut buf).unwrap();
    let event = codec.decode(&mut buf).unwrap().unwrap();

    let HandlerEvent::Message {
        rpc,
        invalid_messages,
    } = event
    else {
        panic!("Expected message event");
    };
    assert!(invalid_messages.is_empty());
    // The codec emits an empty `Extensions` entry for every decoded RPC.
    assert_eq!(rpc.control_msgs, vec![ControlAction::Extensions(None)]);
    assert_eq!(
        rpc.large_message_fragments,
        vec![LargeMessageFragment {
            message_id,
            fragment_index: 2,
            total_fragments: 4,
            fragment_data: vec![3u8; 256],
            topic_hash,
        }]
    );
}

/// Verifies that v1.4 RPCs are dropped, not queued, for a peer that did not
/// advertise the Large Message Handling extension.
#[test]
fn test_send_message_drops_v14_rpcs_to_non_capable_peer() {
    let (mut gs, peers, _, _) = DefaultBehaviourTestBuilder::default()
        .peer_no(1)
        .create_network();
    let peer_id = peers[0];
    let topic_hash = Topic::new("large-message-topic").hash();
    let message_id = MessageId::new(&[1]);

    let sent_preamble = gs.send_message(
        peer_id,
        RpcOut::Preamble(Preamble {
            message_id: message_id.clone(),
            message_size: 1 << 20,
            topic_hash: topic_hash.clone(),
        }),
    );
    let sent_imreceiving = gs.send_message(
        peer_id,
        RpcOut::ImReceiving(ImReceiving {
            message_id: message_id.clone(),
        }),
    );
    let sent_fragment = gs.send_message(
        peer_id,
        RpcOut::LargeMessageFragment {
            fragment: LargeMessageFragment {
                message_id,
                fragment_index: 0,
                total_fragments: 2,
                fragment_data: vec![1u8; 64],
                topic_hash,
            },
            timeout: Delay::new(Duration::from_secs(5)),
        },
    );
    assert!(!sent_preamble);
    assert!(!sent_imreceiving);
    assert!(!sent_fragment);

    let mut queue = gs.connected_peers.get(&peer_id).unwrap().messages.clone();
    assert!(std::iter::from_fn(|| queue.try_pop()).all(|rpc| !matches!(
        rpc,
        RpcOut::Preamble(_) | RpcOut::ImReceiving(_) | RpcOut::LargeMessageFragment { .. }
    )));
}

/// Verifies that v1.4 RPCs are queued for a peer that advertised the Large
/// Message Handling extension.
#[test]
fn test_send_message_queues_v14_rpcs_to_capable_peer() {
    let (mut gs, peers, _, _) = DefaultBehaviourTestBuilder::default()
        .peer_no(1)
        .create_network();
    let peer_id = peers[0];
    advertise_large_messages(&mut gs, peer_id);
    let topic_hash = Topic::new("large-message-topic").hash();
    let message_id = MessageId::new(&[1]);

    let sent_preamble = gs.send_message(
        peer_id,
        RpcOut::Preamble(Preamble {
            message_id: message_id.clone(),
            message_size: 1 << 20,
            topic_hash: topic_hash.clone(),
        }),
    );
    let sent_imreceiving = gs.send_message(
        peer_id,
        RpcOut::ImReceiving(ImReceiving {
            message_id: message_id.clone(),
        }),
    );
    let sent_fragment = gs.send_message(
        peer_id,
        RpcOut::LargeMessageFragment {
            fragment: LargeMessageFragment {
                message_id,
                fragment_index: 0,
                total_fragments: 2,
                fragment_data: vec![1u8; 64],
                topic_hash,
            },
            timeout: Delay::new(Duration::from_secs(5)),
        },
    );
    assert!(sent_preamble);
    assert!(sent_imreceiving);
    assert!(sent_fragment);

    let mut queue = gs.connected_peers.get(&peer_id).unwrap().messages.clone();
    let drained: Vec<RpcOut> = std::iter::from_fn(|| queue.try_pop()).collect();
    assert!(drained.iter().any(|rpc| matches!(rpc, RpcOut::Preamble(_))));
    assert!(
        drained
            .iter()
            .any(|rpc| matches!(rpc, RpcOut::ImReceiving(_)))
    );
    assert!(
        drained
            .iter()
            .any(|rpc| matches!(rpc, RpcOut::LargeMessageFragment { .. }))
    );
}

/// Verifies that the capability lookup reads the tracked extensions.
#[test]
fn test_supports_large_messages_reads_extensions() {
    let (mut gs, peers, _, _) = DefaultBehaviourTestBuilder::default()
        .peer_no(1)
        .create_network();
    let peer_id = peers[0];

    // Unknown peers are not capable.
    assert!(!gs.supports_large_messages(&PeerId::random()));
    // A peer that has not sent extensions is not capable.
    assert!(!gs.supports_large_messages(&peer_id));

    gs.connected_peers.get_mut(&peer_id).unwrap().extensions = Some(Extensions {
        partial_messages: None,
        large_message_handling: Some(false),
    });
    assert!(!gs.supports_large_messages(&peer_id));

    gs.connected_peers.get_mut(&peer_id).unwrap().extensions = Some(Extensions {
        partial_messages: None,
        large_message_handling: Some(true),
    });
    assert!(gs.supports_large_messages(&peer_id));
}
