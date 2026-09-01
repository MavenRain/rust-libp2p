// Copyright 2025 Sigma Prime Pty Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! Tests for publishing and fanout functionality.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use futures_timer::Delay;
use libp2p_identity::PeerId;
use libp2p_swarm::{ConnectionId, NetworkBehaviour};

use super::{DefaultBehaviourTestBuilder, disconnect_peer};
use crate::{
    Behaviour, IdentTopic as Topic, PublishError,
    config::{Config, ConfigBuilder},
    extensions::large_messages::{
        MAX_STAGGER_BYTES, MAX_STAGGERED_MESSAGES, STAGGER_CAP, StaggerPayload, StaggeredMessage,
        StaggeredSend,
    },
    handler::HandlerEvent,
    peer_score::{PeerScoreParams, PeerScoreThresholds},
    queue::Queue,
    topic::TopicHash,
    transform::DataTransform,
    types::{
        ControlAction, Extensions, LargeMessageFragment, MessageAcceptance, MessageId, PeerKind,
        RawMessage, RpcIn, RpcOut,
    },
};

/// Test local node publish to subscribed topic
#[test]
fn test_publish_without_flood_publishing() {
    // node should:
    // - Send publish message to all peers
    // - Insert message into gs.mcache and gs.received

    // turn off flood publish to test old behaviour
    let config = ConfigBuilder::default()
        .flood_publish(false)
        .build()
        .unwrap();

    let publish_topic = String::from("test_publish");
    let (mut gs, _, queues, topic_hashes) = DefaultBehaviourTestBuilder::default()
        .peer_no(20)
        .topics(vec![publish_topic.clone()])
        .to_subscribe(true)
        .gs_config(config)
        .create_network();

    assert!(
        gs.mesh.contains_key(&topic_hashes[0]),
        "Subscribe should add a new entry to the mesh[topic] hashmap"
    );

    // all peers should be subscribed to the topic
    assert_eq!(
        gs.connected_peers
            .values()
            .filter(|p| p.topics.contains(&topic_hashes[0]))
            .count(),
        20,
        "Peers should be subscribed to the topic"
    );

    // publish on topic
    let publish_data = vec![0; 42];
    gs.publish(Topic::new(publish_topic), publish_data).unwrap();

    // Collect all publish messages
    let publishes = queues
        .into_values()
        .fold(vec![], |mut collected_publish, mut queue| {
            while !queue.is_empty() {
                if let Some(RpcOut::Publish { message, .. }) = queue.try_pop() {
                    collected_publish.push(message);
                }
            }
            collected_publish
        });

    // Transform the inbound message
    let message = &gs
        .data_transform
        .inbound_transform(
            publishes
                .first()
                .expect("Should contain > 0 entries")
                .clone(),
        )
        .unwrap();

    let msg_id = gs.config.message_id(message);

    let config: Config = Config::default();
    assert_eq!(
        publishes.len(),
        config.mesh_n(),
        "Should send a publish message to at least mesh_n peers"
    );

    assert!(
        gs.mcache.get(&msg_id).is_some(),
        "Message cache should contain published message"
    );
}

/// Test local node publish to unsubscribed topic
#[test]
fn test_fanout() {
    // node should:
    // - Populate fanout peers
    // - Send publish message to fanout peers
    // - Insert message into gs.mcache and gs.received

    // turn off flood publish to test fanout behaviour
    let config = ConfigBuilder::default()
        .flood_publish(false)
        .build()
        .unwrap();

    let fanout_topic = String::from("test_fanout");
    let (mut gs, _, queues, topic_hashes) = DefaultBehaviourTestBuilder::default()
        .peer_no(20)
        .topics(vec![fanout_topic.clone()])
        .to_subscribe(true)
        .gs_config(config)
        .create_network();

    assert!(
        gs.mesh.contains_key(&topic_hashes[0]),
        "Subscribe should add a new entry to the mesh[topic] hashmap"
    );
    // Unsubscribe from topic
    assert!(
        gs.unsubscribe(&Topic::new(fanout_topic.clone())),
        "should be able to unsubscribe successfully from topic"
    );

    // Publish on unsubscribed topic
    let publish_data = vec![0; 42];
    gs.publish(Topic::new(fanout_topic.clone()), publish_data)
        .unwrap();

    assert_eq!(
        gs.fanout
            .get(&TopicHash::from_raw(fanout_topic))
            .unwrap()
            .len(),
        gs.config.mesh_n(),
        "Fanout should contain `mesh_n` peers for fanout topic"
    );

    // Collect all publish messages
    let publishes = queues
        .into_values()
        .fold(vec![], |mut collected_publish, mut queue| {
            while !queue.is_empty() {
                if let Some(RpcOut::Publish { message, .. }) = queue.try_pop() {
                    collected_publish.push(message);
                }
            }
            collected_publish
        });

    // Transform the inbound message
    let message = &gs
        .data_transform
        .inbound_transform(
            publishes
                .first()
                .expect("Should contain > 0 entries")
                .clone(),
        )
        .unwrap();

    let msg_id = gs.config.message_id(message);

    assert_eq!(
        publishes.len(),
        gs.config.mesh_n(),
        "Should send a publish message to `mesh_n` fanout peers"
    );

    assert!(
        gs.mcache.get(&msg_id).is_some(),
        "Message cache should contain published message"
    );
}

#[test]
fn test_flood_publish() {
    let config: Config = Config::default();

    let topic = "test";
    // Adds more peers than mesh can hold to test flood publishing
    let (mut gs, _, queues, _) = DefaultBehaviourTestBuilder::default()
        .peer_no(config.mesh_n_high() + 10)
        .topics(vec![topic.into()])
        .to_subscribe(true)
        .create_network();

    // publish message
    let publish_data = vec![0; 42];
    gs.publish(Topic::new(topic), publish_data).unwrap();

    // Collect all publish messages
    let publishes = queues
        .into_values()
        .fold(vec![], |mut collected_publish, mut queue| {
            while !queue.is_empty() {
                if let Some(RpcOut::Publish { message, .. }) = queue.try_pop() {
                    collected_publish.push(message);
                }
            }
            collected_publish
        });

    // Transform the inbound message
    let message = &gs
        .data_transform
        .inbound_transform(
            publishes
                .first()
                .expect("Should contain > 0 entries")
                .clone(),
        )
        .unwrap();

    let msg_id = gs.config.message_id(message);

    let config: Config = Config::default();
    assert_eq!(
        publishes.len(),
        config.mesh_n_high() + 10,
        "Should send a publish message to all known peers"
    );

    assert!(
        gs.mcache.get(&msg_id).is_some(),
        "Message cache should contain published message"
    );
}

// ---- gossipsub v1.4 Large Message Handling: publish-side fragmentation ----

const LARGE_TOPIC: &str = "large-publish";

/// A publish-side config with Large Message Handling enabled and a transmit
/// ceiling that can carry the test messages.
fn large_send_config() -> Config {
    ConfigBuilder::default()
        .max_transmit_size(1 << 17)
        .large_message_handling(true)
        .build()
        .unwrap()
}

/// Same as [`large_send_config`], with the PREAMBLE threshold lowered under
/// the 100 KB test message.
fn preamble_config() -> Config {
    ConfigBuilder::default()
        .max_transmit_size(1 << 17)
        .large_message_handling(true)
        .preamble_threshold(70_000)
        .build()
        .unwrap()
}

/// One-topic network on [`LARGE_TOPIC`] wired with `config`.
#[allow(clippy::type_complexity)]
fn large_network(
    config: Config,
    peer_no: usize,
) -> (
    Behaviour,
    Vec<PeerId>,
    HashMap<PeerId, Queue>,
    Vec<TopicHash>,
) {
    DefaultBehaviourTestBuilder::default()
        .peer_no(peer_no)
        .topics(vec![String::from(LARGE_TOPIC)])
        .to_subscribe(true)
        .gs_config(config)
        .create_network()
}

/// Marks the peer as having advertised the Large Message Handling extension.
fn advertise_large_messages(gs: &mut Behaviour, peer_id: PeerId) {
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

/// Drains `queue`, returning the popped RPCs in pop order.
fn drain_rpcs(queue: &mut Queue) -> Vec<RpcOut> {
    std::iter::from_fn(|| queue.try_pop()).collect()
}

/// Counts the (publishes, preambles, fragments) among `rpcs`.
fn count_kinds(rpcs: &[RpcOut]) -> (usize, usize, usize) {
    (
        rpcs.iter()
            .filter(|rpc| matches!(rpc, RpcOut::Publish { .. }))
            .count(),
        rpcs.iter()
            .filter(|rpc| matches!(rpc, RpcOut::Preamble(_)))
            .count(),
        rpcs.iter()
            .filter(|rpc| matches!(rpc, RpcOut::LargeMessageFragment { .. }))
            .count(),
    )
}

/// Occupies `count` slots of the queue's fragment tier with filler fragments.
fn fill_fragment_tier(queue: &mut Queue, count: usize, message_id: &MessageId, topic: &TopicHash) {
    (0..count).for_each(|index| {
        let _ = queue.try_push(RpcOut::LargeMessageFragment {
            fragment: LargeMessageFragment {
                message_id: message_id.clone(),
                fragment_index: index as u32,
                total_fragments: count as u32,
                fragment_data: vec![0u8; 8],
                topic_hash: topic.clone(),
            },
            timeout: Delay::new(Duration::from_secs(5)),
        });
    });
}

#[test]
fn test_publish_below_threshold_is_not_fragmented() {
    let (mut gs, peers, mut queues, _) = large_network(large_send_config(), 1);
    advertise_large_messages(&mut gs, peers[0]);

    gs.publish(Topic::new(LARGE_TOPIC), vec![1u8; 1_000])
        .unwrap();

    let rpcs = drain_rpcs(queues.get_mut(&peers[0]).unwrap());
    let (publishes, preambles, fragments) = count_kinds(&rpcs);
    assert_eq!(publishes, 1, "a small message goes out whole");
    assert_eq!(preambles, 0);
    assert_eq!(fragments, 0);
}

#[test]
fn test_publish_above_threshold_sends_preamble_then_fragments() {
    let (mut gs, peers, mut queues, _) = large_network(preamble_config(), 1);
    advertise_large_messages(&mut gs, peers[0]);

    gs.publish(Topic::new(LARGE_TOPIC), vec![1u8; 100_000])
        .unwrap();

    let rpcs = drain_rpcs(queues.get_mut(&peers[0]).unwrap());
    let (publishes, preambles, fragments) = count_kinds(&rpcs);
    assert_eq!(publishes, 0, "a fragmented message is never sent whole");
    assert_eq!(preambles, 1);
    assert_eq!(
        fragments, 2,
        "100 KB splits into two spec-default fragments"
    );

    // The PREAMBLE announces exactly the concatenated fragment bytes.
    let fragment_bytes: u64 = rpcs
        .iter()
        .map(|rpc| {
            if let RpcOut::LargeMessageFragment { fragment, .. } = rpc {
                fragment.fragment_data.len() as u64
            } else {
                0
            }
        })
        .sum();
    let announced = rpcs
        .iter()
        .find_map(|rpc| {
            if let RpcOut::Preamble(preamble) = rpc {
                Some(preamble.message_size)
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(announced, fragment_bytes);
}

#[test]
fn test_publish_above_fragmentation_below_preamble_threshold_sends_no_preamble() {
    let (mut gs, peers, mut queues, _) = large_network(large_send_config(), 1);
    advertise_large_messages(&mut gs, peers[0]);

    gs.publish(Topic::new(LARGE_TOPIC), vec![1u8; 100_000])
        .unwrap();

    let rpcs = drain_rpcs(queues.get_mut(&peers[0]).unwrap());
    let (publishes, preambles, fragments) = count_kinds(&rpcs);
    assert_eq!(publishes, 0);
    assert_eq!(
        preambles, 0,
        "under the PREAMBLE threshold nothing is announced"
    );
    assert_eq!(fragments, 2);
}

#[test]
fn test_publish_sends_whole_message_to_non_v14_peer() {
    let (mut gs, peers, mut queues, _) = large_network(large_send_config(), 1);

    gs.publish(Topic::new(LARGE_TOPIC), vec![1u8; 100_000])
        .unwrap();

    let rpcs = drain_rpcs(queues.get_mut(&peers[0]).unwrap());
    let (publishes, preambles, fragments) = count_kinds(&rpcs);
    assert_eq!(publishes, 1, "a legacy peer gets the whole message");
    assert_eq!(preambles, 0);
    assert_eq!(fragments, 0);
}

#[test]
fn test_publish_mixed_mesh_sends_fragments_and_whole_message() {
    let (mut gs, peers, mut queues, _) = large_network(large_send_config(), 2);
    advertise_large_messages(&mut gs, peers[0]);

    gs.publish(Topic::new(LARGE_TOPIC), vec![1u8; 100_000])
        .unwrap();

    let capable = drain_rpcs(queues.get_mut(&peers[0]).unwrap());
    let (capable_publishes, _, capable_fragments) = count_kinds(&capable);
    assert_eq!(capable_publishes, 0);
    assert_eq!(capable_fragments, 2);

    let legacy = drain_rpcs(queues.get_mut(&peers[1]).unwrap());
    let (legacy_publishes, _, legacy_fragments) = count_kinds(&legacy);
    assert_eq!(legacy_publishes, 1);
    assert_eq!(legacy_fragments, 0);
}

#[test]
fn test_publish_preamble_precedes_fragments() {
    let (mut gs, peers, mut queues, _) = large_network(preamble_config(), 1);
    advertise_large_messages(&mut gs, peers[0]);

    gs.publish(Topic::new(LARGE_TOPIC), vec![1u8; 100_000])
        .unwrap();

    let rpcs = drain_rpcs(queues.get_mut(&peers[0]).unwrap());
    let first_preamble = rpcs
        .iter()
        .position(|rpc| matches!(rpc, RpcOut::Preamble(_)))
        .unwrap();
    let first_fragment = rpcs
        .iter()
        .position(|rpc| matches!(rpc, RpcOut::LargeMessageFragment { .. }))
        .unwrap();
    assert!(
        first_preamble < first_fragment,
        "the PREAMBLE must pop before any fragment"
    );
}

#[test]
fn test_publish_over_topic_limit_still_errors_message_too_large() {
    let (mut gs, _, _, _) = large_network(large_send_config(), 1);

    let result = gs.publish(Topic::new(LARGE_TOPIC), vec![1u8; (1 << 17) + 1]);
    assert!(
        matches!(result, Err(PublishError::MessageTooLarge)),
        "fragmentation raises no transmit ceiling"
    );
}

#[test]
fn test_publish_unchanged_when_extension_disabled() {
    let config = ConfigBuilder::default()
        .max_transmit_size(1 << 17)
        .build()
        .unwrap();
    let (mut gs, peers, mut queues, _) = large_network(config, 1);
    advertise_large_messages(&mut gs, peers[0]);

    gs.publish(Topic::new(LARGE_TOPIC), vec![1u8; 100_000])
        .unwrap();

    let rpcs = drain_rpcs(queues.get_mut(&peers[0]).unwrap());
    let (publishes, preambles, fragments) = count_kinds(&rpcs);
    assert_eq!(publishes, 1, "disabled config publishes exactly as before");
    assert_eq!(preambles, 0);
    assert_eq!(fragments, 0);
}

#[test]
fn test_publish_skips_a_peer_without_room_for_the_whole_message() {
    let (mut gs, peers, mut queues, topic_hashes) = large_network(preamble_config(), 2);
    advertise_large_messages(&mut gs, peers[0]);
    advertise_large_messages(&mut gs, peers[1]);

    // Leave a single fragment slot on the first peer: not enough for the run.
    let filler_id = MessageId::new(b"filler");
    fill_fragment_tier(
        queues.get_mut(&peers[0]).unwrap(),
        127,
        &filler_id,
        &topic_hashes[0],
    );
    assert_eq!(
        queues
            .get(&peers[0])
            .unwrap()
            .fragments_remaining_capacity(),
        1
    );

    gs.publish(Topic::new(LARGE_TOPIC), vec![1u8; 100_000])
        .unwrap();

    let full = drain_rpcs(queues.get_mut(&peers[0]).unwrap());
    let new_fragments = full
        .iter()
        .filter(|rpc| {
            matches!(rpc, RpcOut::LargeMessageFragment { fragment, .. }
                if fragment.message_id != filler_id)
        })
        .count();
    let (_, full_preambles, _) = count_kinds(&full);
    assert_eq!(new_fragments, 0, "a skipped peer gets no fragment at all");
    assert_eq!(full_preambles, 0, "a skipped peer gets no PREAMBLE either");

    let open = drain_rpcs(queues.get_mut(&peers[1]).unwrap());
    let (_, open_preambles, open_fragments) = count_kinds(&open);
    assert_eq!(open_preambles, 1);
    assert_eq!(open_fragments, 2);
}

#[test]
fn test_publish_errors_all_queues_full_when_no_peer_has_room() {
    let (mut gs, peers, mut queues, topic_hashes) = large_network(large_send_config(), 1);
    advertise_large_messages(&mut gs, peers[0]);

    let filler_id = MessageId::new(b"filler");
    fill_fragment_tier(
        queues.get_mut(&peers[0]).unwrap(),
        128,
        &filler_id,
        &topic_hashes[0],
    );

    let result = gs.publish(Topic::new(LARGE_TOPIC), vec![1u8; 100_000]);
    assert!(
        matches!(result, Err(PublishError::AllQueuesFull(_))),
        "no peer took a usable message"
    );
}

#[test]
fn test_publish_returns_ok_when_one_peer_took_the_whole_message() {
    let (mut gs, peers, mut queues, topic_hashes) = large_network(large_send_config(), 2);
    advertise_large_messages(&mut gs, peers[0]);
    advertise_large_messages(&mut gs, peers[1]);

    let filler_id = MessageId::new(b"filler");
    fill_fragment_tier(
        queues.get_mut(&peers[0]).unwrap(),
        128,
        &filler_id,
        &topic_hashes[0],
    );

    gs.publish(Topic::new(LARGE_TOPIC), vec![1u8; 100_000])
        .unwrap();

    let open = drain_rpcs(queues.get_mut(&peers[1]).unwrap());
    let (_, _, open_fragments) = count_kinds(&open);
    assert_eq!(open_fragments, 2, "the peer with room gets the whole run");
}

#[test]
fn test_idontwant_on_publish_still_sent_to_v14_recipients() {
    let config = ConfigBuilder::default()
        .max_transmit_size(1 << 17)
        .large_message_handling(true)
        .idontwant_on_publish(true)
        .build()
        .unwrap();
    let (mut gs, peers, mut queues, _) = DefaultBehaviourTestBuilder::default()
        .peer_no(1)
        .topics(vec![String::from(LARGE_TOPIC)])
        .to_subscribe(true)
        .gs_config(config)
        .peer_kind(PeerKind::Gossipsubv1_3)
        .create_network();
    advertise_large_messages(&mut gs, peers[0]);

    gs.publish(Topic::new(LARGE_TOPIC), vec![1u8; 100_000])
        .unwrap();

    let rpcs = drain_rpcs(queues.get_mut(&peers[0]).unwrap());
    let idontwants = rpcs
        .iter()
        .filter(|rpc| matches!(rpc, RpcOut::IDontWant(_)))
        .count();
    let (_, _, fragments) = count_kinds(&rpcs);
    assert_eq!(idontwants, 1, "IDONTWANT-on-publish also covers v1.4 peers");
    assert_eq!(fragments, 2);
}

// ---- gossipsub v1.4 Large Message Handling: staggered sending (Stage 5) ----

/// A `peer_no`-peer network on [`LARGE_TOPIC`] wired with `config`, every
/// peer advertising the Large Message Handling extension.
#[allow(clippy::type_complexity)]
fn stagger_network(
    config: Config,
    peer_no: usize,
) -> (
    Behaviour,
    Vec<PeerId>,
    HashMap<PeerId, Queue>,
    Vec<TopicHash>,
) {
    let (mut gs, peers, queues, topic_hashes) = large_network(config, peer_no);
    peers
        .iter()
        .for_each(|peer_id| advertise_large_messages(&mut gs, *peer_id));
    (gs, peers, queues, topic_hashes)
}

/// Makes every queued staggered send due immediately.
fn make_all_due(gs: &mut Behaviour) {
    let now = Instant::now();
    gs.stagger_queue
        .iter_mut()
        .for_each(|entry| entry.due = now);
}

/// A minimal raw message for filling stagger tables in tests.
fn filler_message(topic: &TopicHash) -> RawMessage {
    RawMessage {
        source: None,
        data: vec![],
        sequence_number: None,
        topic: topic.clone(),
        signature: None,
        key: None,
        validated: false,
    }
}

#[test]
fn test_stagger_below_threshold_sends_simultaneously() {
    let config = ConfigBuilder::default()
        .max_transmit_size(1 << 17)
        .large_message_handling(true)
        .stagger_threshold(1 << 20)
        .build()
        .unwrap();
    let (mut gs, peers, mut queues, _) = stagger_network(config, 3);

    gs.publish(Topic::new(LARGE_TOPIC), vec![1u8; 100_000])
        .unwrap();

    peers.iter().for_each(|peer_id| {
        let (_, _, fragments) = count_kinds(&drain_rpcs(queues.get_mut(peer_id).unwrap()));
        assert_eq!(
            fragments, 2,
            "below the threshold every peer is sent at once"
        );
    });
    assert!(gs.stagger_queue.is_empty());
    assert!(gs.stagger_payloads.is_empty());
}

#[test]
fn test_stagger_above_threshold_delays_successive_peers() {
    let (mut gs, peers, mut queues, _) = stagger_network(large_send_config(), 3);

    let message_id = gs
        .publish(Topic::new(LARGE_TOPIC), vec![1u8; 100_000])
        .unwrap();

    let immediate = peers
        .iter()
        .filter(|peer_id| {
            let (_, _, fragments) = count_kinds(&drain_rpcs(queues.get_mut(peer_id).unwrap()));
            fragments == 2
        })
        .count();
    assert_eq!(immediate, 1, "only the first peer is sent right away");
    assert_eq!(gs.stagger_queue.len(), 2);
    let dues: Vec<Instant> = gs.stagger_queue.iter().map(|entry| entry.due).collect();
    assert_eq!(
        dues[1].duration_since(dues[0]),
        gs.config.stagger_interval(),
        "successive sends are one stagger interval apart"
    );
    assert_eq!(gs.stagger_payloads.get(&message_id).unwrap().pending, 2);
}

#[test]
fn test_stagger_disabled_with_zero_interval() {
    let config = ConfigBuilder::default()
        .max_transmit_size(1 << 17)
        .large_message_handling(true)
        .stagger_interval(Duration::ZERO)
        .build()
        .unwrap();
    let (mut gs, peers, mut queues, _) = stagger_network(config, 3);

    gs.publish(Topic::new(LARGE_TOPIC), vec![1u8; 100_000])
        .unwrap();

    peers.iter().for_each(|peer_id| {
        let (_, _, fragments) = count_kinds(&drain_rpcs(queues.get_mut(peer_id).unwrap()));
        assert_eq!(fragments, 2, "a zero interval disables staggering");
    });
    assert!(gs.stagger_queue.is_empty());
}

#[test]
fn test_stagger_skips_peer_that_idontwanted_mid_window() {
    let (mut gs, _, mut queues, _) = stagger_network(large_send_config(), 3);

    let message_id = gs
        .publish(Topic::new(LARGE_TOPIC), vec![1u8; 100_000])
        .unwrap();
    let queued: Vec<PeerId> = gs.stagger_queue.iter().map(|entry| entry.peer_id).collect();
    assert_eq!(queued.len(), 2);

    // The IDONTWANT lands during the stagger window.
    gs.connected_peers
        .get_mut(&queued[0])
        .unwrap()
        .dont_send
        .insert(message_id.clone(), Instant::now());
    make_all_due(&mut gs);
    gs.flush_staggered_sends();

    let (_, _, suppressed) = count_kinds(&drain_rpcs(queues.get_mut(&queued[0]).unwrap()));
    assert_eq!(suppressed, 0, "the peer that said IDONTWANT is skipped");
    let (_, _, delivered) = count_kinds(&drain_rpcs(queues.get_mut(&queued[1]).unwrap()));
    assert_eq!(delivered, 2);
    assert!(gs.stagger_queue.is_empty());
    assert!(gs.stagger_payloads.is_empty());
    assert_eq!(gs.stagger_bytes, 0);
}

#[test]
fn test_stagger_skips_peer_that_imreceived_mid_window() {
    let (mut gs, _, mut queues, _) = stagger_network(large_send_config(), 3);

    let message_id = gs
        .publish(Topic::new(LARGE_TOPIC), vec![1u8; 100_000])
        .unwrap();
    let queued: Vec<PeerId> = gs.stagger_queue.iter().map(|entry| entry.peer_id).collect();
    assert_eq!(queued.len(), 2);

    // The IMRECEIVING lands during the stagger window.
    gs.connected_peers
        .get_mut(&queued[0])
        .unwrap()
        .imreceiving
        .insert(message_id.clone(), Instant::now());
    make_all_due(&mut gs);
    gs.flush_staggered_sends();

    let (_, _, suppressed) = count_kinds(&drain_rpcs(queues.get_mut(&queued[0]).unwrap()));
    assert_eq!(suppressed, 0, "the peer that said IMRECEIVING is skipped");
    let (_, _, delivered) = count_kinds(&drain_rpcs(queues.get_mut(&queued[1]).unwrap()));
    assert_eq!(delivered, 2);
    assert!(gs.stagger_payloads.is_empty());
}

#[test]
fn test_stagger_skips_disconnected_peer() {
    let (mut gs, _, mut queues, _) = stagger_network(large_send_config(), 3);

    gs.publish(Topic::new(LARGE_TOPIC), vec![1u8; 100_000])
        .unwrap();
    let queued: Vec<PeerId> = gs.stagger_queue.iter().map(|entry| entry.peer_id).collect();
    assert_eq!(queued.len(), 2);

    // The peer drops mid-window; the flush re-check must notice.
    gs.connected_peers.remove(&queued[0]);
    make_all_due(&mut gs);
    gs.flush_staggered_sends();

    let (_, _, suppressed) = count_kinds(&drain_rpcs(queues.get_mut(&queued[0]).unwrap()));
    assert_eq!(suppressed, 0, "a disconnected peer gets nothing");
    let (_, _, delivered) = count_kinds(&drain_rpcs(queues.get_mut(&queued[1]).unwrap()));
    assert_eq!(delivered, 2);
    assert!(gs.stagger_payloads.is_empty());
}

#[test]
fn test_stagger_skips_peer_pruned_from_mesh_mid_window() {
    let (mut gs, _, mut queues, topic_hashes) = stagger_network(large_send_config(), 3);

    gs.publish(Topic::new(LARGE_TOPIC), vec![1u8; 100_000])
        .unwrap();
    let queued: Vec<PeerId> = gs.stagger_queue.iter().map(|entry| entry.peer_id).collect();
    assert_eq!(queued.len(), 2);

    gs.mesh
        .get_mut(&topic_hashes[0])
        .unwrap()
        .remove(&queued[0]);
    make_all_due(&mut gs);
    gs.flush_staggered_sends();

    let (_, _, suppressed) = count_kinds(&drain_rpcs(queues.get_mut(&queued[0]).unwrap()));
    assert_eq!(suppressed, 0, "a peer pruned mid-window gets nothing");
    let (_, _, delivered) = count_kinds(&drain_rpcs(queues.get_mut(&queued[1]).unwrap()));
    assert_eq!(delivered, 2);
    assert!(gs.stagger_payloads.is_empty());
}

#[test]
fn test_stagger_delivers_to_non_mesh_recipients() {
    let (mut gs, peers, mut queues, topic_hashes) = stagger_network(large_send_config(), 3);
    // Flood publish (the default) admits every subscribed peer as a
    // recipient; empty the mesh so all three are deliberate non-mesh
    // recipients, as explicit, floodsub, fanout and flood-publish peers are.
    gs.mesh.get_mut(&topic_hashes[0]).unwrap().clear();

    gs.publish(Topic::new(LARGE_TOPIC), vec![1u8; 100_000])
        .unwrap();
    make_all_due(&mut gs);
    gs.flush_staggered_sends();

    peers.iter().for_each(|peer_id| {
        let (_, _, fragments) = count_kinds(&drain_rpcs(queues.get_mut(peer_id).unwrap()));
        assert_eq!(fragments, 2, "a non-mesh recipient keeps its deferred send");
    });
    assert!(gs.stagger_queue.is_empty());
    assert!(gs.stagger_payloads.is_empty());
    assert_eq!(gs.stagger_bytes, 0);
}

#[test]
fn test_stagger_deadline_flushes_remaining_peers() {
    let (mut gs, _, mut queues, _) = stagger_network(large_send_config(), 4);

    let message_id = gs
        .publish(Topic::new(LARGE_TOPIC), vec![1u8; 100_000])
        .unwrap();
    let queued: Vec<PeerId> = gs.stagger_queue.iter().map(|entry| entry.peer_id).collect();
    assert_eq!(queued.len(), 3);

    // Expire the whole message without making any single send due.
    gs.stagger_payloads.get_mut(&message_id).unwrap().deadline = Instant::now();
    gs.flush_staggered_sends();

    queued.iter().for_each(|peer_id| {
        let (_, _, fragments) = count_kinds(&drain_rpcs(queues.get_mut(peer_id).unwrap()));
        assert_eq!(
            fragments, 2,
            "the deadline flushes every remaining peer at once"
        );
    });
    assert!(gs.stagger_queue.is_empty());
    assert!(gs.stagger_payloads.is_empty());
}

#[test]
fn test_stagger_entry_cap_falls_back_to_immediate_send() {
    let (mut gs, peers, mut queues, topic_hashes) = stagger_network(large_send_config(), 3);

    // Fill the queue to the cap, so the deferred sends cannot be admitted.
    let filler_peer = PeerId::random();
    (0..STAGGER_CAP).for_each(|_| {
        gs.stagger_queue.push_back(StaggeredSend {
            peer_id: filler_peer,
            message_id: MessageId::new(b"stagger-filler"),
            topic_hash: topic_hashes[0].clone(),
            queue_duration: Duration::from_secs(5),
            due: Instant::now() + Duration::from_secs(60),
            mesh_member: false,
        });
    });

    gs.publish(Topic::new(LARGE_TOPIC), vec![1u8; 100_000])
        .unwrap();

    peers.iter().for_each(|peer_id| {
        let (_, _, fragments) = count_kinds(&drain_rpcs(queues.get_mut(peer_id).unwrap()));
        assert_eq!(
            fragments, 2,
            "over the cap the message goes out immediately"
        );
    });
    assert_eq!(gs.stagger_queue.len(), STAGGER_CAP);
}

#[test]
fn test_stagger_message_cap_falls_back_to_immediate_send() {
    let (mut gs, peers, mut queues, topic_hashes) = stagger_network(large_send_config(), 3);

    (0..MAX_STAGGERED_MESSAGES).for_each(|i| {
        gs.stagger_payloads.insert(
            MessageId::from(format!("stagger-filler-{i}")),
            StaggeredMessage {
                payload: StaggerPayload::Whole(Arc::new(filler_message(&topic_hashes[0]))),
                bytes: 0,
                pending: 1,
                deadline: Instant::now() + Duration::from_secs(60),
            },
        );
    });

    gs.publish(Topic::new(LARGE_TOPIC), vec![1u8; 100_000])
        .unwrap();

    peers.iter().for_each(|peer_id| {
        let (_, _, fragments) = count_kinds(&drain_rpcs(queues.get_mut(peer_id).unwrap()));
        assert_eq!(
            fragments, 2,
            "over the cap the message goes out immediately"
        );
    });
    assert_eq!(gs.stagger_payloads.len(), MAX_STAGGERED_MESSAGES);
}

#[test]
fn test_stagger_byte_cap_falls_back_to_immediate_send() {
    let (mut gs, peers, mut queues, _) = stagger_network(large_send_config(), 3);

    gs.stagger_bytes = MAX_STAGGER_BYTES;

    gs.publish(Topic::new(LARGE_TOPIC), vec![1u8; 100_000])
        .unwrap();

    peers.iter().for_each(|peer_id| {
        let (_, _, fragments) = count_kinds(&drain_rpcs(queues.get_mut(peer_id).unwrap()));
        assert_eq!(
            fragments, 2,
            "over the cap the message goes out immediately"
        );
    });
    assert!(gs.stagger_queue.is_empty());
    assert_eq!(gs.stagger_bytes, MAX_STAGGER_BYTES);
}

#[test]
fn test_stagger_cancelled_on_reject_validation_result() {
    let (mut gs, _, _queues, _) = stagger_network(large_send_config(), 3);

    let message_id = gs
        .publish(Topic::new(LARGE_TOPIC), vec![1u8; 100_000])
        .unwrap();
    assert_eq!(gs.stagger_queue.len(), 2);

    gs.report_message_validation_result(&message_id, &PeerId::random(), MessageAcceptance::Reject);

    assert!(
        gs.stagger_queue.is_empty(),
        "a rejected message stops staggering"
    );
    assert!(gs.stagger_payloads.is_empty());
    assert_eq!(gs.stagger_bytes, 0);
}

#[test]
fn test_preamble_is_not_staggered() {
    let (mut gs, peers, mut queues, _) = stagger_network(preamble_config(), 3);

    gs.publish(Topic::new(LARGE_TOPIC), vec![1u8; 100_000])
        .unwrap();

    let counts: Vec<(usize, usize)> = peers
        .iter()
        .map(|peer_id| {
            let (_, preambles, fragments) =
                count_kinds(&drain_rpcs(queues.get_mut(peer_id).unwrap()));
            (preambles, fragments)
        })
        .collect();
    assert!(
        counts.iter().all(|(preambles, _)| *preambles == 1),
        "every recipient gets its PREAMBLE immediately"
    );
    assert_eq!(
        counts
            .iter()
            .filter(|(_, fragments)| *fragments == 2)
            .count(),
        1,
        "only the first peer gets its fragments immediately"
    );
    assert_eq!(gs.stagger_queue.len(), 2);
}

#[test]
fn test_stagger_payload_is_shared_not_cloned_per_peer() {
    let (mut gs, _, _queues, _) = stagger_network(large_send_config(), 4);

    let message_id = gs
        .publish(Topic::new(LARGE_TOPIC), vec![1u8; 100_000])
        .unwrap();

    let staggered = gs.stagger_payloads.get(&message_id).unwrap();
    assert_eq!(staggered.pending, 3);
    match &staggered.payload {
        StaggerPayload::Fragments(fragments) => {
            assert_eq!(
                Arc::strong_count(fragments),
                1,
                "one shared copy, not one per peer"
            );
            assert_eq!(
                staggered.bytes,
                fragments
                    .iter()
                    .map(|fragment| fragment.fragment_data.len())
                    .sum::<usize>()
            );
        }
        StaggerPayload::Whole(_) => panic!("capable peers stagger fragment runs"),
    }
}

#[test]
fn test_stagger_drops_entries_for_disconnected_peer() {
    let (mut gs, _, _queues, _) = stagger_network(large_send_config(), 3);

    let message_id = gs
        .publish(Topic::new(LARGE_TOPIC), vec![1u8; 100_000])
        .unwrap();
    let queued: Vec<PeerId> = gs.stagger_queue.iter().map(|entry| entry.peer_id).collect();
    assert_eq!(queued.len(), 2);

    disconnect_peer(&mut gs, &queued[0]);

    assert!(
        gs.stagger_queue
            .iter()
            .all(|entry| entry.peer_id != queued[0]),
        "the departing peer's entries are dropped"
    );
    assert_eq!(gs.stagger_queue.len(), 1);
    assert_eq!(gs.stagger_payloads.get(&message_id).unwrap().pending, 1);
}

#[test]
fn test_stagger_peer_order_is_score_descending() {
    let (mut gs, peers, mut queues, _) = DefaultBehaviourTestBuilder::default()
        .peer_no(3)
        .topics(vec![String::from(LARGE_TOPIC)])
        .to_subscribe(true)
        .gs_config(large_send_config())
        .scoring(Some((
            PeerScoreParams::default(),
            PeerScoreThresholds::default(),
        )))
        .create_network();
    peers
        .iter()
        .for_each(|peer_id| advertise_large_messages(&mut gs, *peer_id));
    gs.set_application_score(&peers[0], 1.0);
    gs.set_application_score(&peers[1], 3.0);
    gs.set_application_score(&peers[2], 2.0);

    gs.publish(Topic::new(LARGE_TOPIC), vec![1u8; 100_000])
        .unwrap();

    let (_, _, fragments) = count_kinds(&drain_rpcs(queues.get_mut(&peers[1]).unwrap()));
    assert_eq!(fragments, 2, "the best-scored peer is served first");
    let queued: Vec<PeerId> = gs.stagger_queue.iter().map(|entry| entry.peer_id).collect();
    assert_eq!(
        queued,
        vec![peers[2], peers[0]],
        "deferred sends follow in descending score order"
    );
}
