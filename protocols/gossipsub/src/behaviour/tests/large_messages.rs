//! Behaviour tests for the gossipsub v1.4 Large Message Handling extension:
//! fragment reassembly, consistency checks, resource caps, PREAMBLE handling,
//! poisoning, and the disabled-by-default gate.

use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use libp2p_identity::{Keypair, PeerId};
use libp2p_swarm::{ConnectionId, NetworkBehaviour, ToSwarm};
use prost::Message as _;

use super::{
    super::{FRAGMENTS_RELAYED_CAP, IMRECEIVING_CAP},
    DefaultBehaviourTestBuilder, count_control_msgs, disconnect_peer,
};
#[cfg(feature = "partial-messages")]
use crate::types::SubscriptionOpts;
use crate::{
    Behaviour, DataTransform, Event, IdentTopic as Topic, MessageAcceptance, MessageAuthenticity,
    PeerScoreParams, PeerScoreThresholds, PublishError, TopicHash, TopicScoreParams,
    ValidationMode,
    config::{Config, ConfigBuilder},
    extensions::large_messages::{
        self, FRAGMENT_ENTRY_OVERHEAD, LARGE_FRAGMENT_RPC_OVERHEAD, MAX_POISONED_IDS_PER_PEER,
        MAX_REASSEMBLIES_TOTAL, MAX_RELAY_RECORDS, MAX_SENDERS_PER_MESSAGE,
        RELAY_BYTES_PER_HEARTBEAT, RELAY_COOLDOWN,
    },
    handler::HandlerEvent,
    queue::Queue,
    rpc_proto::proto,
    types::{
        ControlAction, Extensions, IDontWant, IWant, ImReceiving, LargeMessageFragment, MessageId,
        PeerKind, Preamble, RpcIn, RpcOut,
    },
};

const TOPIC: &str = "large-topic";

/// A config with Large Message Handling enabled. The extension requires a
/// `max_transmit_size` that can carry a spec-default 64 KiB fragment RPC.
/// Staggered sending is off, so every send in these suites is immediate;
/// staggering has its own tests in `publish.rs`.
fn enabled_config() -> Config {
    ConfigBuilder::default()
        .max_transmit_size(1 << 17)
        .large_message_handling(true)
        .stagger_interval(Duration::ZERO)
        .build()
        .unwrap()
}

/// One-topic test network wired with `config` and optional scoring.
#[allow(clippy::type_complexity)]
fn network_with(
    config: Config,
    peer_no: usize,
    scoring: Option<(PeerScoreParams, PeerScoreThresholds)>,
) -> (
    Behaviour,
    Vec<PeerId>,
    HashMap<PeerId, Queue>,
    Vec<TopicHash>,
) {
    DefaultBehaviourTestBuilder::default()
        .peer_no(peer_no)
        .topics(vec![String::from(TOPIC)])
        .to_subscribe(true)
        .gs_config(config)
        .scoring(scoring)
        .create_network()
}

/// Enabled network without scoring.
#[allow(clippy::type_complexity)]
fn enabled_network(
    peer_no: usize,
) -> (
    Behaviour,
    Vec<PeerId>,
    HashMap<PeerId, Queue>,
    Vec<TopicHash>,
) {
    network_with(enabled_config(), peer_no, None)
}

/// Enabled network with scoring whose positive topic weights are zeroed, so
/// any negative score is attributable to P4 or P7 alone.
#[allow(clippy::type_complexity)]
fn scored_network(
    peer_no: usize,
) -> (
    Behaviour,
    Vec<PeerId>,
    HashMap<PeerId, Queue>,
    Vec<TopicHash>,
) {
    network_with(enabled_config(), peer_no, Some(quiet_scoring()))
}

/// Topic params with every reward and drift weight zeroed.
fn quiet_topic_params() -> TopicScoreParams {
    TopicScoreParams {
        time_in_mesh_weight: 0.0,
        first_message_deliveries_weight: 0.0,
        mesh_message_deliveries_weight: 0.0,
        ..TopicScoreParams::default()
    }
}

/// Scoring params covering [`TOPIC`] with [`quiet_topic_params`].
fn quiet_scoring() -> (PeerScoreParams, PeerScoreThresholds) {
    let mut params = PeerScoreParams::default();
    params
        .topics
        .insert(Topic::new(TOPIC).hash(), quiet_topic_params());
    (params, PeerScoreThresholds::default())
}

/// Reads the peer's current score.
fn score(gs: &mut Behaviour, peer_id: &PeerId) -> f64 {
    gs.as_peer_score_mut().score_report(peer_id).score
}

/// Injects one RPC from `peer` into the behaviour.
fn deliver(
    gs: &mut Behaviour,
    peer: PeerId,
    control_msgs: Vec<ControlAction>,
    large_message_fragments: Vec<LargeMessageFragment>,
) {
    gs.on_connection_handler_event(
        peer,
        ConnectionId::new_unchecked(0),
        HandlerEvent::Message {
            rpc: RpcIn {
                messages: vec![],
                subscriptions: vec![],
                control_msgs,
                large_message_fragments,
                #[cfg(feature = "partial-messages")]
                partial_message: None,
            },
            invalid_messages: vec![],
        },
    );
}

/// Injects fragments from `peer`.
fn deliver_fragments(gs: &mut Behaviour, peer: PeerId, fragments: Vec<LargeMessageFragment>) {
    deliver(gs, peer, vec![], fragments);
}

/// Injects one PREAMBLE from `peer`.
fn deliver_preamble(gs: &mut Behaviour, peer: PeerId, preamble: Preamble) {
    deliver(gs, peer, vec![ControlAction::Preamble(preamble)], vec![]);
}

/// Builds a message signed by a fresh remote identity. Returns the message id
/// the local node computes for it and the encoded `proto::Message` bytes a
/// sender would fragment.
fn signed_message(
    gs: &mut Behaviour,
    topic_hash: &TopicHash,
    data: Vec<u8>,
) -> (MessageId, Vec<u8>) {
    let mut sender: Behaviour = Behaviour::new(
        MessageAuthenticity::Signed(Keypair::generate_ed25519()),
        Config::default(),
    )
    .unwrap();
    let raw = sender.build_raw_message(topic_hash.clone(), data).unwrap();
    let message = gs.data_transform.inbound_transform(raw.clone()).unwrap();
    let message_id = gs.config.message_id(&message);
    let proto_message: proto::Message = raw.into();
    (message_id, proto_message.encode_to_vec())
}

/// Splits `encoded` into fragments of at most `chunk` bytes, sender-style:
/// every non-final fragment is exactly `chunk` bytes.
fn fragments_for(
    encoded: &[u8],
    chunk: usize,
    message_id: &MessageId,
    topic_hash: &TopicHash,
) -> Vec<LargeMessageFragment> {
    let total = u32::try_from(encoded.len().div_ceil(chunk)).unwrap();
    encoded
        .chunks(chunk)
        .enumerate()
        .map(|(index, fragment_data)| LargeMessageFragment {
            message_id: message_id.clone(),
            fragment_index: u32::try_from(index).unwrap(),
            total_fragments: total,
            fragment_data: fragment_data.to_vec(),
            topic_hash: topic_hash.clone(),
        })
        .collect()
}

/// One synthetic fragment with `len` filler bytes.
fn make_fragment(
    message_id: &MessageId,
    index: u32,
    total: u32,
    len: usize,
    topic_hash: &TopicHash,
) -> LargeMessageFragment {
    LargeMessageFragment {
        message_id: message_id.clone(),
        fragment_index: index,
        total_fragments: total,
        fragment_data: vec![7u8; len],
        topic_hash: topic_hash.clone(),
    }
}

/// Permissive limits for driving `large_messages::State` directly.
fn wide_limits() -> large_messages::Limits {
    large_messages::Limits {
        max_inbound_fragment_bytes: 1 << 20,
        fragment_timeout: Duration::from_secs(30),
        max_pending_fragments: 16,
        max_reassembly_bytes_per_peer: 1 << 20,
        max_reassembly_bytes_total: 1 << 26,
        max_preamble_announcements_per_peer: 16,
        max_message_bytes: 1 << 20,
        preamble_threshold: 400 << 10,
    }
}

#[test]
fn test_fragments_reassemble_in_order() {
    let (mut gs, peers, _queues, topic_hashes) = enabled_network(1);
    let (message_id, encoded) = signed_message(&mut gs, &topic_hashes[0], vec![11u8; 96]);
    let chunk = encoded.len().div_ceil(3);
    let fragments = fragments_for(&encoded, chunk, &message_id, &topic_hashes[0]);
    assert_eq!(fragments.len(), 3);

    deliver_fragments(&mut gs, peers[0], fragments);

    assert!(
        gs.duplicate_cache.contains(&message_id),
        "the reassembled message should reach the receive pipeline"
    );
    assert_eq!(gs.large_messages.total_bytes(), 0);
    assert_eq!(gs.large_messages.total_reassemblies(), 0);
    assert_eq!(gs.large_messages.senders_for(&message_id), 0);
}

#[test]
fn test_fragments_reassemble_out_of_order() {
    let (mut gs, peers, _queues, topic_hashes) = enabled_network(1);
    let (message_id, encoded) = signed_message(&mut gs, &topic_hashes[0], vec![13u8; 96]);
    let chunk = encoded.len().div_ceil(3);
    let fragments = fragments_for(&encoded, chunk, &message_id, &topic_hashes[0]);
    assert_eq!(fragments.len(), 3);

    fragments
        .into_iter()
        .rev()
        .for_each(|fragment| deliver_fragments(&mut gs, peers[0], vec![fragment]));

    assert!(
        gs.duplicate_cache.contains(&message_id),
        "delivery order must not matter for reassembly"
    );
    assert_eq!(gs.large_messages.total_bytes(), 0);
    assert_eq!(gs.large_messages.total_reassemblies(), 0);
}

#[test]
fn test_duplicate_fragment_index_is_ignored() {
    let (mut gs, peers, _queues, topic_hashes) = enabled_network(1);
    let (message_id, encoded) = signed_message(&mut gs, &topic_hashes[0], vec![17u8; 96]);
    let chunk = encoded.len().div_ceil(3);
    let fragments = fragments_for(&encoded, chunk, &message_id, &topic_hashes[0]);
    let mut iter = fragments.into_iter();
    let first = iter.next().unwrap();

    deliver_fragments(&mut gs, peers[0], vec![first.clone()]);
    let charged = gs.large_messages.total_bytes();
    assert_eq!(charged, chunk + FRAGMENT_ENTRY_OVERHEAD);

    deliver_fragments(&mut gs, peers[0], vec![first]);
    assert_eq!(
        gs.large_messages.total_bytes(),
        charged,
        "a duplicate index must not charge the budget again"
    );

    iter.for_each(|fragment| deliver_fragments(&mut gs, peers[0], vec![fragment]));
    assert!(
        gs.duplicate_cache.contains(&message_id),
        "a tolerated duplicate must not break the transfer"
    );
    assert_eq!(gs.large_messages.total_bytes(), 0);
}

#[test]
fn test_excessive_duplicate_indices_applies_p7() {
    let config = ConfigBuilder::default()
        .max_transmit_size(1 << 17)
        .large_message_handling(true)
        .max_pending_fragments(2)
        .build()
        .unwrap();
    let (mut gs, peers, _queues, topic_hashes) = network_with(config, 1, Some(quiet_scoring()));
    let message_id = MessageId::new(b"dup-heavy");
    let fragment = make_fragment(&message_id, 0, 3, 64, &topic_hashes[0]);

    deliver_fragments(&mut gs, peers[0], vec![fragment.clone()]);
    deliver_fragments(&mut gs, peers[0], vec![fragment.clone(), fragment.clone()]);
    assert!(
        score(&mut gs, &peers[0]).abs() < f64::EPSILON,
        "tolerated duplicates must not be penalized"
    );

    deliver_fragments(&mut gs, peers[0], vec![fragment]);
    assert!(
        score(&mut gs, &peers[0]) < 0.0,
        "excessive duplicates must apply P7"
    );
}

#[test]
fn test_total_fragments_mismatch_drops_buffer_and_penalizes() {
    let (mut gs, peers, _queues, topic_hashes) = scored_network(1);
    let message_id = MessageId::new(b"total-mismatch");

    deliver_fragments(
        &mut gs,
        peers[0],
        vec![make_fragment(&message_id, 0, 3, 64, &topic_hashes[0])],
    );
    assert_eq!(gs.large_messages.pending_reassemblies(&peers[0]), 1);

    deliver_fragments(
        &mut gs,
        peers[0],
        vec![make_fragment(&message_id, 1, 4, 64, &topic_hashes[0])],
    );
    assert_eq!(gs.large_messages.pending_reassemblies(&peers[0]), 0);
    assert_eq!(gs.large_messages.total_bytes(), 0);
    assert_eq!(gs.large_messages.senders_for(&message_id), 0);
    assert!(score(&mut gs, &peers[0]) < 0.0, "check 1 must apply P4");
}

#[test]
fn test_non_final_fragment_length_must_match_the_first_one() {
    let (mut gs, peers, _queues, topic_hashes) = scored_network(1);
    let message_id = MessageId::new(b"len-mismatch");

    deliver_fragments(
        &mut gs,
        peers[0],
        vec![make_fragment(&message_id, 0, 3, 100, &topic_hashes[0])],
    );
    deliver_fragments(
        &mut gs,
        peers[0],
        vec![make_fragment(&message_id, 1, 3, 99, &topic_hashes[0])],
    );

    assert_eq!(gs.large_messages.pending_reassemblies(&peers[0]), 0);
    assert_eq!(gs.large_messages.total_bytes(), 0);
    assert!(score(&mut gs, &peers[0]) < 0.0, "check 3 must apply P4");
}

#[test]
fn test_foreign_chunk_size_reassembles_without_penalty() {
    // D8 regression: the sender's chunk size is whatever the transfer teaches,
    // never this node's own `fragment_size` (61440 by default).
    let (mut gs, peers, _queues, topic_hashes) = scored_network(1);
    let (message_id, encoded) = signed_message(&mut gs, &topic_hashes[0], vec![7u8; 70_000]);
    assert!(encoded.len() > 2 * 32_768);
    let fragments = fragments_for(&encoded, 32_768, &message_id, &topic_hashes[0]);

    deliver_fragments(&mut gs, peers[0], fragments);

    assert!(
        gs.duplicate_cache.contains(&message_id),
        "a 32768-byte chunk size must reassemble"
    );
    assert!(
        score(&mut gs, &peers[0]).abs() < f64::EPSILON,
        "a foreign chunk size must not be penalized"
    );
}

#[test]
fn test_final_fragment_before_any_non_final_is_rechecked() {
    let (mut gs, peers, _queues, topic_hashes) = scored_network(1);
    let message_id = MessageId::new(b"final-first");

    // The final fragment lands first; no chunk size is known yet.
    deliver_fragments(
        &mut gs,
        peers[0],
        vec![make_fragment(&message_id, 2, 3, 150, &topic_hashes[0])],
    );
    assert_eq!(gs.large_messages.pending_reassemblies(&peers[0]), 1);

    // The first non-final fragment teaches a 100-byte chunk size, which the
    // stored 150-byte final fragment violates.
    deliver_fragments(
        &mut gs,
        peers[0],
        vec![make_fragment(&message_id, 0, 3, 100, &topic_hashes[0])],
    );
    assert_eq!(gs.large_messages.pending_reassemblies(&peers[0]), 0);
    assert_eq!(gs.large_messages.total_bytes(), 0);
    assert!(
        score(&mut gs, &peers[0]) < 0.0,
        "the stored final fragment must be re-checked and apply P4"
    );
}

#[test]
fn test_inbound_fragment_over_rpc_carrying_capacity_is_dropped_at_decode() {
    // The codec enforces this bound pre-parse; feeding the behaviour directly
    // must hit the same bound in `handle_fragment`'s malformed check.
    let (mut gs, peers, _queues, topic_hashes) = enabled_network(1);
    let message_id = MessageId::new(b"oversize-fragment");
    let over_capacity = (1 << 17) - LARGE_FRAGMENT_RPC_OVERHEAD + 1;

    deliver_fragments(
        &mut gs,
        peers[0],
        vec![make_fragment(
            &message_id,
            0,
            2,
            over_capacity,
            &topic_hashes[0],
        )],
    );

    assert_eq!(gs.large_messages.pending_reassemblies(&peers[0]), 0);
    assert_eq!(gs.large_messages.total_bytes(), 0);
    assert_eq!(gs.large_messages.senders_for(&message_id), 0);
}

#[test]
fn test_topic_mismatch_drops_buffer_and_penalizes() {
    let other_topic = Topic::new("other-topic").hash();
    let (mut params, thresholds) = quiet_scoring();
    params
        .topics
        .insert(other_topic.clone(), quiet_topic_params());
    let (mut gs, peers, _queues, topic_hashes) =
        network_with(enabled_config(), 1, Some((params, thresholds)));
    let message_id = MessageId::new(b"topic-mismatch");

    deliver_fragments(
        &mut gs,
        peers[0],
        vec![make_fragment(&message_id, 0, 3, 64, &topic_hashes[0])],
    );
    deliver_fragments(
        &mut gs,
        peers[0],
        vec![make_fragment(&message_id, 1, 3, 64, &other_topic)],
    );

    assert_eq!(gs.large_messages.pending_reassemblies(&peers[0]), 0);
    assert_eq!(gs.large_messages.total_bytes(), 0);
    assert!(score(&mut gs, &peers[0]) < 0.0, "check 6 must apply P4");
}

#[test]
fn test_reassembled_size_over_topic_limit_is_rejected() {
    let config = ConfigBuilder::default()
        .max_transmit_size(1 << 17)
        .large_message_handling(true)
        .max_transmit_size_for_topic(256, Topic::new(TOPIC).hash())
        .build()
        .unwrap();
    let (mut gs, peers, _queues, topic_hashes) = network_with(config, 1, Some(quiet_scoring()));
    let message_id = MessageId::new(b"over-topic-limit");
    let payload = vec![9u8; 300];
    let fragments = fragments_for(&payload, 100, &message_id, &topic_hashes[0]);

    fragments
        .into_iter()
        .for_each(|fragment| deliver_fragments(&mut gs, peers[0], vec![fragment]));

    assert!(!gs.duplicate_cache.contains(&message_id));
    assert_eq!(gs.large_messages.pending_reassemblies(&peers[0]), 0);
    assert_eq!(gs.large_messages.total_bytes(), 0);
    assert!(
        score(&mut gs, &peers[0]) < 0.0,
        "exceeding the topic's transmit ceiling must apply P4"
    );
}

#[test]
fn test_reassembled_message_signature_is_verified() {
    let (mut gs, peers, _queues, topic_hashes) = scored_network(1);
    let mut sender: Behaviour = Behaviour::new(
        MessageAuthenticity::Signed(Keypair::generate_ed25519()),
        Config::default(),
    )
    .unwrap();
    let mut raw = sender
        .build_raw_message(topic_hashes[0].clone(), vec![3u8; 64])
        .unwrap();
    raw.signature = Some(vec![0u8; 64]);
    let proto_message: proto::Message = raw.into();
    let encoded = proto_message.encode_to_vec();
    let message_id = MessageId::new(b"tampered-signature");
    let fragments = fragments_for(
        &encoded,
        encoded.len().div_ceil(2),
        &message_id,
        &topic_hashes[0],
    );

    deliver_fragments(&mut gs, peers[0], fragments);

    assert!(!gs.duplicate_cache.contains(&message_id));
    assert_eq!(gs.large_messages.pending_reassemblies(&peers[0]), 0);
    assert!(
        score(&mut gs, &peers[0]) < 0.0,
        "an invalid signature on the reassembled message must apply P4"
    );
}

#[test]
fn test_message_id_mismatch_is_rejected_and_penalized() {
    let (mut gs, peers, _queues, topic_hashes) = scored_network(1);
    let (computed_id, encoded) = signed_message(&mut gs, &topic_hashes[0], vec![19u8; 96]);
    let wrong_id = MessageId::new(b"wrong-announced-id");
    assert_ne!(computed_id, wrong_id);
    let fragments = fragments_for(
        &encoded,
        encoded.len().div_ceil(3),
        &wrong_id,
        &topic_hashes[0],
    );

    deliver_fragments(&mut gs, peers[0], fragments);

    assert!(!gs.duplicate_cache.contains(&computed_id));
    assert!(!gs.duplicate_cache.contains(&wrong_id));
    assert!(
        gs.large_messages.is_poisoned(&peers[0], &wrong_id),
        "an id-binding failure must poison the slot"
    );
    assert!(score(&mut gs, &peers[0]) < 0.0, "check 8 must apply P4");
}

#[test]
fn test_message_id_mismatch_poisons_slot_until_timeout() {
    let (mut gs, peers, _queues, topic_hashes) = enabled_network(1);
    let (_computed_id, encoded) = signed_message(&mut gs, &topic_hashes[0], vec![23u8; 96]);
    let wrong_id = MessageId::new(b"poisoned-id");
    let fragments = fragments_for(
        &encoded,
        encoded.len().div_ceil(3),
        &wrong_id,
        &topic_hashes[0],
    );

    deliver_fragments(&mut gs, peers[0], fragments.clone());
    assert!(gs.large_messages.is_poisoned(&peers[0], &wrong_id));
    assert_eq!(gs.large_messages.poisoned_len(&peers[0]), 1);

    // While poisoned, the same transfer is refused on admission.
    deliver_fragments(&mut gs, peers[0], fragments.clone());
    assert_eq!(gs.large_messages.pending_reassemblies(&peers[0]), 0);
    assert_eq!(gs.large_messages.total_bytes(), 0);

    // The poison entry expires with `fragment_timeout`.
    let limits = gs.large_message_limits(&topic_hashes[0]);
    let actions = gs
        .large_messages
        .heartbeat(&limits, Instant::now() + gs.config.fragment_timeout());
    assert!(actions.is_empty());
    assert!(!gs.large_messages.is_poisoned(&peers[0], &wrong_id));

    // After expiry the pair is admitted again.
    let mut iter = fragments.into_iter();
    deliver_fragments(&mut gs, peers[0], vec![iter.next().unwrap()]);
    assert_eq!(gs.large_messages.pending_reassemblies(&peers[0]), 1);
}

#[test]
fn test_per_peer_pending_cap_rejects_new_without_evicting() {
    let config = ConfigBuilder::default()
        .max_transmit_size(1 << 17)
        .large_message_handling(true)
        .max_pending_fragments(2)
        .build()
        .unwrap();
    let (mut gs, peers, _queues, topic_hashes) = network_with(config, 1, None);
    let id_a = MessageId::new(b"pending-a");
    let id_b = MessageId::new(b"pending-b");
    let id_c = MessageId::new(b"pending-c");

    deliver_fragments(
        &mut gs,
        peers[0],
        vec![make_fragment(&id_a, 0, 2, 32, &topic_hashes[0])],
    );
    deliver_fragments(
        &mut gs,
        peers[0],
        vec![make_fragment(&id_b, 0, 2, 32, &topic_hashes[0])],
    );
    assert_eq!(gs.large_messages.pending_reassemblies(&peers[0]), 2);

    deliver_fragments(
        &mut gs,
        peers[0],
        vec![make_fragment(&id_c, 0, 2, 32, &topic_hashes[0])],
    );

    assert_eq!(
        gs.large_messages.pending_reassemblies(&peers[0]),
        2,
        "the reject must not evict an existing buffer"
    );
    assert_eq!(gs.large_messages.senders_for(&id_a), 1);
    assert_eq!(gs.large_messages.senders_for(&id_b), 1);
    assert_eq!(gs.large_messages.senders_for(&id_c), 0);
}

#[test]
fn test_per_peer_byte_cap_rejects_new() {
    let config = ConfigBuilder::default()
        .max_transmit_size(1 << 17)
        .large_message_handling(true)
        .max_reassembly_bytes_per_peer(2048)
        .build()
        .unwrap();
    let (mut gs, peers, _queues, topic_hashes) = network_with(config, 1, None);
    let message_id = MessageId::new(b"peer-byte-cap");

    // 2000 bytes plus the entry overhead exceed the 2048-byte peer budget.
    deliver_fragments(
        &mut gs,
        peers[0],
        vec![make_fragment(&message_id, 0, 3, 2000, &topic_hashes[0])],
    );
    assert_eq!(gs.large_messages.pending_reassemblies(&peers[0]), 1);
    assert_eq!(
        gs.large_messages.total_bytes(),
        0,
        "an over-budget fragment must not be stored"
    );

    // A fragment that fits the budget still stores.
    deliver_fragments(
        &mut gs,
        peers[0],
        vec![make_fragment(&message_id, 1, 3, 500, &topic_hashes[0])],
    );
    assert_eq!(
        gs.large_messages.total_bytes(),
        500 + FRAGMENT_ENTRY_OVERHEAD
    );
}

#[test]
fn test_global_byte_cap_rejects_new() {
    let mut state = large_messages::State::default();
    let limits = large_messages::Limits {
        max_reassembly_bytes_total: 1024,
        ..wide_limits()
    };
    let peer = PeerId::random();
    let topic_hash = Topic::new(TOPIC).hash();
    let message_id = MessageId::new(b"global-byte-cap");

    let actions = state.handle_fragment(
        &peer,
        make_fragment(&message_id, 0, 3, 1000, &topic_hash),
        false,
        &limits,
        &ValidationMode::Strict,
    );
    assert!(actions.is_empty());
    assert_eq!(state.pending_reassemblies(&peer), 1);
    assert_eq!(
        state.total_bytes(),
        0,
        "a fragment over the global byte cap must not be stored"
    );

    let actions = state.handle_fragment(
        &peer,
        make_fragment(&message_id, 1, 3, 500, &topic_hash),
        false,
        &limits,
        &ValidationMode::Strict,
    );
    assert!(
        actions
            .iter()
            .all(|action| matches!(action, large_messages::ReceivedAction::RelayFragment(_))),
        "a stored fragment's only side effect is its eager relay"
    );
    assert_eq!(state.total_bytes(), 500 + FRAGMENT_ENTRY_OVERHEAD);
}

#[test]
fn test_global_reassembly_slot_cap_rejects_new() {
    let mut state = large_messages::State::default();
    let limits = wide_limits();
    let topic_hash = Topic::new(TOPIC).hash();

    // 64 peers x 16 pending buffers fill every one of the 1024 global slots.
    (0..64u32).for_each(|peer_index| {
        let peer = PeerId::random();
        (0..16u32).for_each(|slot| {
            let message_id = MessageId::from(format!("slot-{peer_index}-{slot}"));
            let actions = state.handle_fragment(
                &peer,
                make_fragment(&message_id, 0, 2, 8, &topic_hash),
                false,
                &limits,
                &ValidationMode::Strict,
            );
            assert!(
                actions.iter().all(|action| matches!(
                    action,
                    large_messages::ReceivedAction::RelayFragment(_)
                )),
                "a stored fragment's only side effect is its eager relay"
            );
        });
    });
    assert_eq!(state.total_reassemblies(), MAX_REASSEMBLIES_TOTAL);

    let straggler = PeerId::random();
    let message_id = MessageId::new(b"one-too-many");
    let actions = state.handle_fragment(
        &straggler,
        make_fragment(&message_id, 0, 2, 8, &topic_hash),
        false,
        &limits,
        &ValidationMode::Strict,
    );
    assert!(actions.is_empty());
    assert_eq!(state.total_reassemblies(), MAX_REASSEMBLIES_TOTAL);
    assert_eq!(state.pending_reassemblies(&straggler), 0);
}

#[test]
fn test_max_senders_per_message_caps_distinct_senders() {
    let (mut gs, peers, _queues, topic_hashes) = enabled_network(4);
    let message_id = MessageId::new(b"many-senders");

    peers.iter().take(3).for_each(|peer| {
        deliver_fragments(
            &mut gs,
            *peer,
            vec![make_fragment(&message_id, 0, 2, 16, &topic_hashes[0])],
        );
    });
    assert_eq!(
        gs.large_messages.senders_for(&message_id),
        MAX_SENDERS_PER_MESSAGE
    );

    deliver_fragments(
        &mut gs,
        peers[3],
        vec![make_fragment(&message_id, 0, 2, 16, &topic_hashes[0])],
    );
    assert_eq!(
        gs.large_messages.senders_for(&message_id),
        MAX_SENDERS_PER_MESSAGE
    );
    assert_eq!(gs.large_messages.pending_reassemblies(&peers[3]), 0);
}

#[test]
fn test_mesh_sender_reclaims_slot_from_non_mesh_senders() {
    let (mut gs, peers, queues, topic_hashes) = enabled_network(5);
    // The builder meshes every subscribed peer; take the first four out so
    // they model cheap non-mesh identities, keeping only the honest sender.
    let mesh_peers = gs.mesh.get_mut(&topic_hashes[0]).unwrap();
    peers.iter().take(4).for_each(|peer| {
        mesh_peers.remove(peer);
    });
    // IMRECEIVING is a v1.4 RPC: only capable peers can receive the refusal.
    make_capable(&mut gs, peers[3]);
    make_capable(&mut gs, peers[4]);
    let message_id = MessageId::new(b"squatted-slots");

    // Three non-mesh identities fill every sender slot for the id.
    peers.iter().take(3).for_each(|peer| {
        deliver_fragments(
            &mut gs,
            *peer,
            vec![make_fragment(&message_id, 0, 2, 16, &topic_hashes[0])],
        );
    });
    assert_eq!(
        gs.large_messages.senders_for(&message_id),
        MAX_SENDERS_PER_MESSAGE
    );

    // The mesh sender must reclaim a slot rather than be refused.
    deliver_fragments(
        &mut gs,
        peers[4],
        vec![make_fragment(&message_id, 0, 2, 16, &topic_hashes[0])],
    );
    assert_eq!(
        gs.large_messages.senders_for(&message_id),
        MAX_SENDERS_PER_MESSAGE
    );
    assert_eq!(
        gs.large_messages.pending_reassemblies(&peers[4]),
        1,
        "the mesh sender must take a slot from a non-mesh sender"
    );
    let non_mesh_buffers: usize = peers
        .iter()
        .take(3)
        .map(|peer| gs.large_messages.pending_reassemblies(peer))
        .sum();
    assert_eq!(non_mesh_buffers, 2, "one non-mesh buffer must be evicted");
    let (refusals, queues) = count_control_msgs(queues, |peer_id, rpc| {
        peer_id == &peers[4] && matches!(rpc, RpcOut::ImReceiving(_))
    });
    assert_eq!(refusals, 0, "the mesh sender must not be refused");

    // Another non-mesh sender is still refused with IMRECEIVING.
    deliver_fragments(
        &mut gs,
        peers[3],
        vec![make_fragment(&message_id, 0, 2, 16, &topic_hashes[0])],
    );
    assert_eq!(gs.large_messages.pending_reassemblies(&peers[3]), 0);
    let (refusals, _queues) = count_control_msgs(queues, |peer_id, rpc| {
        peer_id == &peers[3] && matches!(rpc, RpcOut::ImReceiving(_))
    });
    assert_eq!(refusals, 1, "a non-mesh sender is still refused at the cap");
}

#[test]
fn test_mesh_senders_never_evict_mesh_senders() {
    let mut state = large_messages::State::default();
    let limits = wide_limits();
    let topic_hash = Topic::new(TOPIC).hash();
    let message_id = MessageId::new(b"mesh-only-slots");

    (0..u32::from(MAX_SENDERS_PER_MESSAGE)).for_each(|_| {
        let peer = PeerId::random();
        let _ = state.handle_fragment(
            &peer,
            make_fragment(&message_id, 0, 2, 16, &topic_hash),
            true,
            &limits,
            &ValidationMode::Strict,
        );
    });
    assert_eq!(state.senders_for(&message_id), MAX_SENDERS_PER_MESSAGE);

    let latecomer = PeerId::random();
    let actions = state.handle_fragment(
        &latecomer,
        make_fragment(&message_id, 0, 2, 16, &topic_hash),
        true,
        &limits,
        &ValidationMode::Strict,
    );
    assert!(
        actions.iter().any(|action| matches!(
            action,
            large_messages::ReceivedAction::ReplyImReceiving { .. }
        )),
        "a full set of mesh senders refuses even a mesh latecomer"
    );
    assert_eq!(state.senders_for(&message_id), MAX_SENDERS_PER_MESSAGE);
    assert_eq!(state.pending_reassemblies(&latecomer), 0);
}

#[test]
fn test_preamble_never_allocates_from_message_size() {
    let (mut gs, peers, _queues, topic_hashes) = enabled_network(1);
    gs.handle_graft(&peers[0], topic_hashes.clone());
    let message_id = MessageId::new(b"huge-claim");

    deliver_preamble(
        &mut gs,
        peers[0],
        Preamble {
            message_id: message_id.clone(),
            message_size: u64::MAX,
            topic_hash: topic_hashes[0].clone(),
        },
    );

    assert_eq!(
        gs.large_messages.total_bytes(),
        0,
        "`messageSize` must never drive an allocation"
    );
    assert!(gs.large_messages.has_announcement(&peers[0], &message_id));
    assert_eq!(gs.large_messages.announcements_len(&peers[0]), 1);
}

#[test]
fn test_preamble_announcement_cap_evicts_lru() {
    let config = ConfigBuilder::default()
        .max_transmit_size(1 << 17)
        .large_message_handling(true)
        .max_preamble_announcements_per_peer(2)
        .build()
        .unwrap();
    let (mut gs, peers, _queues, topic_hashes) = network_with(config, 1, None);
    gs.handle_graft(&peers[0], topic_hashes.clone());
    let ids: Vec<MessageId> = (0..3u8)
        .map(|i| MessageId::from(format!("announce-{i}")))
        .collect();

    ids.iter().for_each(|message_id| {
        deliver_preamble(
            &mut gs,
            peers[0],
            Preamble {
                message_id: message_id.clone(),
                message_size: 256,
                topic_hash: topic_hashes[0].clone(),
            },
        );
    });

    assert_eq!(gs.large_messages.announcements_len(&peers[0]), 2);
    assert!(
        !gs.large_messages.has_announcement(&peers[0], &ids[0]),
        "the oldest announcement must be evicted"
    );
    assert!(gs.large_messages.has_announcement(&peers[0], &ids[1]));
    assert!(gs.large_messages.has_announcement(&peers[0], &ids[2]));
}

#[test]
fn test_preamble_from_non_mesh_peer_is_ignored() {
    // The peer connects without subscribing, so it can never join the mesh.
    let (mut gs, peers, _queues, topic_hashes) = DefaultBehaviourTestBuilder::default()
        .peer_no(1)
        .topics(vec![String::from(TOPIC)])
        .to_subscribe(false)
        .gs_config(enabled_config())
        .create_network();
    let message_id = MessageId::new(b"not-in-mesh");

    deliver_preamble(
        &mut gs,
        peers[0],
        Preamble {
            message_id,
            message_size: 256,
            topic_hash: topic_hashes[0].clone(),
        },
    );

    assert_eq!(gs.large_messages.announcements_len(&peers[0]), 0);
}

#[test]
fn test_preamble_for_known_message_sends_idontwant() {
    // IDONTWANT is only sent to peers that speak gossipsub v1.2 or later.
    let (mut gs, peers, queues, topic_hashes) = DefaultBehaviourTestBuilder::default()
        .peer_no(1)
        .topics(vec![String::from(TOPIC)])
        .to_subscribe(true)
        .gs_config(enabled_config())
        .peer_kind(PeerKind::Gossipsubv1_2)
        .create_network();
    gs.handle_graft(&peers[0], topic_hashes.clone());
    let message_id = MessageId::new(b"already-held");
    assert!(gs.duplicate_cache.insert(message_id.clone()));

    deliver_preamble(
        &mut gs,
        peers[0],
        Preamble {
            message_id: message_id.clone(),
            message_size: 256,
            topic_hash: topic_hashes[0].clone(),
        },
    );

    let (count, _queues) = count_control_msgs(queues, |_, rpc| {
        matches!(
            rpc,
            RpcOut::IDontWant(IDontWant { message_ids }) if message_ids.contains(&message_id)
        )
    });
    assert_eq!(count, 1, "a known message must be answered with IDONTWANT");
    assert_eq!(gs.large_messages.announcements_len(&peers[0]), 0);
}

#[test]
fn test_announced_size_mismatch_is_delivered_and_not_penalized() {
    // Check 5: `messageSize` is advisory.
    let (mut gs, peers, _queues, topic_hashes) = scored_network(1);
    gs.handle_graft(&peers[0], topic_hashes.clone());
    let (message_id, encoded) = signed_message(&mut gs, &topic_hashes[0], vec![5u8; 120]);

    deliver_preamble(
        &mut gs,
        peers[0],
        Preamble {
            message_id: message_id.clone(),
            message_size: 1,
            topic_hash: topic_hashes[0].clone(),
        },
    );
    assert!(gs.large_messages.has_announcement(&peers[0], &message_id));

    let fragments = fragments_for(
        &encoded,
        encoded.len().div_ceil(2),
        &message_id,
        &topic_hashes[0],
    );
    deliver_fragments(&mut gs, peers[0], fragments);

    assert!(
        gs.duplicate_cache.contains(&message_id),
        "an announced-size mismatch must still deliver"
    );
    assert!(
        score(&mut gs, &peers[0]).abs() < f64::EPSILON,
        "an announced-size mismatch must not be penalized"
    );
}

#[test]
fn test_fragment_timeout_drops_buffer_and_penalizes() {
    let (mut gs, peers, _queues, topic_hashes) = scored_network(1);
    let message_id = MessageId::new(b"stalled");

    deliver_fragments(
        &mut gs,
        peers[0],
        vec![make_fragment(&message_id, 0, 2, 64, &topic_hashes[0])],
    );
    assert_eq!(gs.large_messages.pending_reassemblies(&peers[0]), 1);

    let limits = gs.large_message_limits(&topic_hashes[0]);
    let actions = gs
        .large_messages
        .heartbeat(&limits, Instant::now() + gs.config.fragment_timeout());
    gs.handle_large_message_actions(&peers[0], actions);

    assert_eq!(gs.large_messages.pending_reassemblies(&peers[0]), 0);
    assert_eq!(gs.large_messages.total_bytes(), 0);
    assert_eq!(gs.large_messages.senders_for(&message_id), 0);
    assert!(
        score(&mut gs, &peers[0]) < 0.0,
        "a timed-out reassembly must apply P7"
    );
}

#[test]
fn test_preamble_without_data_applies_p7() {
    let (mut gs, peers, _queues, topic_hashes) = scored_network(1);
    gs.handle_graft(&peers[0], topic_hashes.clone());
    let message_id = MessageId::new(b"no-data-followed");

    deliver_preamble(
        &mut gs,
        peers[0],
        Preamble {
            message_id,
            message_size: 256,
            topic_hash: topic_hashes[0].clone(),
        },
    );
    assert_eq!(gs.large_messages.announcements_len(&peers[0]), 1);

    let limits = gs.large_message_limits(&topic_hashes[0]);
    let actions = gs
        .large_messages
        .heartbeat(&limits, Instant::now() + gs.config.fragment_timeout());
    gs.handle_large_message_actions(&peers[0], actions);

    assert_eq!(gs.large_messages.announcements_len(&peers[0]), 0);
    assert!(
        score(&mut gs, &peers[0]) < 0.0,
        "a PREAMBLE never followed by data must apply P7"
    );
}

#[test]
fn test_poison_set_is_capped_per_peer_and_evicts_lru() {
    let mut state = large_messages::State::default();
    let peer = PeerId::random();
    let now = Instant::now();

    (0..=MAX_POISONED_IDS_PER_PEER).for_each(|i| {
        state.poison(&peer, MessageId::from(format!("poison-{i}")), now);
    });

    assert_eq!(state.poisoned_len(&peer), MAX_POISONED_IDS_PER_PEER);
    assert!(
        !state.is_poisoned(&peer, &MessageId::from(String::from("poison-0"))),
        "the oldest poisoned id must be evicted"
    );
    assert!(state.is_poisoned(
        &peer,
        &MessageId::from(format!("poison-{MAX_POISONED_IDS_PER_PEER}"))
    ));
}

#[test]
fn test_poison_set_expires_at_fragment_timeout() {
    let mut state = large_messages::State::default();
    let limits = wide_limits();
    let peer = PeerId::random();
    let message_id = MessageId::new(b"expiring-poison");
    let now = Instant::now();

    state.poison(&peer, message_id.clone(), now);
    assert!(state.is_poisoned(&peer, &message_id));

    let actions = state.heartbeat(&limits, now + limits.fragment_timeout);
    assert!(actions.is_empty(), "poison expiry must not penalize");
    assert!(!state.is_poisoned(&peer, &message_id));
    assert_eq!(state.poisoned_len(&peer), 0);
}

#[test]
fn test_peer_disconnect_releases_poison_set() {
    let (mut gs, peers, _queues, _topic_hashes) = enabled_network(1);
    let message_id = MessageId::new(b"poison-on-departure");

    gs.large_messages
        .poison(&peers[0], message_id.clone(), Instant::now());
    assert!(gs.large_messages.is_poisoned(&peers[0], &message_id));

    disconnect_peer(&mut gs, &peers[0]);

    assert!(!gs.large_messages.is_poisoned(&peers[0], &message_id));
    assert_eq!(gs.large_messages.poisoned_len(&peers[0]), 0);
}

#[test]
fn test_senders_per_message_entry_is_removed_when_the_last_buffer_drops() {
    let (mut gs, peers, _queues, topic_hashes) = enabled_network(2);
    let message_id = MessageId::new(b"shared-id");

    peers.iter().for_each(|peer| {
        deliver_fragments(
            &mut gs,
            *peer,
            vec![make_fragment(&message_id, 0, 2, 32, &topic_hashes[0])],
        );
    });
    assert_eq!(gs.large_messages.senders_for(&message_id), 2);

    disconnect_peer(&mut gs, &peers[0]);
    assert_eq!(gs.large_messages.senders_for(&message_id), 1);

    disconnect_peer(&mut gs, &peers[1]);
    assert_eq!(
        gs.large_messages.senders_for(&message_id),
        0,
        "the sender entry must go with its last buffer"
    );
}

#[test]
fn test_peer_disconnect_releases_all_budget() {
    let (mut gs, peers, _queues, topic_hashes) = enabled_network(1);
    let message_id = MessageId::new(b"budget-holder");

    deliver_fragments(
        &mut gs,
        peers[0],
        vec![make_fragment(&message_id, 0, 2, 100, &topic_hashes[0])],
    );
    assert_eq!(
        gs.large_messages.total_bytes(),
        100 + FRAGMENT_ENTRY_OVERHEAD
    );
    assert_eq!(gs.large_messages.total_reassemblies(), 1);
    assert_eq!(gs.large_messages.senders_for(&message_id), 1);

    disconnect_peer(&mut gs, &peers[0]);

    assert_eq!(gs.large_messages.total_bytes(), 0);
    assert_eq!(gs.large_messages.total_reassemblies(), 0);
    assert_eq!(gs.large_messages.pending_reassemblies(&peers[0]), 0);
    assert_eq!(gs.large_messages.senders_for(&message_id), 0);
}

#[test]
fn test_reassembly_does_not_award_delivery_score() {
    // D7: only a reassembled message travelling the normal receive path may
    // earn credit; fragments alone must earn none.
    // Keep the delivery reward live but zero the time-in-mesh drift, so a
    // nonzero score can only come from a (wrongly) credited delivery.
    let mut params = PeerScoreParams::default();
    params.topics.insert(
        Topic::new(TOPIC).hash(),
        TopicScoreParams {
            first_message_deliveries_weight: 1.0,
            ..quiet_topic_params()
        },
    );
    let (mut gs, peers, _queues, topic_hashes) = network_with(
        enabled_config(),
        1,
        Some((params, PeerScoreThresholds::default())),
    );
    let message_id = MessageId::new(b"no-credit");

    deliver_fragments(
        &mut gs,
        peers[0],
        vec![
            make_fragment(&message_id, 0, 3, 64, &topic_hashes[0]),
            make_fragment(&message_id, 1, 3, 64, &topic_hashes[0]),
        ],
    );
    assert_eq!(gs.large_messages.pending_reassemblies(&peers[0]), 1);

    gs.as_peer_score_mut().refresh_scores();
    assert!(
        score(&mut gs, &peers[0]).abs() < f64::EPSILON,
        "accepted fragments must not earn delivery credit"
    );
}

#[test]
fn test_fragments_ignored_when_extension_disabled() {
    let (mut gs, peers, _queues, topic_hashes) = network_with(Config::default(), 1, None);
    let message_id = MessageId::new(b"while-disabled");

    deliver_fragments(
        &mut gs,
        peers[0],
        vec![make_fragment(&message_id, 0, 2, 64, &topic_hashes[0])],
    );
    assert_eq!(gs.large_messages.total_reassemblies(), 0);
    assert_eq!(gs.large_messages.pending_reassemblies(&peers[0]), 0);
    assert_eq!(gs.large_messages.senders_for(&message_id), 0);

    gs.handle_graft(&peers[0], topic_hashes.clone());
    deliver_preamble(
        &mut gs,
        peers[0],
        Preamble {
            message_id,
            message_size: 256,
            topic_hash: topic_hashes[0].clone(),
        },
    );
    assert_eq!(gs.large_messages.announcements_len(&peers[0]), 0);
}

// ---- Stage 3: sender-side fragmentation ----

#[test]
fn test_fragment_message_slices_are_contiguous_and_sized() {
    let (mut gs, _peers, _queues, topic_hashes) = enabled_network(1);
    let raw = gs
        .build_raw_message(topic_hashes[0].clone(), vec![9u8; 10_000])
        .unwrap();
    let message = gs.data_transform.inbound_transform(raw.clone()).unwrap();
    let message_id = gs.config.message_id(&message);
    let proto_message: proto::Message = raw.clone().into();
    let encoded = proto_message.encode_to_vec();
    let chunk = 1_024usize;

    let fragments = large_messages::fragment_message(&message_id, &raw, chunk).unwrap();

    assert_eq!(fragments.len(), encoded.len().div_ceil(chunk));
    fragments.iter().enumerate().for_each(|(index, fragment)| {
        assert_eq!(fragment.fragment_index as usize, index);
        assert_eq!(fragment.total_fragments as usize, fragments.len());
        assert_eq!(fragment.message_id, message_id);
        assert_eq!(fragment.topic_hash, topic_hashes[0]);
        if index + 1 < fragments.len() {
            assert_eq!(
                fragment.fragment_data.len(),
                chunk,
                "every non-final fragment is exactly `fragment_size` bytes"
            );
        } else {
            assert!(fragment.fragment_data.len() <= chunk);
        }
    });
}

#[test]
fn test_fragment_message_splits_encoded_message() {
    let (mut gs, _peers, _queues, topic_hashes) = enabled_network(1);
    let raw = gs
        .build_raw_message(topic_hashes[0].clone(), vec![5u8; 10_000])
        .unwrap();
    let message = gs.data_transform.inbound_transform(raw.clone()).unwrap();
    let message_id = gs.config.message_id(&message);
    let proto_message: proto::Message = raw.clone().into();
    let encoded = proto_message.encode_to_vec();
    let chunk = 1_024usize;

    let fragments = large_messages::fragment_message(&message_id, &raw, chunk).unwrap();

    let concatenated: Vec<u8> = fragments
        .iter()
        .flat_map(|fragment| fragment.fragment_data.clone())
        .collect();
    assert_eq!(
        concatenated, encoded,
        "the fragments are exactly the encoded `proto::Message` bytes"
    );
    assert_eq!(&fragments[0].fragment_data[..], &encoded[..chunk]);
}

#[test]
fn test_fragment_message_rejects_over_hard_cap() {
    let (mut gs, _peers, _queues, topic_hashes) = enabled_network(1);
    let raw = gs
        .build_raw_message(topic_hashes[0].clone(), vec![9u8; 20_000])
        .unwrap();
    let message = gs.data_transform.inbound_transform(raw.clone()).unwrap();
    let message_id = gs.config.message_id(&message);

    // 20 KB in 16-byte fragments needs more than `MAX_FRAGMENTS_HARD_CAP`.
    let result = large_messages::fragment_message(&message_id, &raw, 16);
    assert!(matches!(result, Err(PublishError::MessageTooLarge)));
}

#[test]
fn test_fragment_message_round_trips_through_reassembly() {
    let (mut gs, peers, _queues, topic_hashes) = enabled_network(1);
    let chunk = 4_096usize;

    // Probe the constant encoding overhead so the payload sizes below make the
    // encoded message straddle a `fragment_size` boundary exactly.
    let mut sender: Behaviour = Behaviour::new(
        MessageAuthenticity::Signed(Keypair::generate_ed25519()),
        Config::default(),
    )
    .unwrap();
    let probe = sender
        .build_raw_message(topic_hashes[0].clone(), vec![3u8; 1_000])
        .unwrap();
    let probe_message: proto::Message = probe.into();
    let overhead = probe_message.encode_to_vec().len() - 1_000;

    [
        2 * chunk - overhead - 1,
        2 * chunk - overhead,
        2 * chunk - overhead + 1,
    ]
    .iter()
    .for_each(|&len| {
        let raw = sender
            .build_raw_message(topic_hashes[0].clone(), vec![3u8; len])
            .unwrap();
        let message = gs.data_transform.inbound_transform(raw.clone()).unwrap();
        let message_id = gs.config.message_id(&message);
        let raw_proto: proto::Message = raw.clone().into();
        let encoded_len = raw_proto.encode_to_vec().len();

        let fragments = large_messages::fragment_message(&message_id, &raw, chunk).unwrap();
        assert_eq!(fragments.len(), encoded_len.div_ceil(chunk));

        deliver_fragments(&mut gs, peers[0], fragments);

        assert!(
            gs.duplicate_cache.contains(&message_id),
            "payload of {len} bytes must reassemble"
        );
        let delivered = gs.events.iter().any(|event| {
            matches!(
                event,
                ToSwarm::GenerateEvent(Event::Message { message, .. })
                    if message.data == vec![3u8; len]
            )
        });
        assert!(
            delivered,
            "payload of {len} bytes must reach the application"
        );
    });
}

#[test]
fn test_publish_then_reassemble_round_trip() {
    let (mut publisher, publisher_peers, mut publisher_queues, _) = enabled_network(1);
    deliver(
        &mut publisher,
        publisher_peers[0],
        vec![ControlAction::Extensions(Some(Extensions {
            partial_messages: None,
            large_message_handling: Some(true),
        }))],
        vec![],
    );

    let data = vec![42u8; 100_000];
    let message_id = publisher.publish(Topic::new(TOPIC), data.clone()).unwrap();

    let queue = publisher_queues.get_mut(&publisher_peers[0]).unwrap();
    let fragments: Vec<LargeMessageFragment> = std::iter::from_fn(|| queue.try_pop())
        .filter_map(|rpc| {
            if let RpcOut::LargeMessageFragment { fragment, .. } = rpc {
                Some(fragment)
            } else {
                None
            }
        })
        .collect();
    assert!(
        fragments.len() >= 2,
        "the publish must have been fragmented"
    );

    let (mut receiver, receiver_peers, _receiver_queues, _) = enabled_network(1);
    deliver_fragments(&mut receiver, receiver_peers[0], fragments);

    assert!(
        receiver.duplicate_cache.contains(&message_id),
        "the receiver must reassemble the published message"
    );
    let delivered = receiver.events.iter().any(|event| {
        matches!(
            event,
            ToSwarm::GenerateEvent(Event::Message { message, .. })
                if message.data == data
        )
    });
    assert!(
        delivered,
        "the reassembled message must reach the application with identical bytes"
    );
}

// ---- Stage 4: pipelined relay, forward-path fragmentation, IMRECEIVING ----

/// A config with the extension enabled and a preamble threshold low enough
/// that a modest transfer qualifies for IMRECEIVING announcements while
/// staying under the topic's message ceiling.
fn announce_config() -> Config {
    ConfigBuilder::default()
        .max_transmit_size(1 << 17)
        .large_message_handling(true)
        .preamble_threshold(8192)
        .stagger_interval(Duration::ZERO)
        .build()
        .unwrap()
}

/// Marks `peer` as announcing the Large Message Handling extension.
fn make_capable(gs: &mut Behaviour, peer: PeerId) {
    deliver(
        gs,
        peer,
        vec![ControlAction::Extensions(Some(Extensions {
            partial_messages: None,
            large_message_handling: Some(true),
        }))],
        vec![],
    );
}

/// Drains `peer`'s queue and returns the large-message fragments it held.
fn drain_fragments(
    queues: &mut HashMap<PeerId, Queue>,
    peer: &PeerId,
) -> Vec<LargeMessageFragment> {
    queues
        .get_mut(peer)
        .map(|queue| {
            std::iter::from_fn(|| queue.try_pop())
                .filter_map(|rpc| {
                    if let RpcOut::LargeMessageFragment { fragment, .. } = rpc {
                        Some(fragment)
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A signed message big enough that `forward_msg` fragments it, split with
/// this node's own `fragment_size` chunking so the forward run and the relay
/// ledger agree on `total_fragments`.
fn large_signed_run(
    gs: &mut Behaviour,
    topic_hash: &TopicHash,
) -> (MessageId, Vec<LargeMessageFragment>) {
    let (message_id, encoded) = signed_message(gs, topic_hash, vec![13u8; 100_000]);
    let chunk = gs.config.fragment_size();
    let fragments = fragments_for(&encoded, chunk, &message_id, topic_hash);
    (message_id, fragments)
}

#[test]
fn test_fragment_from_mesh_peer_is_relayed_before_reassembly() {
    let (mut gs, peers, mut queues, topic_hashes) = enabled_network(2);
    gs.handle_graft(&peers[0], topic_hashes.clone());
    gs.handle_graft(&peers[1], topic_hashes.clone());
    make_capable(&mut gs, peers[1]);
    let message_id = MessageId::new(b"relay-early");

    deliver_fragments(
        &mut gs,
        peers[0],
        vec![make_fragment(&message_id, 0, 3, 64, &topic_hashes[0])],
    );

    let relayed = drain_fragments(&mut queues, &peers[1]);
    assert_eq!(
        relayed.len(),
        1,
        "the fragment must be relayed before reassembly completes"
    );
    assert_eq!(relayed[0].fragment_index, 0);
    assert!(!gs.duplicate_cache.contains(&message_id));
    assert_eq!(gs.large_messages.pending_reassemblies(&peers[0]), 1);
}

#[test]
fn test_fragment_from_non_mesh_peer_is_reassembled_but_not_relayed() {
    let (mut gs, peers, mut queues, topic_hashes) = enabled_network(2);
    gs.handle_graft(&peers[1], topic_hashes.clone());
    make_capable(&mut gs, peers[1]);
    // The builder meshes every subscribed peer; make the sender non-mesh.
    gs.mesh.get_mut(&topic_hashes[0]).unwrap().remove(&peers[0]);
    let message_id = MessageId::new(b"non-mesh-sender");

    deliver_fragments(
        &mut gs,
        peers[0],
        vec![make_fragment(&message_id, 0, 3, 64, &topic_hashes[0])],
    );

    assert_eq!(
        gs.large_messages.pending_reassemblies(&peers[0]),
        1,
        "a non-mesh sender may still be reassembled from"
    );
    assert!(
        drain_fragments(&mut queues, &peers[1]).is_empty(),
        "a non-mesh sender's fragments must not be relayed"
    );
}

#[test]
fn test_fragment_from_below_threshold_peer_is_dropped() {
    let (mut gs, peers, mut queues, topic_hashes) = scored_network(2);
    gs.handle_graft(&peers[0], topic_hashes.clone());
    gs.handle_graft(&peers[1], topic_hashes.clone());
    make_capable(&mut gs, peers[1]);
    gs.set_application_score(&peers[0], -2.0);
    assert!(score(&mut gs, &peers[0]) < PeerScoreThresholds::default().gossip_threshold);
    let message_id = MessageId::new(b"low-score-sender");

    deliver_fragments(
        &mut gs,
        peers[0],
        vec![make_fragment(&message_id, 0, 3, 64, &topic_hashes[0])],
    );

    assert_eq!(
        gs.large_messages.pending_reassemblies(&peers[0]),
        1,
        "reassembly still proceeds"
    );
    assert!(
        drain_fragments(&mut queues, &peers[1]).is_empty(),
        "a below-threshold sender's fragments must not be relayed"
    );
}

#[test]
fn test_fragment_for_known_message_id_is_not_relayed_and_triggers_idontwant() {
    // IDONTWANT is only sent to peers that speak gossipsub v1.2 or later.
    let (mut gs, peers, queues, topic_hashes) = DefaultBehaviourTestBuilder::default()
        .peer_no(2)
        .topics(vec![String::from(TOPIC)])
        .to_subscribe(true)
        .gs_config(enabled_config())
        .peer_kind(PeerKind::Gossipsubv1_2)
        .create_network();
    gs.handle_graft(&peers[0], topic_hashes.clone());
    gs.handle_graft(&peers[1], topic_hashes.clone());
    make_capable(&mut gs, peers[1]);
    let message_id = MessageId::new(b"already-complete");
    assert!(gs.duplicate_cache.insert(message_id.clone()));

    deliver_fragments(
        &mut gs,
        peers[0],
        vec![make_fragment(&message_id, 0, 2, 64, &topic_hashes[0])],
    );

    assert_eq!(gs.large_messages.pending_reassemblies(&peers[0]), 0);
    let mut relayed = 0;
    let (idontwants, _queues) = count_control_msgs(queues, |peer_id, rpc| {
        if matches!(rpc, RpcOut::LargeMessageFragment { .. }) {
            relayed += 1;
        }
        peer_id == &peers[0]
            && matches!(
                rpc,
                RpcOut::IDontWant(IDontWant { message_ids }) if message_ids.contains(&message_id)
            )
    });
    assert_eq!(
        idontwants, 1,
        "a fragment for a message we hold must draw IDONTWANT"
    );
    assert_eq!(relayed, 0, "a known message id must not be relayed");
}

#[test]
fn test_each_fragment_index_is_relayed_at_most_once_per_recipient_across_senders() {
    let (mut gs, peers, mut queues, topic_hashes) = enabled_network(3);
    gs.handle_graft(&peers[0], topic_hashes.clone());
    gs.handle_graft(&peers[1], topic_hashes.clone());
    gs.handle_graft(&peers[2], topic_hashes.clone());
    make_capable(&mut gs, peers[1]);
    let message_id = MessageId::new(b"cross-sender-dedup");

    deliver_fragments(
        &mut gs,
        peers[0],
        vec![make_fragment(&message_id, 0, 3, 64, &topic_hashes[0])],
    );
    deliver_fragments(
        &mut gs,
        peers[2],
        vec![make_fragment(&message_id, 0, 3, 64, &topic_hashes[0])],
    );

    let relayed = drain_fragments(&mut queues, &peers[1]);
    assert_eq!(
        relayed.len(),
        1,
        "index 0 must reach the recipient once across senders"
    );
}

#[test]
fn test_reassembled_message_is_not_re_fragmented_to_a_fully_relayed_peer() {
    let (mut gs, peers, mut queues, topic_hashes) = enabled_network(2);
    gs.handle_graft(&peers[0], topic_hashes.clone());
    gs.handle_graft(&peers[1], topic_hashes.clone());
    make_capable(&mut gs, peers[1]);
    let (message_id, fragments) = large_signed_run(&mut gs, &topic_hashes[0]);
    let total = fragments.len();
    assert!(total >= 2);

    deliver_fragments(&mut gs, peers[0], fragments);

    assert!(
        gs.duplicate_cache.contains(&message_id),
        "the transfer must complete"
    );
    let relayed = drain_fragments(&mut queues, &peers[1]);
    assert_eq!(
        relayed.len(),
        total,
        "each fragment must reach the recipient exactly once across relay plus forward_msg"
    );
}

#[test]
fn test_partially_relayed_peer_receives_only_the_missing_indices() {
    let (mut gs, peers, mut queues, topic_hashes) = enabled_network(2);
    gs.handle_graft(&peers[1], topic_hashes.clone());
    make_capable(&mut gs, peers[1]);
    let (message_id, fragments) = large_signed_run(&mut gs, &topic_hashes[0]);
    let total = u32::try_from(fragments.len()).unwrap();
    assert!(total >= 2);
    // Pretend the pipelined relay already sent every index but 0.
    (1..total).for_each(|index| {
        let _ = gs
            .large_messages
            .record_relayed(&message_id, peers[1], index, total);
    });

    deliver_fragments(&mut gs, peers[0], fragments);

    assert!(gs.duplicate_cache.contains(&message_id));
    let forwarded = drain_fragments(&mut queues, &peers[1]);
    assert_eq!(forwarded.len(), 1);
    assert_eq!(
        forwarded[0].fragment_index, 0,
        "only the missing index is sent"
    );
}

#[test]
fn test_never_relayed_peer_receives_the_whole_run_from_forward_msg() {
    let (mut gs, peers, mut queues, topic_hashes) = enabled_network(2);
    gs.handle_graft(&peers[1], topic_hashes.clone());
    make_capable(&mut gs, peers[1]);
    // A non-mesh sender keeps the pipelined relay out of the picture, so the
    // whole run below comes from `forward_msg` reading an empty ledger.
    gs.mesh.get_mut(&topic_hashes[0]).unwrap().remove(&peers[0]);
    let (message_id, fragments) = large_signed_run(&mut gs, &topic_hashes[0]);
    let total = u32::try_from(fragments.len()).unwrap();

    deliver_fragments(&mut gs, peers[0], fragments);

    assert!(gs.duplicate_cache.contains(&message_id));
    let forwarded = drain_fragments(&mut queues, &peers[1]);
    let mut indices: Vec<u32> = forwarded
        .iter()
        .map(|fragment| fragment.fragment_index)
        .collect();
    indices.sort_unstable();
    assert_eq!(
        indices,
        (0..total).collect::<Vec<_>>(),
        "a peer with no ledger record gets the whole run"
    );
}

#[cfg(feature = "partial-messages")]
#[test]
fn test_forward_skips_partial_requesting_peer_when_fragmenting() {
    let (mut gs, peers, mut queues, topic_hashes) = enabled_network(3);
    gs.handle_graft(&peers[1], topic_hashes.clone());
    gs.handle_graft(&peers[2], topic_hashes.clone());
    make_capable(&mut gs, peers[1]);
    make_capable(&mut gs, peers[2]);
    // A non-mesh sender keeps the pipelined relay out of the picture, so the
    // fragments below all come from `forward_msg`'s fragmenting path.
    gs.mesh.get_mut(&topic_hashes[0]).unwrap().remove(&peers[0]);
    gs.partial_messages_extension.peer_subscribed(
        &peers[1],
        topic_hashes[0].clone(),
        SubscriptionOpts {
            requests_partial: true,
            supports_partial: true,
        },
    );
    let (message_id, fragments) = large_signed_run(&mut gs, &topic_hashes[0]);
    let total = fragments.len();

    deliver_fragments(&mut gs, peers[0], fragments);

    assert!(gs.duplicate_cache.contains(&message_id));
    assert!(
        drain_fragments(&mut queues, &peers[1]).is_empty(),
        "a partial-requesting peer must not be handed a full fragmented copy"
    );
    assert_eq!(drain_fragments(&mut queues, &peers[2]).len(), total);
}

#[test]
fn test_fragments_relayed_evicts_lru_and_expires_at_fragment_timeout() {
    let (mut gs, peers, _queues, _topic_hashes) = enabled_network(1);

    (0..=FRAGMENTS_RELAYED_CAP).for_each(|index| {
        gs.mark_fragments_relayed(&MessageId::from(format!("fr-{index}")), vec![peers[0]]);
    });

    let peer = gs.connected_peers.get(&peers[0]).unwrap();
    assert_eq!(peer.fragments_relayed.len(), FRAGMENTS_RELAYED_CAP);
    assert!(
        !peer
            .fragments_relayed
            .contains_key(&MessageId::from("fr-0".to_string())),
        "the oldest id is evicted first"
    );

    let stale = Instant::now()
        .checked_sub(gs.config.fragment_timeout() + Duration::from_secs(1))
        .unwrap();
    let peer = gs.connected_peers.get_mut(&peers[0]).unwrap();
    *peer
        .fragments_relayed
        .get_mut(&MessageId::from("fr-1".to_string()))
        .unwrap() = stale;
    gs.heartbeat();

    let peer = gs.connected_peers.get(&peers[0]).unwrap();
    assert!(
        !peer
            .fragments_relayed
            .contains_key(&MessageId::from("fr-1".to_string())),
        "a fully-relayed id must expire at fragment_timeout"
    );
    assert!(
        peer.fragments_relayed
            .contains_key(&MessageId::from(format!("fr-{FRAGMENTS_RELAYED_CAP}")))
    );
}

#[test]
fn test_fragments_relayed_dropped_on_disconnect() {
    let (mut gs, peers, _queues, _topic_hashes) = enabled_network(1);
    let message_id = MessageId::new(b"gone-with-peer");
    gs.mark_fragments_relayed(&message_id, vec![peers[0]]);
    assert!(
        gs.connected_peers
            .get(&peers[0])
            .unwrap()
            .fragments_relayed
            .contains_key(&message_id)
    );

    disconnect_peer(&mut gs, &peers[0]);

    assert!(
        !gs.connected_peers.contains_key(&peers[0]),
        "per-peer relay state must not outlive the connection"
    );
}

#[test]
fn test_relayed_ledger_evicts_lru_and_a_re_send_is_the_only_consequence() {
    let mut state = large_messages::State::default();
    let recipient = PeerId::random();

    (0..=MAX_RELAY_RECORDS).for_each(|index| {
        let _ = state.record_relayed(&MessageId::from(format!("ledger-{index}")), recipient, 0, 2);
    });

    assert_eq!(state.relayed_records(), MAX_RELAY_RECORDS);
    let evicted = MessageId::from("ledger-0".to_string());
    assert!(!state.already_relayed(&evicted, &recipient, 0));
    assert_eq!(
        state.missing_indices(&evicted, &recipient, 2),
        vec![0, 1],
        "an evicted record means a full re-send, never a lost fragment"
    );
    assert_eq!(
        state.missing_indices(
            &MessageId::from(format!("ledger-{MAX_RELAY_RECORDS}")),
            &recipient,
            2
        ),
        vec![1]
    );
}

#[test]
fn test_relay_token_bucket_stops_relay_but_not_reassembly() {
    let mut state = large_messages::State::default();
    let limits = wide_limits();
    let peer = PeerId::random();
    let topic_hash = Topic::new(TOPIC).hash();
    let message_id = MessageId::new(b"bucket-drain");

    // 8 x 64 KiB = 512 KiB crosses the 480 KiB per-heartbeat relay budget.
    let relayed: usize = (0..8u32)
        .map(|index| {
            state
                .handle_fragment(
                    &peer,
                    make_fragment(&message_id, index, 9, 65_536, &topic_hash),
                    false,
                    &limits,
                    &ValidationMode::Strict,
                )
                .into_iter()
                .filter(|action| matches!(action, large_messages::ReceivedAction::RelayFragment(_)))
                .count()
        })
        .sum();

    assert_eq!(relayed, 7, "the eighth fragment must exhaust the bucket");
    assert_eq!(
        state.pending_reassemblies(&peer),
        1,
        "reassembly must continue when relay stops"
    );
    assert_eq!(
        state.relay_budget(&peer),
        Some(RELAY_BYTES_PER_HEARTBEAT - 7 * 65_536)
    );
}

#[test]
fn test_relay_tokens_refill_on_heartbeat() {
    let mut state = large_messages::State::default();
    let limits = wide_limits();
    let peer = PeerId::random();
    let topic_hash = Topic::new(TOPIC).hash();
    let message_id = MessageId::new(b"bucket-refill");

    let actions = state.handle_fragment(
        &peer,
        make_fragment(&message_id, 0, 3, 300_000, &topic_hash),
        false,
        &limits,
        &ValidationMode::Strict,
    );
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, large_messages::ReceivedAction::RelayFragment(_)))
    );
    let actions = state.handle_fragment(
        &peer,
        make_fragment(&message_id, 1, 3, 300_000, &topic_hash),
        false,
        &limits,
        &ValidationMode::Strict,
    );
    assert!(
        actions
            .iter()
            .all(|action| !matches!(action, large_messages::ReceivedAction::RelayFragment(_))),
        "the second 300 KB fragment must overdraw the bucket"
    );
    assert_eq!(
        state.relay_budget(&peer),
        Some(RELAY_BYTES_PER_HEARTBEAT - 300_000)
    );

    let _ = state.heartbeat(&limits, Instant::now());

    assert_eq!(
        state.relay_budget(&peer),
        Some(RELAY_BYTES_PER_HEARTBEAT),
        "every heartbeat refills the bucket whole"
    );
}

#[test]
fn test_relay_cooldown_after_repeated_incomplete_transfers() {
    let mut state = large_messages::State::default();
    let limits = wide_limits();
    let peer = PeerId::random();
    let topic_hash = Topic::new(TOPIC).hash();

    // Four transfers in a row time out with bytes on the floor.
    (0..4u32).for_each(|round| {
        let message_id = MessageId::from(format!("stall-{round}"));
        let _ = state.handle_fragment(
            &peer,
            make_fragment(&message_id, 0, 2, 64, &topic_hash),
            false,
            &limits,
            &ValidationMode::Strict,
        );
        let _ = state.heartbeat(
            &limits,
            Instant::now() + limits.fragment_timeout + Duration::from_secs(1),
        );
    });
    assert!(
        state.relay_paused(&peer),
        "a fourth incomplete transfer must pause relaying"
    );

    let paused_id = MessageId::new(b"while-paused");
    let actions = state.handle_fragment(
        &peer,
        make_fragment(&paused_id, 0, 2, 64, &topic_hash),
        false,
        &limits,
        &ValidationMode::Strict,
    );
    assert!(
        actions
            .iter()
            .all(|action| !matches!(action, large_messages::ReceivedAction::RelayFragment(_))),
        "no relay during the cooldown"
    );
    assert_eq!(
        state.pending_reassemblies(&peer),
        1,
        "reassembly continues through the cooldown"
    );
    // Complete the buffer (the filler fails check 7 and is dropped whole) so
    // the expiry heartbeat below has nothing left to time out.
    let _ = state.handle_fragment(
        &peer,
        make_fragment(&paused_id, 1, 2, 64, &topic_hash),
        false,
        &limits,
        &ValidationMode::Strict,
    );

    let _ = state.heartbeat(
        &limits,
        Instant::now() + limits.fragment_timeout + RELAY_COOLDOWN + Duration::from_secs(2),
    );
    assert!(!state.relay_paused(&peer), "the cooldown must expire");

    let resumed_id = MessageId::new(b"after-cooldown");
    let actions = state.handle_fragment(
        &peer,
        make_fragment(&resumed_id, 0, 2, 64, &topic_hash),
        false,
        &limits,
        &ValidationMode::Strict,
    );
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, large_messages::ReceivedAction::RelayFragment(_))),
        "relay must resume after the cooldown"
    );
}

#[test]
fn test_withheld_final_fragment_times_out_and_penalizes_sender() {
    let (mut gs, peers, mut queues, topic_hashes) = scored_network(2);
    gs.handle_graft(&peers[0], topic_hashes.clone());
    gs.handle_graft(&peers[1], topic_hashes.clone());
    make_capable(&mut gs, peers[1]);
    let (message_id, mut fragments) = large_signed_run(&mut gs, &topic_hashes[0]);
    let total = fragments.len();
    let _withheld = fragments.pop().unwrap();

    deliver_fragments(&mut gs, peers[0], fragments);
    assert_eq!(
        drain_fragments(&mut queues, &peers[1]).len(),
        total - 1,
        "accepted fragments are relayed eagerly"
    );

    let limits = gs.large_message_limits(&topic_hashes[0]);
    let actions = gs
        .large_messages
        .heartbeat(&limits, Instant::now() + gs.config.fragment_timeout());
    gs.handle_large_message_actions(&peers[0], actions);

    assert_eq!(gs.large_messages.pending_reassemblies(&peers[0]), 0);
    assert!(!gs.duplicate_cache.contains(&message_id));
    assert!(
        score(&mut gs, &peers[0]) < 0.0,
        "a withheld final fragment must cost the sender P7"
    );
}

#[test]
fn test_relayed_then_invalid_message_penalizes_sender_p4() {
    let (mut gs, peers, mut queues, topic_hashes) = scored_network(2);
    gs.handle_graft(&peers[0], topic_hashes.clone());
    gs.handle_graft(&peers[1], topic_hashes.clone());
    make_capable(&mut gs, peers[1]);
    let mut sender: Behaviour = Behaviour::new(
        MessageAuthenticity::Signed(Keypair::generate_ed25519()),
        Config::default(),
    )
    .unwrap();
    let mut raw = sender
        .build_raw_message(topic_hashes[0].clone(), vec![3u8; 100_000])
        .unwrap();
    raw.signature = Some(vec![0u8; 64]);
    let proto_message: proto::Message = raw.into();
    let encoded = proto_message.encode_to_vec();
    let message_id = MessageId::new(b"relayed-then-invalid");
    let chunk = gs.config.fragment_size();
    let fragments = fragments_for(&encoded, chunk, &message_id, &topic_hashes[0]);
    let total = fragments.len();

    deliver_fragments(&mut gs, peers[0], fragments);

    assert_eq!(
        drain_fragments(&mut queues, &peers[1]).len(),
        total,
        "the pipelined relay ran before whole-message validation could"
    );
    assert!(!gs.duplicate_cache.contains(&message_id));
    assert!(
        score(&mut gs, &peers[0]) < 0.0,
        "the reassembled message failed validation, so P4 lands retroactively"
    );
}

#[test]
fn test_forward_fragments_to_capable_mesh_peers() {
    let (mut gs, peers, queues, topic_hashes) = enabled_network(3);
    gs.handle_graft(&peers[1], topic_hashes.clone());
    gs.handle_graft(&peers[2], topic_hashes.clone());
    make_capable(&mut gs, peers[1]);
    let (message_id, fragments) = large_signed_run(&mut gs, &topic_hashes[0]);
    let total = fragments.len();

    deliver_fragments(&mut gs, peers[0], fragments);

    assert!(gs.duplicate_cache.contains(&message_id));
    let mut capable_fragments = 0;
    let (legacy_publishes, _queues) = count_control_msgs(queues, |peer_id, rpc| {
        if peer_id == &peers[1] && matches!(rpc, RpcOut::LargeMessageFragment { .. }) {
            capable_fragments += 1;
        }
        peer_id == &peers[2] && matches!(rpc, RpcOut::Publish { .. })
    });
    assert_eq!(capable_fragments, total);
    assert_eq!(
        legacy_publishes, 1,
        "an incapable mesh peer gets the whole message"
    );
}

#[test]
fn test_relay_skips_source_and_incapable_peers() {
    let (mut gs, peers, mut queues, topic_hashes) = enabled_network(3);
    gs.handle_graft(&peers[0], topic_hashes.clone());
    gs.handle_graft(&peers[1], topic_hashes.clone());
    gs.handle_graft(&peers[2], topic_hashes.clone());
    make_capable(&mut gs, peers[1]);
    let message_id = MessageId::new(b"skip-source");

    deliver_fragments(
        &mut gs,
        peers[0],
        vec![make_fragment(&message_id, 0, 3, 64, &topic_hashes[0])],
    );

    assert_eq!(drain_fragments(&mut queues, &peers[1]).len(), 1);
    assert!(
        drain_fragments(&mut queues, &peers[0]).is_empty(),
        "a fragment is never echoed to its sender"
    );
    assert!(
        drain_fragments(&mut queues, &peers[2]).is_empty(),
        "an incapable peer cannot receive v1.4 frames"
    );
}

#[test]
fn test_imreceiving_sent_once_on_first_fragment() {
    let (mut gs, peers, queues, topic_hashes) = network_with(announce_config(), 3, None);
    gs.handle_graft(&peers[1], topic_hashes.clone());
    make_capable(&mut gs, peers[1]);
    let message_id = MessageId::new(b"announce-once");

    // First fragment announces; a second fragment and a second sender do not.
    deliver_fragments(
        &mut gs,
        peers[0],
        vec![make_fragment(&message_id, 0, 4, 4096, &topic_hashes[0])],
    );
    deliver_fragments(
        &mut gs,
        peers[0],
        vec![make_fragment(&message_id, 1, 4, 4096, &topic_hashes[0])],
    );
    deliver_fragments(
        &mut gs,
        peers[2],
        vec![make_fragment(&message_id, 0, 4, 4096, &topic_hashes[0])],
    );

    let (announcements, _queues) = count_control_msgs(queues, |peer_id, rpc| {
        peer_id == &peers[1]
            && matches!(
                rpc,
                RpcOut::ImReceiving(ImReceiving { message_id: id }) if *id == message_id
            )
    });
    assert_eq!(
        announcements, 1,
        "IMRECEIVING goes out once per message id per node"
    );
}

#[test]
fn test_imreceiving_not_sent_below_preamble_threshold() {
    let (mut gs, peers, queues, topic_hashes) = network_with(announce_config(), 2, None);
    gs.handle_graft(&peers[1], topic_hashes.clone());
    make_capable(&mut gs, peers[1]);
    let message_id = MessageId::new(b"too-small-to-announce");

    deliver_fragments(
        &mut gs,
        peers[0],
        vec![make_fragment(&message_id, 0, 2, 1024, &topic_hashes[0])],
    );

    let (announcements, _queues) =
        count_control_msgs(queues, |_, rpc| matches!(rpc, RpcOut::ImReceiving(_)));
    assert_eq!(
        announcements, 0,
        "a transfer below the preamble threshold is not announced"
    );
}

#[test]
fn test_imreceiving_from_non_mesh_peer_is_ignored() {
    let (mut gs, peers, _queues, topic_hashes) = enabled_network(1);
    // The builder meshes every subscribed peer; make the sender non-mesh.
    gs.mesh.get_mut(&topic_hashes[0]).unwrap().remove(&peers[0]);
    let message_id = MessageId::new(b"advisory-outsider");

    deliver(
        &mut gs,
        peers[0],
        vec![ControlAction::ImReceiving(ImReceiving {
            message_id: message_id.clone(),
        })],
        vec![],
    );

    assert!(
        !gs.connected_peers
            .get(&peers[0])
            .unwrap()
            .imreceiving
            .contains_key(&message_id)
    );
}

#[test]
fn test_imreceiving_suppresses_forward_and_expires_after_fragment_timeout() {
    let (mut gs, peers, queues, topic_hashes) = enabled_network(1);
    gs.handle_graft(&peers[0], topic_hashes.clone());
    let message_id = MessageId::new(b"suppressed-forward");
    deliver(
        &mut gs,
        peers[0],
        vec![ControlAction::ImReceiving(ImReceiving {
            message_id: message_id.clone(),
        })],
        vec![],
    );
    let raw = gs
        .build_raw_message(topic_hashes[0].clone(), vec![1u8; 64])
        .unwrap();

    let _ = gs.forward_msg(&message_id, raw.clone(), None, HashSet::new());
    let (published, queues) = count_control_msgs(queues, |peer_id, rpc| {
        peer_id == &peers[0]
            && matches!(rpc, RpcOut::Publish { message_id: id, .. } if *id == message_id)
    });
    assert_eq!(
        published, 0,
        "an IMRECEIVING id must not be forwarded to its announcer"
    );

    let stale = Instant::now()
        .checked_sub(gs.config.fragment_timeout() + Duration::from_secs(1))
        .unwrap();
    *gs.connected_peers
        .get_mut(&peers[0])
        .unwrap()
        .imreceiving
        .get_mut(&message_id)
        .unwrap() = stale;
    gs.heartbeat();
    assert!(
        !gs.connected_peers
            .get(&peers[0])
            .unwrap()
            .imreceiving
            .contains_key(&message_id)
    );

    let _ = gs.forward_msg(&message_id, raw, None, HashSet::new());
    let (published, _queues) = count_control_msgs(queues, |peer_id, rpc| {
        peer_id == &peers[0]
            && matches!(rpc, RpcOut::Publish { message_id: id, .. } if *id == message_id)
    });
    assert_eq!(published, 1, "suppression must lapse at fragment_timeout");
}

#[test]
fn test_imreceiving_does_not_expire_at_idontwant_timeout() {
    // C15: IMRECEIVING suppression lives for `fragment_timeout`, not the 3 s
    // IDONTWANT window.
    let (mut gs, peers, _queues, topic_hashes) = enabled_network(1);
    gs.handle_graft(&peers[0], topic_hashes.clone());
    let message_id = MessageId::new(b"outlives-idontwant");
    deliver(
        &mut gs,
        peers[0],
        vec![ControlAction::ImReceiving(ImReceiving {
            message_id: message_id.clone(),
        })],
        vec![],
    );

    let five_seconds_ago = Instant::now().checked_sub(Duration::from_secs(5)).unwrap();
    let peer = gs.connected_peers.get_mut(&peers[0]).unwrap();
    *peer.imreceiving.get_mut(&message_id).unwrap() = five_seconds_ago;
    peer.dont_send
        .insert(MessageId::new(b"idontwant-entry"), five_seconds_ago);

    gs.heartbeat();

    let peer = gs.connected_peers.get(&peers[0]).unwrap();
    assert!(peer.dont_send.is_empty(), "5 s is past IDONTWANT_TIMEOUT");
    assert!(
        peer.imreceiving.contains_key(&message_id),
        "IMRECEIVING suppression must survive the IDONTWANT flush"
    );
}

#[test]
fn test_imreceiving_purges_queued_fragments() {
    let (mut gs, peers, mut queues, topic_hashes) = enabled_network(2);
    gs.handle_graft(&peers[0], topic_hashes.clone());
    gs.handle_graft(&peers[1], topic_hashes.clone());
    make_capable(&mut gs, peers[1]);
    let message_id = MessageId::new(b"purge-queued");

    // The relayed copy now sits in the recipient's queue.
    deliver_fragments(
        &mut gs,
        peers[0],
        vec![make_fragment(&message_id, 0, 3, 64, &topic_hashes[0])],
    );

    deliver(
        &mut gs,
        peers[1],
        vec![ControlAction::ImReceiving(ImReceiving {
            message_id: message_id.clone(),
        })],
        vec![],
    );

    assert!(
        drain_fragments(&mut queues, &peers[1]).is_empty(),
        "IMRECEIVING must purge fragments already queued for that id"
    );
}

#[test]
fn test_imreceiving_cap_evicts_lru() {
    let (mut gs, peers, _queues, topic_hashes) = enabled_network(1);
    gs.handle_graft(&peers[0], topic_hashes.clone());

    (0..=IMRECEIVING_CAP).for_each(|index| {
        deliver(
            &mut gs,
            peers[0],
            vec![ControlAction::ImReceiving(ImReceiving {
                message_id: MessageId::from(format!("imr-{index}")),
            })],
            vec![],
        );
    });

    let peer = gs.connected_peers.get(&peers[0]).unwrap();
    assert_eq!(peer.imreceiving.len(), IMRECEIVING_CAP);
    assert!(
        !peer
            .imreceiving
            .contains_key(&MessageId::from("imr-0".to_string())),
        "the oldest id is evicted first"
    );
    assert!(
        peer.imreceiving
            .contains_key(&MessageId::from(format!("imr-{IMRECEIVING_CAP}")))
    );
}

#[test]
fn test_imreceiving_sender_not_penalized() {
    let (mut gs, peers, _queues, topic_hashes) = scored_network(1);
    gs.handle_graft(&peers[0], topic_hashes.clone());

    deliver(
        &mut gs,
        peers[0],
        vec![
            ControlAction::ImReceiving(ImReceiving {
                message_id: MessageId::new(b"advisory-1"),
            }),
            ControlAction::ImReceiving(ImReceiving {
                message_id: MessageId::new(b"advisory-1"),
            }),
            ControlAction::ImReceiving(ImReceiving {
                message_id: MessageId::new(b"advisory-2"),
            }),
        ],
        vec![],
    );

    assert!(
        score(&mut gs, &peers[0]).abs() < f64::EPSILON,
        "IMRECEIVING is advisory and must never be penalized"
    );
}

#[test]
fn test_imreceiving_not_applied_to_explicit_peers() {
    let (mut gs, peers, _queues, topic_hashes) = enabled_network(1);
    gs.handle_graft(&peers[0], topic_hashes.clone());
    gs.add_explicit_peer(&peers[0]);
    let message_id = MessageId::new(b"explicit-advisory");

    deliver(
        &mut gs,
        peers[0],
        vec![ControlAction::ImReceiving(ImReceiving {
            message_id: message_id.clone(),
        })],
        vec![],
    );

    assert!(
        !gs.connected_peers
            .get(&peers[0])
            .unwrap()
            .imreceiving
            .contains_key(&message_id),
        "suppression is never applied to explicit peers"
    );
}

#[test]
fn test_ihave_for_in_flight_message_defers_iwant() {
    let (mut gs, peers, queues, topic_hashes) = enabled_network(2);
    let in_flight = MessageId::new(b"in-flight");
    deliver_fragments(
        &mut gs,
        peers[0],
        vec![make_fragment(&in_flight, 0, 2, 64, &topic_hashes[0])],
    );
    assert!(gs.large_messages.is_receiving(&in_flight));
    let fresh = MessageId::new(b"not-in-flight");

    gs.handle_ihave(
        &peers[1],
        vec![(
            topic_hashes[0].clone(),
            vec![in_flight.clone(), fresh.clone()],
        )],
    );

    let mut deferred_requested = false;
    let (iwants, _queues) = count_control_msgs(queues, |peer_id, rpc| {
        if peer_id == &peers[1]
            && matches!(
                rpc,
                RpcOut::IWant(IWant { message_ids }) if message_ids.contains(&in_flight)
            )
        {
            deferred_requested = true;
        }
        peer_id == &peers[1]
            && matches!(
                rpc,
                RpcOut::IWant(IWant { message_ids }) if message_ids.contains(&fresh)
            )
    });
    assert!(
        !deferred_requested,
        "an id with a transfer in flight defers its IWANT"
    );
    assert_eq!(iwants, 1, "other ids are still requested");
}

#[test]
fn test_no_v14_rpc_reaches_a_non_v14_mesh_peer() {
    let (mut gs, peers, queues, topic_hashes) = network_with(announce_config(), 2, None);
    gs.handle_graft(&peers[0], topic_hashes.clone());
    gs.handle_graft(&peers[1], topic_hashes.clone());
    // peers[1] never announces the extension: relay, IMRECEIVING and the
    // fragmenting forward path must all route around it.
    let (message_id, fragments) = large_signed_run(&mut gs, &topic_hashes[0]);

    deliver_fragments(&mut gs, peers[0], fragments);

    assert!(gs.duplicate_cache.contains(&message_id));
    let mut publishes = 0;
    let (v14_frames, _queues) = count_control_msgs(queues, |peer_id, rpc| {
        if peer_id == &peers[1] && matches!(rpc, RpcOut::Publish { .. }) {
            publishes += 1;
        }
        peer_id == &peers[1]
            && matches!(
                rpc,
                RpcOut::Preamble(_) | RpcOut::ImReceiving(_) | RpcOut::LargeMessageFragment { .. }
            )
    });
    assert_eq!(v14_frames, 0, "no v1.4 frame may reach a non-v1.4 peer");
    assert_eq!(
        publishes, 1,
        "the peer still gets the message the legacy way"
    );
}

#[test]
fn test_forward_delivers_under_both_validation_modes() {
    // Application validation off: the reassembled message forwards at once.
    let (mut gs, peers, mut queues, topic_hashes) = enabled_network(2);
    gs.handle_graft(&peers[0], topic_hashes.clone());
    gs.handle_graft(&peers[1], topic_hashes.clone());
    make_capable(&mut gs, peers[1]);
    let (message_id, fragments) = large_signed_run(&mut gs, &topic_hashes[0]);
    let total = fragments.len();
    deliver_fragments(&mut gs, peers[0], fragments);
    assert!(gs.duplicate_cache.contains(&message_id));
    assert_eq!(drain_fragments(&mut queues, &peers[1]).len(), total);

    // Application validation on: the relay is still eager, and acceptance
    // must not double-send what the relay already delivered.
    let config = ConfigBuilder::default()
        .max_transmit_size(1 << 17)
        .large_message_handling(true)
        .validate_messages()
        .build()
        .unwrap();
    let (mut gs, peers, mut queues, topic_hashes) = network_with(config, 2, None);
    gs.handle_graft(&peers[0], topic_hashes.clone());
    gs.handle_graft(&peers[1], topic_hashes.clone());
    make_capable(&mut gs, peers[1]);
    let (message_id, fragments) = large_signed_run(&mut gs, &topic_hashes[0]);
    let total = fragments.len();
    deliver_fragments(&mut gs, peers[0], fragments);
    assert_eq!(
        drain_fragments(&mut queues, &peers[1]).len(),
        total,
        "relay must not wait for application validation"
    );

    assert!(gs.report_message_validation_result(&message_id, &peers[0], MessageAcceptance::Accept));
    assert!(
        drain_fragments(&mut queues, &peers[1]).is_empty(),
        "acceptance must not double-send relayed fragments"
    );
}
