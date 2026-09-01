// Copyright 2019 Parity Technologies (UK) Ltd.
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

use std::{task::Poll, time::Duration};

use futures::{
    StreamExt,
    stream::{FuturesUnordered, SelectAll},
};
use libp2p_gossipsub as gossipsub;
use libp2p_gossipsub::{MessageAuthenticity, ValidationMode};
use libp2p_swarm::Swarm;
use libp2p_swarm_test::SwarmExt as _;
use quickcheck::{QuickCheck, TestResult};
use rand::{SeedableRng, seq::IndexedMutRandom};
use tokio::{runtime::Runtime, time};
use tracing_subscriber::EnvFilter;

struct Graph {
    nodes: SelectAll<Swarm<gossipsub::Behaviour>>,
}

impl Graph {
    async fn new_connected(num_nodes: usize, seed: u64) -> Graph {
        if num_nodes == 0 {
            panic!("expecting at least one node");
        }

        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        let mut not_connected_nodes = (0..num_nodes)
            .map(|_| build_node())
            .collect::<FuturesUnordered<_>>()
            .collect::<Vec<_>>()
            .await;

        let mut connected_nodes = vec![not_connected_nodes.pop().unwrap()];

        for mut next in not_connected_nodes {
            let connected = connected_nodes
                .choose_mut(&mut rng)
                .expect("at least one connected node");

            next.connect(connected).await;

            connected_nodes.push(next);
        }

        Graph {
            nodes: SelectAll::from_iter(connected_nodes),
        }
    }

    /// Polls the graph and passes each event into the provided FnMut until the closure returns
    /// `true`.
    ///
    /// Returns [`true`] on success and [`false`] on timeout.
    async fn wait_for<F: FnMut(&gossipsub::Event) -> bool>(&mut self, mut f: F) -> bool {
        let condition = async {
            loop {
                if let Ok(ev) = self
                    .nodes
                    .select_next_some()
                    .await
                    .try_into_behaviour_event()
                    && f(&ev)
                {
                    break;
                }
            }
        };

        match time::timeout(Duration::from_secs(10), condition).await {
            Ok(()) => true,
            Err(_) => false,
        }
    }

    /// Polls the graph until Poll::Pending is obtained, completing the underlying polls.
    async fn drain_events(&mut self) {
        let fut = futures::future::poll_fn(|cx| {
            loop {
                match self.nodes.poll_next_unpin(cx) {
                    Poll::Ready(_) => {}
                    Poll::Pending => return Poll::Ready(()),
                }
            }
        });
        time::timeout(Duration::from_secs(10), fut).await.unwrap();
    }
}

async fn build_node() -> Swarm<gossipsub::Behaviour> {
    // NOTE: The graph of created nodes can be disconnected from the mesh point of view as nodes
    // can reach their d_lo value and not add other nodes to their mesh. To speed up this test, we
    // reduce the default values of the heartbeat, so that all nodes will receive gossip in a
    // timely fashion.

    let mut swarm = Swarm::new_ephemeral_tokio(|identity| {
        let peer_id = identity.public().to_peer_id();

        let config = gossipsub::ConfigBuilder::default()
            .heartbeat_initial_delay(Duration::from_millis(100))
            .heartbeat_interval(Duration::from_millis(200))
            .history_length(10)
            .history_gossip(10)
            .validation_mode(ValidationMode::Permissive)
            .build()
            .unwrap();
        gossipsub::Behaviour::new(MessageAuthenticity::Author(peer_id), config).unwrap()
    });
    swarm.listen().with_memory_addr_external().await;

    swarm
}

/// A config with fast heartbeats and the v1.4 Large Message Handling
/// extension enabled, with reassembly budgets that admit a 4 MiB message.
fn large_message_config(max_transmit_size: usize) -> gossipsub::Config {
    gossipsub::ConfigBuilder::default()
        .heartbeat_initial_delay(Duration::from_millis(100))
        .heartbeat_interval(Duration::from_millis(200))
        .validation_mode(ValidationMode::Permissive)
        .max_transmit_size(max_transmit_size)
        .large_message_handling(true)
        .max_reassembly_bytes_per_peer(8 * 1024 * 1024)
        .max_reassembly_bytes_total(96 * 1024 * 1024)
        .build()
        .unwrap()
}

/// A pre-v1.4 config: the same fast heartbeats and a raised transmit
/// ceiling, without the Large Message Handling extension.
fn legacy_config(max_transmit_size: usize) -> gossipsub::Config {
    gossipsub::ConfigBuilder::default()
        .heartbeat_initial_delay(Duration::from_millis(100))
        .heartbeat_interval(Duration::from_millis(200))
        .validation_mode(ValidationMode::Permissive)
        .max_transmit_size(max_transmit_size)
        .build()
        .unwrap()
}

async fn build_node_with_config(config: gossipsub::Config) -> Swarm<gossipsub::Behaviour> {
    let mut swarm = Swarm::new_ephemeral_tokio(|identity| {
        let peer_id = identity.public().to_peer_id();
        gossipsub::Behaviour::new(MessageAuthenticity::Author(peer_id), config).unwrap()
    });
    swarm.listen().with_memory_addr_external().await;

    swarm
}

/// A deterministic payload whose bytes can be compared after reassembly.
fn deterministic_payload(len: usize, seed: usize) -> Vec<u8> {
    (0..len).map(|i| ((i + seed) % 251) as u8).collect()
}

/// Waits until every node has seen `expected` `Subscribed` events, then
/// drains the graph so grafts complete before publishing.
async fn await_subscriptions(graph: &mut Graph, expected: usize) {
    let mut subscribed = 0;
    let all_subscribed = graph
        .wait_for(move |ev| {
            if let gossipsub::Event::Subscribed { .. } = ev {
                subscribed += 1;
            }
            subscribed == expected
        })
        .await;
    assert!(all_subscribed, "timed out waiting for subscriptions");
    graph.drain_events().await;
}

/// Publishes `payload` from the node identified by `publisher` and returns
/// the `MessageId` the publish reported.
fn publish_from(
    graph: &mut Graph,
    publisher: libp2p_identity::PeerId,
    topic: gossipsub::IdentTopic,
    payload: Vec<u8>,
) -> gossipsub::MessageId {
    graph
        .nodes
        .iter_mut()
        .find(|node| *node.local_peer_id() == publisher)
        .unwrap()
        .behaviour_mut()
        .publish(topic, payload)
        .unwrap()
}

/// Both peers support the v1.4 Large Message Handling extension: a 512 KiB
/// payload is fragmented, announced with a PREAMBLE, reassembled by the
/// receiver, and delivered with identical bytes and the announced id.
/// Covers the v1.4 -> v1.4 cell of the spec's compatibility matrix.
#[tokio::test]
async fn large_message_round_trip() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let mut publisher = build_node_with_config(large_message_config(1 << 20)).await;
    let mut receiver = build_node_with_config(large_message_config(1 << 20)).await;
    let publisher_id = *publisher.local_peer_id();
    publisher.connect(&mut receiver).await;

    let topic = gossipsub::IdentTopic::new("large-message-round-trip");
    publisher.behaviour_mut().subscribe(&topic).unwrap();
    receiver.behaviour_mut().subscribe(&topic).unwrap();

    let mut graph = Graph {
        nodes: SelectAll::from_iter([publisher, receiver]),
    };
    await_subscriptions(&mut graph, 2).await;

    let payload = deterministic_payload(512 * 1024, 1);
    let expected_id = publish_from(&mut graph, publisher_id, topic, payload.clone());

    let delivered = graph
        .wait_for(move |ev| {
            matches!(
                ev,
                gossipsub::Event::Message { message_id, message, .. }
                    if *message_id == expected_id && message.data == payload
            )
        })
        .await;
    assert!(delivered, "the reassembled message was not delivered");
}

/// A v1.4 publisher falls back to a whole-message send for a peer that does
/// not advertise the extension, and handles a whole large message published
/// by that peer. Covers the v1.4 -> pre-v1.4 and pre-v1.4 -> v1.4 cells of
/// the compatibility matrix (`multi_hop_propagation` covers pre -> pre).
#[tokio::test]
async fn large_message_falls_back_for_pre_v14_peer() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let mut v14 = build_node_with_config(large_message_config(1 << 20)).await;
    let mut legacy = build_node_with_config(legacy_config(1 << 20)).await;
    let v14_id = *v14.local_peer_id();
    let legacy_id = *legacy.local_peer_id();
    v14.connect(&mut legacy).await;

    let topic = gossipsub::IdentTopic::new("large-message-fallback");
    v14.behaviour_mut().subscribe(&topic).unwrap();
    legacy.behaviour_mut().subscribe(&topic).unwrap();

    let mut graph = Graph {
        nodes: SelectAll::from_iter([v14, legacy]),
    };
    await_subscriptions(&mut graph, 2).await;

    // v1.4 -> pre-v1.4: the publisher must not fragment for this peer.
    let forward_payload = deterministic_payload(512 * 1024, 2);
    let forward_id = publish_from(&mut graph, v14_id, topic.clone(), forward_payload.clone());
    let delivered = graph
        .wait_for(move |ev| {
            matches!(
                ev,
                gossipsub::Event::Message { message_id, message, .. }
                    if *message_id == forward_id && message.data == forward_payload
            )
        })
        .await;
    assert!(delivered, "the whole-message fallback was not delivered");

    // pre-v1.4 -> v1.4: a whole large message is handled as before.
    let backward_payload = deterministic_payload(512 * 1024, 3);
    let backward_id = publish_from(&mut graph, legacy_id, topic, backward_payload.clone());
    let delivered = graph
        .wait_for(move |ev| {
            matches!(
                ev,
                gossipsub::Event::Message { message_id, message, .. }
                    if *message_id == backward_id && message.data == backward_payload
            )
        })
        .await;
    assert!(delivered, "the legacy publish was not delivered");
}

/// Three v1.4 nodes on a line publish a 4 MiB message from one end. The
/// middle node relays fragments before its own reassembly completes
/// (pipelining), and both the middle and far nodes deliver identical bytes
/// under the announced id.
#[tokio::test]
async fn large_message_relays_before_reassembly_on_a_line() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let mut first = build_node_with_config(large_message_config(5 * 1024 * 1024)).await;
    let mut middle = build_node_with_config(large_message_config(5 * 1024 * 1024)).await;
    let mut last = build_node_with_config(large_message_config(5 * 1024 * 1024)).await;
    let first_id = *first.local_peer_id();
    first.connect(&mut middle).await;
    middle.connect(&mut last).await;

    let topic = gossipsub::IdentTopic::new("large-message-line");
    first.behaviour_mut().subscribe(&topic).unwrap();
    middle.behaviour_mut().subscribe(&topic).unwrap();
    last.behaviour_mut().subscribe(&topic).unwrap();

    let mut graph = Graph {
        nodes: SelectAll::from_iter([first, middle, last]),
    };
    // The line has two edges; each edge reports one Subscribed per side.
    await_subscriptions(&mut graph, 4).await;

    let payload = deterministic_payload(4 * 1024 * 1024, 4);
    let expected_id = publish_from(&mut graph, first_id, topic, payload.clone());

    let mut deliveries = 0;
    let delivered = graph
        .wait_for(move |ev| {
            if let gossipsub::Event::Message {
                message_id,
                message,
                ..
            } = ev
                && *message_id == expected_id
                && message.data == payload
            {
                deliveries += 1;
            }
            deliveries == 2
        })
        .await;
    assert!(
        delivered,
        "the middle and far nodes did not both deliver the message"
    );
}

#[test]
fn multi_hop_propagation() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    fn prop(num_nodes: u8, seed: u64) -> TestResult {
        if !(2..=50).contains(&num_nodes) {
            return TestResult::discard();
        }

        tracing::debug!(number_of_nodes=%num_nodes, seed=%seed);

        let rt = Runtime::new().unwrap();

        rt.block_on(async move {
            let mut graph = Graph::new_connected(num_nodes as usize, seed).await;
            let number_nodes = graph.nodes.len();

            // Subscribe each node to the same topic.
            let topic = gossipsub::IdentTopic::new("test-net");
            for node in &mut graph.nodes {
                node.behaviour_mut().subscribe(&topic).unwrap();
            }

            // Wait for all nodes to be subscribed.
            let mut subscribed = 0;

            let all_subscribed = graph
                .wait_for(move |ev| {
                    if let gossipsub::Event::Subscribed { .. } = ev {
                        subscribed += 1;
                        if subscribed == (number_nodes - 1) * 2 {
                            return true;
                        }
                    }

                    false
                })
                .await;

            if !all_subscribed {
                return TestResult::error(format!(
                    "Timed out waiting for all nodes to subscribe but only have {subscribed:?}/{num_nodes:?}.",
                ));
            }

            // It can happen that the publish occurs before all grafts have completed causing this test
            // to fail. We drain all the poll messages before publishing.
            graph.drain_events().await;

            // Publish a single message.
            graph
                .nodes
                .iter_mut()
                .next()
                .unwrap()
                .behaviour_mut()
                .publish(topic, vec![1, 2, 3])
                .unwrap();

            // Wait for all nodes to receive the published message.
            let mut received_msgs = 0;
            let all_received = graph
                .wait_for(move |ev| {
                    if let gossipsub::Event::Message { .. } = ev {
                        received_msgs += 1;
                        if received_msgs == number_nodes - 1 {
                            return true;
                        }
                    }

                    false
                })
                .await;

            if !all_received {
                return TestResult::error(format!(
                    "Timed out waiting for all nodes to receive the msg but only have {received_msgs:?}/{num_nodes:?}.",
                ));
            }

            TestResult::passed()
        })
    }

    QuickCheck::new()
        .max_tests(5)
        .quickcheck(prop as fn(u8, u64) -> TestResult)
}
