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

//! Support for the gossipsub v1.4 Large Message Handling extension.

use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::Duration,
};

use hashlink::LinkedHashMap;
use libp2p_identity::PeerId;
use prost::Message as _;
use web_time::Instant;

use crate::{
    ValidationError,
    config::ValidationMode,
    error::PublishError,
    protocol::validate_proto_message,
    rpc_proto::proto,
    topic::TopicHash,
    types::{LargeMessageFragment, MessageId, Preamble, RawMessage},
};

/// Protobuf and control overhead a fragment RPC adds on top of `fragment_data`.
pub(crate) const LARGE_FRAGMENT_RPC_OVERHEAD: usize = 512;
/// Fragments accepted inside a single RPC, enforced before prost decode. Equal to
/// `MAX_FRAGMENTS_HARD_CAP`, so no conformant transfer can reach it: this is an
/// anti-pathology bound on a stream-fatal path, not an operational rate limit.
pub(crate) const MAX_FRAGMENTS_PER_RPC: usize = 1_024;
/// Largest `totalFragments` value that is ever trusted. Wire-supplied, never an allocation size.
pub(crate) const MAX_FRAGMENTS_HARD_CAP: u32 = 1_024;
/// Reassembly buffers held across every peer.
pub(crate) const MAX_REASSEMBLIES_TOTAL: usize = 1_024;
/// Distinct senders allowed to reassemble one message id at once. Mesh and
/// explicit senders can reclaim a slot held by a non-mesh sender, so the cap
/// cannot be squatted by cheap non-mesh identities.
pub(crate) const MAX_SENDERS_PER_MESSAGE: u8 = 3;
/// Bookkeeping charged per stored fragment, so the byte caps are true memory caps.
pub(crate) const FRAGMENT_ENTRY_OVERHEAD: usize = 64;
/// Message ids one peer may hold in `PeerState.poisoned` after an id-binding failure.
pub(crate) const MAX_POISONED_IDS_PER_PEER: usize = 16;
/// Relay token bucket refill per heartbeat, in bytes. Stated in bytes, not in
/// fragments, so an inbound rate never depends on our own send-side `fragment_size`.
pub(crate) const RELAY_BYTES_PER_HEARTBEAT: usize = 491_520;
/// Incomplete transfers from one peer before relay for that peer pauses.
pub(crate) const MAX_INCOMPLETE_TRANSFERS: u8 = 3;
/// How long relay stays paused for a repeat offender.
pub(crate) const RELAY_COOLDOWN: Duration = Duration::from_secs(60);
/// Message ids tracked by the per-recipient relay ledger.
pub(crate) const MAX_RELAY_RECORDS: usize = 1_024;
/// Messages with staggered sends in flight.
pub(crate) const MAX_STAGGERED_MESSAGES: usize = 32;
/// Payload bytes held by the stagger payload table.
pub(crate) const MAX_STAGGER_BYTES: usize = 33_554_432;
/// Deferred per-peer sends held by the stagger queue.
pub(crate) const STAGGER_CAP: usize = 1_024;

/// One deferred per-peer send. Ids only: the payload lives once in the
/// behaviour's payload table and is shared by every entry for the same message.
pub(crate) struct StaggeredSend {
    pub(crate) peer_id: PeerId,
    pub(crate) message_id: MessageId,
    pub(crate) topic_hash: TopicHash,
    pub(crate) queue_duration: Duration,
    /// When this send becomes due.
    pub(crate) due: Instant,
    /// Whether the peer was in `mesh[topic]` when the send was deferred.
    /// Only such entries are re-checked for mesh membership before dispatch:
    /// explicit, floodsub, fanout and flood-publish recipients are deliberate
    /// non-mesh recipients and must not be dropped for not being in the mesh.
    pub(crate) mesh_member: bool,
}

/// The payload of one staggered message, shared across all of its deferred sends.
pub(crate) enum StaggerPayload {
    /// Peers without the extension, or a message below the fragmentation threshold.
    Whole(Arc<RawMessage>),
    /// Peers with the extension.
    Fragments(Arc<[LargeMessageFragment]>),
}

/// Book-keeping for one staggered message in the payload table.
pub(crate) struct StaggeredMessage {
    pub(crate) payload: StaggerPayload,
    /// Bytes charged against [`MAX_STAGGER_BYTES`].
    pub(crate) bytes: usize,
    /// Deferred sends still queued for this message.
    pub(crate) pending: usize,
    /// After this instant every remaining send is flushed at once.
    pub(crate) deadline: Instant,
}

/// Reassembly state for the gossipsub v1.4 Large Message Handling extension.
///
/// Holds buffers and bounds only. Every decision that needs the duplicate cache,
/// the mesh, the data transform or peer scoring is taken by the
/// [`Behaviour`](crate::Behaviour); this type reports back through [`ReceivedAction`].
#[derive(Default)]
pub(crate) struct State {
    /// Per-peer buffers, announcements and budget. One entry per peer, so
    /// `peer_disconnected` is a single remove that releases everything.
    peers: HashMap<PeerId, PeerState>,
    /// Live senders per message id.
    ///
    /// One entry per message id with at least one open reassembly, so the key
    /// count is bounded by `total_reassemblies` and therefore by
    /// `MAX_REASSEMBLIES_TOTAL`. The entry is created with the first sender's
    /// buffer, decremented whenever a buffer for that id is dropped for any
    /// reason (completion, timeout, consistency failure, `peer_disconnected`),
    /// and removed at zero. That removal is what keeps the bound true, so it is
    /// a single helper, `release_sender`, called from every drop site.
    senders_per_message: HashMap<MessageId, u8>,
    /// Total payload bytes charged across every buffer in `peers`.
    total_bytes: usize,
    /// Reassembly buffers open across every peer.
    total_reassemblies: usize,
    /// Per-recipient relay ledger: which fragment indices of which message ids
    /// we already put on the wire, and to whom. Capped at [`MAX_RELAY_RECORDS`]
    /// with insertion-order eviction; evicting a record early can cause a
    /// re-send, never a lost message.
    relayed: LinkedHashMap<MessageId, RelayRecord>,
}

/// Everything held for one sending peer.
#[derive(Default)]
struct PeerState {
    /// In-progress reassemblies, keyed by announced message id.
    reassembly: LinkedHashMap<MessageId, Reassembly>,
    /// PREAMBLEs with no fragment yet. Never holds payload bytes.
    announcements: LinkedHashMap<MessageId, Announcement>,
    /// Message ids this peer failed the id-binding check on (check 8), held so
    /// the attacker cannot immediately re-open the slot it just burned.
    /// Ids only, about 40 bytes each.
    poisoned: LinkedHashMap<MessageId, Instant>,
    budget: PeerBudget,
}

/// One in-progress reassembly, keyed by `(peer, message id)` per the spec.
struct Reassembly {
    topic_hash: TopicHash,
    /// `totalFragments` as first announced. Later fragments must agree.
    total_fragments: u32,
    /// Only the fragments actually received. Never sized from `total_fragments`.
    received: BTreeMap<u32, Vec<u8>>,
    received_bytes: usize,
    /// The sender's chunk size, learned from the first non-final fragment of this
    /// transfer. `None` until one arrives. Never our `fragment_size` (D8).
    fragment_len: Option<usize>,
    /// `messageSize` from a PREAMBLE, when one preceded the fragments. Advisory.
    announced_size: Option<u64>,
    /// When the PREAMBLE or first fragment arrived. Drives `fragment_timeout`.
    started: Instant,
    /// Duplicate `fragmentIndex` values seen inside this transfer.
    duplicate_indices: u16,
    /// Whether the sender held mesh (or explicit-peer) standing when the
    /// buffer opened. Buffers without it can be evicted by a mesh sender when
    /// the [`MAX_SENDERS_PER_MESSAGE`] slots for the id are all taken.
    from_mesh: bool,
    /// Whether this node already announced IMRECEIVING for this message id, so
    /// at most one announcement leaves per message id per node.
    imreceiving_sent: bool,
}

/// Per-peer accounting, so a sweep never walks the whole map.
struct PeerBudget {
    reassembly_bytes: usize,
    /// Relay token bucket, in bytes. Refilled to [`RELAY_BYTES_PER_HEARTBEAT`]
    /// on each heartbeat tick. When empty, this peer's fragments are still
    /// reassembled but no longer relayed: pipelining degrades to
    /// store-and-forward, the pre-v1.4 behaviour.
    relay_bytes_this_heartbeat: usize,
    /// Buffers from this peer that timed out holding partial data.
    incomplete_transfers: u8,
    /// While set and in the future, fragments from this peer are reassembled
    /// but never relayed. Cleared on expiry.
    relay_paused_until: Option<Instant>,
}

impl Default for PeerBudget {
    fn default() -> Self {
        Self {
            reassembly_bytes: 0,
            // The bucket starts full: a fresh peer can relay before the first
            // heartbeat tick refills it.
            relay_bytes_this_heartbeat: RELAY_BYTES_PER_HEARTBEAT,
            incomplete_transfers: 0,
            relay_paused_until: None,
        }
    }
}

/// A PREAMBLE with no data yet. About 40 bytes, never a payload allocation.
struct Announcement {
    message_size: u64,
    topic_hash: TopicHash,
    at: Instant,
    /// Whether the PREAMBLE already triggered our IMRECEIVING announcement.
    /// Carried into the [`Reassembly`] this announcement becomes.
    imreceiving_sent: bool,
}

/// What the relay already sent for one message id.
struct RelayRecord {
    /// `totalFragments` of the transfer the ledger tracked. A query with a
    /// different total treats the recipient as never relayed to.
    total_fragments: u32,
    /// Indices already sent, per recipient.
    per_recipient: HashMap<PeerId, IndexSet>,
    /// When the record was created. Swept at `fragment_timeout`.
    at: Instant,
}

/// A fixed-capacity set of fragment indices, one bit per index, so the ledger's
/// worst case stays `MAX_RELAY_RECORDS * recipients * MAX_FRAGMENTS_HARD_CAP`
/// bits.
struct IndexSet {
    words: Vec<u64>,
    len: u32,
}

impl IndexSet {
    fn new(len: u32) -> Self {
        Self {
            words: vec![0u64; (len as usize).div_ceil(64)],
            len,
        }
    }

    /// Sets `index`, reporting whether it was newly set.
    fn insert(&mut self, index: u32) -> bool {
        let bit = 1u64 << (index % 64);
        self.words
            .get_mut((index / 64) as usize)
            .is_some_and(|word| {
                let newly = *word & bit == 0;
                *word |= bit;
                newly
            })
    }

    fn contains(&self, index: u32) -> bool {
        index < self.len
            && self
                .words
                .get((index / 64) as usize)
                .is_some_and(|word| *word & (1u64 << (index % 64)) != 0)
    }

    fn is_full(&self) -> bool {
        self.words
            .iter()
            .map(|word| u64::from(word.count_ones()))
            .sum::<u64>()
            == u64::from(self.len)
    }

    /// Indices not yet set, ascending.
    fn missing(&self) -> Vec<u32> {
        (0..self.len)
            .filter(|index| !self.contains(*index))
            .collect()
    }
}

/// What the [`Behaviour`](crate::Behaviour) should do after a `State` call.
pub(crate) enum ReceivedAction {
    /// Relay this fragment to extension-capable mesh peers.
    RelayFragment(LargeMessageFragment),
    /// First sight of this message: tell the mesh we are receiving it.
    AnnounceReceiving {
        message_id: MessageId,
        topic_hash: TopicHash,
    },
    /// We already hold this message: ask the sender to stop.
    SuppressSender {
        peer_id: PeerId,
        message_id: MessageId,
    },
    /// Too many concurrent senders for this message id: tell the extra sender
    /// we are already receiving it elsewhere.
    ReplyImReceiving {
        peer_id: PeerId,
        message_id: MessageId,
    },
    /// Reassembly completed and the decoded message passed signature validation.
    /// The behaviour still has to bind `announced_id` to a recomputed message id.
    MessageReassembled {
        announced_id: MessageId,
        message: RawMessage,
    },
    /// The peer broke a reassembly invariant.
    PenalizePeer {
        peer_id: PeerId,
        topic_hash: TopicHash,
        penalty: Penalty,
    },
}

/// Which scoring hook a [`ReceivedAction::PenalizePeer`] maps to.
pub(crate) enum Penalty {
    /// P4, `PeerScore::reject_invalid_message`.
    InvalidMessage(ValidationError),
    /// P7, `PeerScore::add_penalty(peer, 1)`.
    Behavioural,
}

/// The bounds a `State` call enforces, read straight off `Config` at the call site.
pub(crate) struct Limits {
    /// Largest `fragmentData` an RPC can carry, from D8:
    /// `global_max_transmit_size - LARGE_FRAGMENT_RPC_OVERHEAD`. Not `fragment_size`.
    pub(crate) max_inbound_fragment_bytes: usize,
    pub(crate) fragment_timeout: Duration,
    pub(crate) max_pending_fragments: usize,
    pub(crate) max_reassembly_bytes_per_peer: usize,
    pub(crate) max_reassembly_bytes_total: usize,
    pub(crate) max_preamble_announcements_per_peer: usize,
    /// `max_transmit_size_for_topic` for the fragment's topic, resolved by the caller.
    pub(crate) max_message_bytes: usize,
    /// Sizes above this announce IMRECEIVING, from `Config::preamble_threshold`.
    pub(crate) preamble_threshold: usize,
}

/// The verdict `store_into` reaches for one fragment against one buffer.
enum StoreOutcome {
    /// No buffer for this pair; nothing to do.
    Missing,
    /// Dropped without penalty: a tolerated duplicate or a byte-cap reject-new.
    Ignored,
    /// Too many duplicate indices inside one timeout window (check 2): P7.
    DuplicatePenalty,
    /// A consistency check failed (checks 1, 3, 4, 6): drop the buffer, P4.
    Violation,
    /// Stored; the transfer is still incomplete.
    Stored { charged: usize },
    /// Stored, and every fragment is now present.
    Completed { charged: usize },
}

impl State {
    /// Records a PREAMBLE. Allocates no payload memory.
    pub(crate) fn handle_preamble(
        &mut self,
        peer_id: &PeerId,
        preamble: Preamble,
        limits: &Limits,
    ) -> Vec<ReceivedAction> {
        let now = Instant::now();
        let refused = self.is_poisoned(peer_id, &preamble.message_id)
            || self
                .peers
                .get(peer_id)
                .is_some_and(|peer_state| peer_state.reassembly.contains_key(&preamble.message_id));
        if refused {
            Vec::new()
        } else {
            // Announce IMRECEIVING for a message we are not yet receiving from
            // anyone, at most once per message id per node, and only above the
            // preamble threshold. The caller already refused PREAMBLEs for
            // messages in the duplicate cache.
            let announce = !self.is_receiving(&preamble.message_id)
                && !self.imreceiving_already_sent(&preamble.message_id)
                && preamble.message_size > limits.preamble_threshold as u64;
            let peer_state = self.peers.entry(*peer_id).or_default();
            let known = peer_state.announcements.contains_key(&preamble.message_id);
            if !known
                && peer_state.announcements.len() >= limits.max_preamble_announcements_per_peer
            {
                peer_state.announcements.pop_front();
            }
            // The keyed insert is what makes a PREAMBLE count only once per
            // message id; a repeat neither refreshes the timer nor evicts.
            peer_state
                .announcements
                .entry(preamble.message_id.clone())
                .or_insert_with(|| Announcement {
                    message_size: preamble.message_size,
                    topic_hash: preamble.topic_hash.clone(),
                    at: now,
                    imreceiving_sent: announce,
                });
            if !known && announce {
                vec![ReceivedAction::AnnounceReceiving {
                    message_id: preamble.message_id,
                    topic_hash: preamble.topic_hash,
                }]
            } else {
                Vec::new()
            }
        }
    }

    /// Stores a fragment, and completes the message when the last one lands.
    ///
    /// `from_mesh` says whether the sender is in the topic mesh (or is an
    /// explicit peer); such a sender may reclaim a sender slot held by a
    /// non-mesh peer when [`MAX_SENDERS_PER_MESSAGE`] is reached.
    pub(crate) fn handle_fragment(
        &mut self,
        peer_id: &PeerId,
        fragment: LargeMessageFragment,
        from_mesh: bool,
        limits: &Limits,
        validation_mode: &ValidationMode,
    ) -> Vec<ReceivedAction> {
        let now = Instant::now();
        // The codec already drops these shapes; feeding the state machine
        // directly must not bypass the same bounds.
        let malformed = fragment.total_fragments == 0
            || fragment.total_fragments > MAX_FRAGMENTS_HARD_CAP
            || fragment.fragment_index >= fragment.total_fragments
            || fragment.fragment_data.is_empty()
            || fragment.fragment_data.len() > limits.max_inbound_fragment_bytes;
        let has_buffer = self
            .peers
            .get(peer_id)
            .is_some_and(|peer_state| peer_state.reassembly.contains_key(&fragment.message_id));
        match () {
            () if malformed || self.is_poisoned(peer_id, &fragment.message_id) => Vec::new(),
            () if has_buffer => {
                self.check_and_store(peer_id, fragment, limits, validation_mode, now)
            }
            () => self.open_buffer_and_store(
                peer_id,
                fragment,
                from_mesh,
                limits,
                validation_mode,
                now,
            ),
        }
    }

    /// Drops buffers and announcements older than `fragment_timeout` and expires
    /// poisoned message ids.
    pub(crate) fn heartbeat(&mut self, limits: &Limits, now: Instant) -> Vec<ReceivedAction> {
        let timeout = limits.fragment_timeout;
        let mut actions = Vec::new();
        let mut released_bytes = 0usize;
        let mut released_buffers = 0usize;
        let mut released_ids: Vec<MessageId> = Vec::new();
        self.peers.iter_mut().for_each(|(peer_id, peer_state)| {
            let PeerState {
                reassembly,
                announcements,
                poisoned,
                budget,
            } = peer_state;
            // Refill the relay token bucket and lift an expired cooldown.
            budget.relay_bytes_this_heartbeat = RELAY_BYTES_PER_HEARTBEAT;
            budget.relay_paused_until = budget.relay_paused_until.filter(|until| now < *until);
            reassembly.retain(|message_id, reassembly| {
                let keep = now.duration_since(reassembly.started) < timeout;
                if !keep {
                    let charge = reassembly.received_bytes
                        + reassembly.received.len() * FRAGMENT_ENTRY_OVERHEAD;
                    budget.reassembly_bytes = budget.reassembly_bytes.saturating_sub(charge);
                    released_bytes += charge;
                    released_buffers += 1;
                    released_ids.push(message_id.clone());
                    // A transfer that timed out holding partial data counts
                    // toward the relay cooldown for this peer.
                    if reassembly.received_bytes > 0 {
                        budget.incomplete_transfers = budget.incomplete_transfers.saturating_add(1);
                        if budget.incomplete_transfers > MAX_INCOMPLETE_TRANSFERS {
                            budget.relay_paused_until = Some(now + RELAY_COOLDOWN);
                        }
                    }
                    actions.push(ReceivedAction::PenalizePeer {
                        peer_id: *peer_id,
                        topic_hash: reassembly.topic_hash.clone(),
                        penalty: Penalty::Behavioural,
                    });
                }
                keep
            });
            announcements.retain(|_, announcement| {
                let keep = now.duration_since(announcement.at) < timeout;
                if !keep {
                    actions.push(ReceivedAction::PenalizePeer {
                        peer_id: *peer_id,
                        topic_hash: announcement.topic_hash.clone(),
                        penalty: Penalty::Behavioural,
                    });
                }
                keep
            });
            poisoned.retain(|_, at| now.duration_since(*at) < timeout);
        });
        self.total_bytes = self.total_bytes.saturating_sub(released_bytes);
        self.total_reassemblies = self.total_reassemblies.saturating_sub(released_buffers);
        released_ids
            .iter()
            .for_each(|message_id| self.release_sender(message_id));
        // The ledger's TTL matches the reassembly buffers it describes.
        self.relayed
            .retain(|_, record| now.duration_since(record.at) < timeout);
        self.peers.retain(|_, peer_state| {
            !(peer_state.reassembly.is_empty()
                && peer_state.announcements.is_empty()
                && peer_state.poisoned.is_empty()
                // A pruned entry would forget a live relay cooldown or the
                // repeat-offender count that triggers one.
                && peer_state.budget.relay_paused_until.is_none()
                && peer_state.budget.incomplete_transfers == 0)
        });
        actions
    }

    /// Drops everything held for a peer that went away, releasing its whole budget.
    pub(crate) fn peer_disconnected(&mut self, peer_id: &PeerId) {
        let released_ids: Vec<MessageId> =
            self.peers
                .remove(peer_id)
                .map_or_else(Vec::new, |peer_state| {
                    let bytes: usize = peer_state
                        .reassembly
                        .iter()
                        .map(|(_, reassembly)| {
                            reassembly.received_bytes
                                + reassembly.received.len() * FRAGMENT_ENTRY_OVERHEAD
                        })
                        .sum();
                    self.total_bytes = self.total_bytes.saturating_sub(bytes);
                    self.total_reassemblies = self
                        .total_reassemblies
                        .saturating_sub(peer_state.reassembly.len());
                    peer_state
                        .reassembly
                        .into_iter()
                        .map(|(message_id, _)| message_id)
                        .collect()
                });
        released_ids
            .iter()
            .for_each(|message_id| self.release_sender(message_id));
    }

    /// Records that `(peer_id, message_id)` failed the behaviour's id-binding
    /// check, so the pair is refused for `fragment_timeout`.
    ///
    /// The check itself needs the data transform and so runs on the
    /// [`Behaviour`](crate::Behaviour) (C12), but the storage lives here with the
    /// rest of the per-peer state: it is capped at `MAX_POISONED_IDS_PER_PEER`,
    /// evicted LRU, swept by `heartbeat`, and released whole by
    /// `peer_disconnected`.
    pub(crate) fn poison(&mut self, peer_id: &PeerId, message_id: MessageId, now: Instant) {
        let peer_state = self.peers.entry(*peer_id).or_default();
        if peer_state.poisoned.len() >= MAX_POISONED_IDS_PER_PEER
            && !peer_state.poisoned.contains_key(&message_id)
        {
            peer_state.poisoned.pop_front();
        }
        peer_state.poisoned.insert(message_id, now);
    }

    /// Whether `(peer_id, message_id)` is poisoned. Consulted on admission by
    /// `handle_preamble` and `handle_fragment`.
    pub(crate) fn is_poisoned(&self, peer_id: &PeerId, message_id: &MessageId) -> bool {
        self.peers
            .get(peer_id)
            .is_some_and(|peer_state| peer_state.poisoned.contains_key(message_id))
    }

    /// Opens a reassembly buffer for `(peer, message id)` if every admission cap
    /// allows it, then stores the fragment. Rejection is reject-new and silent:
    /// an existing buffer is never evicted to make room.
    fn open_buffer_and_store(
        &mut self,
        peer_id: &PeerId,
        fragment: LargeMessageFragment,
        from_mesh: bool,
        limits: &Limits,
        validation_mode: &ValidationMode,
        now: Instant,
    ) -> Vec<ReceivedAction> {
        let announcement_topic_mismatch = self
            .peers
            .get(peer_id)
            .and_then(|peer_state| peer_state.announcements.get(&fragment.message_id))
            .is_some_and(|announcement| announcement.topic_hash != fragment.topic_hash);
        let pending = self
            .peers
            .get(peer_id)
            .map_or(0, |peer_state| peer_state.reassembly.len());
        // A mesh (or explicit) sender is never locked out of the per-id sender
        // slots by senders that were outside the mesh when their buffers
        // opened: the least-progressed such buffer is evicted instead.
        // Without this, [`MAX_SENDERS_PER_MESSAGE`] cheap non-mesh identities
        // could each hold a slot for a chosen message id with a single
        // fragment and draw IMRECEIVING refusals to the honest mesh senders
        // of that message until `fragment_timeout`.
        let at_cap = self
            .senders_per_message
            .get(&fragment.message_id)
            .copied()
            .unwrap_or(0)
            >= MAX_SENDERS_PER_MESSAGE;
        if at_cap
            && from_mesh
            && !announcement_topic_mismatch
            && pending < limits.max_pending_fragments
        {
            self.evict_non_mesh_sender(&fragment.message_id);
        }
        let senders = self
            .senders_per_message
            .get(&fragment.message_id)
            .copied()
            .unwrap_or(0);
        let rejected = pending >= limits.max_pending_fragments
            || self.total_reassemblies >= MAX_REASSEMBLIES_TOTAL
            || senders >= MAX_SENDERS_PER_MESSAGE;
        match () {
            // Check 6 against the announcement: drop it and penalize.
            () if announcement_topic_mismatch => {
                if let Some(peer_state) = self.peers.get_mut(peer_id) {
                    peer_state.announcements.remove(&fragment.message_id);
                }
                self.prune_peer(peer_id);
                vec![ReceivedAction::PenalizePeer {
                    peer_id: *peer_id,
                    topic_hash: fragment.topic_hash,
                    penalty: Penalty::InvalidMessage(ValidationError::MessageReassemblyFailed),
                }]
            }
            // The senders cap is the one rejection the extra sender can act on:
            // an IMRECEIVING reply tells it we already receive this message
            // elsewhere, so it can stop spending bytes on us.
            () if senders >= MAX_SENDERS_PER_MESSAGE => {
                vec![ReceivedAction::ReplyImReceiving {
                    peer_id: *peer_id,
                    message_id: fragment.message_id,
                }]
            }
            () if rejected => Vec::new(),
            () => {
                let peer_state = self.peers.entry(*peer_id).or_default();
                let (started, announced_size, imreceiving_sent) = peer_state
                    .announcements
                    .remove(&fragment.message_id)
                    .map_or((now, None, false), |announcement| {
                        (
                            announcement.at,
                            Some(announcement.message_size),
                            announcement.imreceiving_sent,
                        )
                    });
                peer_state.reassembly.insert(
                    fragment.message_id.clone(),
                    Reassembly {
                        topic_hash: fragment.topic_hash.clone(),
                        total_fragments: fragment.total_fragments,
                        received: BTreeMap::new(),
                        received_bytes: 0,
                        fragment_len: None,
                        announced_size,
                        started,
                        duplicate_indices: 0,
                        imreceiving_sent,
                        from_mesh,
                    },
                );
                *self
                    .senders_per_message
                    .entry(fragment.message_id.clone())
                    .or_insert(0) += 1;
                self.total_reassemblies += 1;
                self.check_and_store(peer_id, fragment, limits, validation_mode, now)
            }
        }
    }

    /// Evicts the least-progressed reassembly of `message_id` whose sender was
    /// not in the topic mesh when the buffer opened, freeing one sender slot
    /// for a mesh sender. The evicted peer broke no rule and is not penalized;
    /// its next fragment for the id is answered with IMRECEIVING while the
    /// slots stay full.
    fn evict_non_mesh_sender(&mut self, message_id: &MessageId) {
        let evict = self
            .peers
            .iter()
            .filter_map(|(peer_id, peer_state)| {
                peer_state
                    .reassembly
                    .get(message_id)
                    .filter(|reassembly| !reassembly.from_mesh)
                    .map(|reassembly| (*peer_id, reassembly.received_bytes))
            })
            .min_by_key(|(_, received_bytes)| *received_bytes)
            .map(|(peer_id, _)| peer_id);
        if let Some(evicted) = evict {
            tracing::debug!(
                peer=%evicted,
                message=%message_id,
                "Evicting a non-mesh reassembly to admit a mesh sender"
            );
            self.drop_buffer(&evicted, message_id);
        }
    }

    /// Runs consistency checks 1-6 against the existing buffer, stores the
    /// fragment, and completes the message when the last one lands (check 7).
    fn check_and_store(
        &mut self,
        peer_id: &PeerId,
        fragment: LargeMessageFragment,
        limits: &Limits,
        validation_mode: &ValidationMode,
        now: Instant,
    ) -> Vec<ReceivedAction> {
        let message_id = fragment.message_id.clone();
        let topic_hash = fragment.topic_hash.clone();
        let index = fragment.fragment_index;
        let len = fragment.fragment_data.len();
        let total_bytes = self.total_bytes;
        let outcome = self
            .peers
            .get_mut(peer_id)
            .map_or(StoreOutcome::Missing, |peer_state| {
                let PeerState {
                    reassembly, budget, ..
                } = peer_state;
                reassembly
                    .get_mut(&message_id)
                    .map_or(StoreOutcome::Missing, |reassembly| {
                        store_into(reassembly, budget, total_bytes, fragment, limits)
                    })
            });
        match outcome {
            StoreOutcome::Missing | StoreOutcome::Ignored => Vec::new(),
            StoreOutcome::Stored { charged } => {
                self.total_bytes += charged;
                self.relay_and_announce(peer_id, &message_id, &topic_hash, index, len, limits, now)
            }
            StoreOutcome::DuplicatePenalty => vec![ReceivedAction::PenalizePeer {
                peer_id: *peer_id,
                topic_hash,
                penalty: Penalty::Behavioural,
            }],
            StoreOutcome::Violation => {
                self.drop_buffer(peer_id, &message_id);
                vec![ReceivedAction::PenalizePeer {
                    peer_id: *peer_id,
                    topic_hash,
                    penalty: Penalty::InvalidMessage(ValidationError::MessageReassemblyFailed),
                }]
            }
            StoreOutcome::Completed { charged } => {
                self.total_bytes += charged;
                // Relay the final fragment before reporting the reassembled
                // message, so the ledger records the whole run before the
                // behaviour's `forward_msg` consults it.
                let mut actions = self.relay_and_announce(
                    peer_id,
                    &message_id,
                    &topic_hash,
                    index,
                    len,
                    limits,
                    now,
                );
                actions.extend(self.complete(peer_id, &message_id, limits, validation_mode));
                actions
            }
        }
    }

    /// After one fragment is stored: announce IMRECEIVING on the first accepted
    /// fragment of a large transfer, and emit the relay when the sender's token
    /// bucket and cooldown allow it. The bucket is charged here even when the
    /// behaviour's admission checks later drop the relay: overcharging is the
    /// safe direction for a rate cap.
    #[allow(clippy::too_many_arguments)]
    fn relay_and_announce(
        &mut self,
        peer_id: &PeerId,
        message_id: &MessageId,
        topic_hash: &TopicHash,
        index: u32,
        len: usize,
        limits: &Limits,
        now: Instant,
    ) -> Vec<ReceivedAction> {
        let already_sent = self.imreceiving_already_sent(message_id);
        let mut actions = Vec::new();
        if let Some(peer_state) = self.peers.get_mut(peer_id) {
            if let Some(reassembly) = peer_state.reassembly.get_mut(message_id) {
                let first_accepted = reassembly.received.len() == 1;
                let projected = u64::from(reassembly.total_fragments) * len as u64;
                let size = reassembly.announced_size.unwrap_or(projected);
                if first_accepted && !already_sent && size > limits.preamble_threshold as u64 {
                    reassembly.imreceiving_sent = true;
                    actions.push(ReceivedAction::AnnounceReceiving {
                        message_id: message_id.clone(),
                        topic_hash: topic_hash.clone(),
                    });
                }
            }
            let budget = &mut peer_state.budget;
            budget.relay_paused_until = budget.relay_paused_until.filter(|until| now < *until);
            let relay_allowed =
                budget.relay_paused_until.is_none() && budget.relay_bytes_this_heartbeat >= len;
            if relay_allowed {
                budget.relay_bytes_this_heartbeat -= len;
            }
            if relay_allowed
                && let Some(reassembly) = peer_state.reassembly.get(message_id)
                && let Some(fragment_data) = reassembly.received.get(&index)
            {
                actions.push(ReceivedAction::RelayFragment(LargeMessageFragment {
                    message_id: message_id.clone(),
                    fragment_index: index,
                    total_fragments: reassembly.total_fragments,
                    fragment_data: fragment_data.clone(),
                    topic_hash: topic_hash.clone(),
                }));
            }
        }
        actions
    }

    /// Whether any live reassembly or announcement already carried this node's
    /// IMRECEIVING for `message_id`, so a node announces at most once per id.
    fn imreceiving_already_sent(&self, message_id: &MessageId) -> bool {
        self.peers.values().any(|peer_state| {
            peer_state
                .reassembly
                .get(message_id)
                .is_some_and(|reassembly| reassembly.imreceiving_sent)
                || peer_state
                    .announcements
                    .get(message_id)
                    .is_some_and(|announcement| announcement.imreceiving_sent)
        })
    }

    /// Whether any reassembly for `message_id` is currently open, from any
    /// sender. `handle_ihave` defers IWANTs for such ids by one heartbeat.
    pub(crate) fn is_receiving(&self, message_id: &MessageId) -> bool {
        self.senders_per_message.contains_key(message_id)
    }

    /// The bytes currently charged across every reassembly buffer.
    #[cfg(feature = "metrics")]
    pub(crate) fn reassembly_bytes_in_use(&self) -> usize {
        self.total_bytes
    }

    /// The number of reassembly buffers currently open across every peer.
    #[cfg(feature = "metrics")]
    pub(crate) fn reassemblies_in_progress(&self) -> usize {
        self.total_reassemblies
    }

    /// Whether a reassembly of `message_id` from `peer_id` is currently open.
    #[cfg(feature = "metrics")]
    pub(crate) fn is_reassembling(&self, peer_id: &PeerId, message_id: &MessageId) -> bool {
        self.peers
            .get(peer_id)
            .is_some_and(|peer_state| peer_state.reassembly.contains_key(message_id))
    }

    /// Records that index `i` of `m` reached `q`. Returns the recipients that now hold every
    /// index, so the caller can mark them in `PeerDetails.fragments_relayed`.
    pub(crate) fn record_relayed(
        &mut self,
        m: &MessageId,
        q: PeerId,
        i: u32,
        total_fragments: u32,
    ) -> Vec<PeerId> {
        // A record tracking a different chunking of the same id cannot answer
        // per-index questions; replace it and accept a possible re-send.
        let stale = self
            .relayed
            .get(m)
            .is_some_and(|record| record.total_fragments != total_fragments);
        if stale {
            self.relayed.remove(m);
        }
        if !self.relayed.contains_key(m) && self.relayed.len() >= MAX_RELAY_RECORDS {
            self.relayed.pop_front();
        }
        let record = self
            .relayed
            .entry(m.clone())
            .or_insert_with(|| RelayRecord {
                total_fragments,
                per_recipient: HashMap::new(),
                at: Instant::now(),
            });
        let indices = record
            .per_recipient
            .entry(q)
            .or_insert_with(|| IndexSet::new(total_fragments));
        indices.insert(i);
        if indices.is_full() {
            vec![q]
        } else {
            Vec::new()
        }
    }

    /// Whether index `i` of `m` already reached `q`, whichever sender it came
    /// from (L3f).
    pub(crate) fn already_relayed(&self, m: &MessageId, q: &PeerId, i: u32) -> bool {
        self.relayed.get(m).is_some_and(|record| {
            record
                .per_recipient
                .get(q)
                .is_some_and(|indices| indices.contains(i))
        })
    }

    /// Indices of `m` that `q` has not received from us. Empty when `q` has them all;
    /// `0..total_fragments` when we relayed nothing to `q`.
    pub(crate) fn missing_indices(
        &self,
        m: &MessageId,
        q: &PeerId,
        total_fragments: u32,
    ) -> Vec<u32> {
        self.relayed
            .get(m)
            .filter(|record| record.total_fragments == total_fragments)
            .and_then(|record| record.per_recipient.get(q))
            .map_or_else(|| (0..total_fragments).collect(), IndexSet::missing)
    }

    /// Check 7: concatenate in `BTreeMap` key order, prost-decode, and validate
    /// the decoded message. The buffer is dropped whole either way.
    fn complete(
        &mut self,
        peer_id: &PeerId,
        message_id: &MessageId,
        limits: &Limits,
        validation_mode: &ValidationMode,
    ) -> Vec<ReceivedAction> {
        self.take_buffer(peer_id, message_id)
            .map_or_else(Vec::new, |reassembly| {
                let topic_hash = reassembly.topic_hash.clone();
                let announced_size = reassembly.announced_size;
                let encoded = reassembly
                    .received
                    .into_values()
                    .collect::<Vec<_>>()
                    .concat();
                // Check 5: `messageSize` is advisory; a mismatch is never penalized.
                if announced_size.is_some_and(|size| size != encoded.len() as u64) {
                    tracing::debug!(
                        message=%message_id,
                        "PREAMBLE messageSize differs from the reassembled length"
                    );
                }
                let topic_for_decode = topic_hash.clone();
                proto::Message::decode(encoded.as_slice()).map_or_else(
                    |_| {
                        vec![ReceivedAction::PenalizePeer {
                            peer_id: *peer_id,
                            topic_hash: topic_for_decode,
                            penalty: Penalty::InvalidMessage(
                                ValidationError::MessageReassemblyFailed,
                            ),
                        }]
                    },
                    |message| {
                        validate_proto_message(
                            message,
                            validation_mode,
                            Some(limits.max_message_bytes),
                        )
                        .map_or_else(
                            |(_, validation_error)| {
                                vec![ReceivedAction::PenalizePeer {
                                    peer_id: *peer_id,
                                    topic_hash,
                                    penalty: Penalty::InvalidMessage(validation_error),
                                }]
                            },
                            |message| {
                                vec![ReceivedAction::MessageReassembled {
                                    announced_id: message_id.clone(),
                                    message,
                                }]
                            },
                        )
                    },
                )
            })
    }

    /// Removes the buffer for `(peer, message id)` and releases every count it
    /// held: peer budget, global bytes, the global slot and the sender slot.
    fn take_buffer(&mut self, peer_id: &PeerId, message_id: &MessageId) -> Option<Reassembly> {
        self.peers
            .get_mut(peer_id)
            .and_then(|peer_state| {
                peer_state
                    .reassembly
                    .remove(message_id)
                    .inspect(|reassembly| {
                        let charge = reassembly.received_bytes
                            + reassembly.received.len() * FRAGMENT_ENTRY_OVERHEAD;
                        peer_state.budget.reassembly_bytes =
                            peer_state.budget.reassembly_bytes.saturating_sub(charge);
                    })
            })
            .inspect(|reassembly| {
                let charge =
                    reassembly.received_bytes + reassembly.received.len() * FRAGMENT_ENTRY_OVERHEAD;
                self.total_bytes = self.total_bytes.saturating_sub(charge);
                self.total_reassemblies = self.total_reassemblies.saturating_sub(1);
                self.release_sender(message_id);
                self.prune_peer(peer_id);
            })
    }

    /// `take_buffer`, discarding the buffer. One drop site for every failure path.
    fn drop_buffer(&mut self, peer_id: &PeerId, message_id: &MessageId) {
        let _ = self.take_buffer(peer_id, message_id);
    }

    /// Decrements the sender count for a message id, removing the entry at zero.
    /// Called from every buffer-drop site, which is what keeps the key count
    /// bounded by the open-buffer count.
    fn release_sender(&mut self, message_id: &MessageId) {
        let remaining = self.senders_per_message.get_mut(message_id).map(|count| {
            *count = count.saturating_sub(1);
            *count
        });
        if remaining == Some(0) {
            self.senders_per_message.remove(message_id);
        }
    }

    /// Removes a peer entry once all of its maps are empty.
    fn prune_peer(&mut self, peer_id: &PeerId) {
        let empty = self.peers.get(peer_id).is_some_and(|peer_state| {
            peer_state.reassembly.is_empty()
                && peer_state.announcements.is_empty()
                && peer_state.poisoned.is_empty()
                // A pruned entry would forget a live relay cooldown or the
                // repeat-offender count that triggers one.
                && peer_state.budget.relay_paused_until.is_none()
                && peer_state.budget.incomplete_transfers == 0
        });
        if empty {
            self.peers.remove(peer_id);
        }
    }
}

/// Runs consistency checks 1-4 and 6 for one fragment against its buffer and
/// stores the payload when every check passes. Pure with respect to `State`, so
/// the borrows stay local.
fn store_into(
    reassembly: &mut Reassembly,
    budget: &mut PeerBudget,
    total_bytes: usize,
    fragment: LargeMessageFragment,
    limits: &Limits,
) -> StoreOutcome {
    let index = fragment.fragment_index;
    let len = fragment.fragment_data.len();
    let charge = len + FRAGMENT_ENTRY_OVERHEAD;
    let single = reassembly.total_fragments == 1;
    let final_index = reassembly.total_fragments.saturating_sub(1);
    let is_final = index == final_index;
    // Check 1.
    let total_mismatch = fragment.total_fragments != reassembly.total_fragments;
    // Check 6.
    let topic_mismatch = fragment.topic_hash != reassembly.topic_hash;
    // Check 2.
    let duplicate = reassembly.received.contains_key(&index);
    // Check 3: uniform chunk size, learned from the transfer, never from our knob.
    let len_violation = !single
        && reassembly.fragment_len.is_some_and(|fragment_len| {
            if is_final {
                len > fragment_len
            } else {
                len != fragment_len
            }
        });
    let learned_len = reassembly
        .fragment_len
        .or((!single && !is_final).then_some(len));
    // Check 3, final-first: a final fragment stored before any non-final one is
    // re-checked the moment the chunk size is learned.
    let stored_final_violates = !single
        && !is_final
        && reassembly.fragment_len.is_none()
        && reassembly
            .received
            .get(&final_index)
            .is_some_and(|data| data.len() > len);
    // Check 4: bounds from us or from the transfer, never from `fragment_size`.
    let over_message = reassembly.received_bytes + len > limits.max_message_bytes;
    let over_layout = learned_len.is_some_and(|fragment_len| {
        (reassembly.received_bytes + len) as u64
            > u64::from(reassembly.total_fragments) * fragment_len as u64
    });
    // Reject-new byte caps; a reject here is silent and keeps the buffer.
    let over_budget = budget.reassembly_bytes + charge > limits.max_reassembly_bytes_per_peer
        || total_bytes + charge > limits.max_reassembly_bytes_total;
    match () {
        () if total_mismatch || topic_mismatch => StoreOutcome::Violation,
        () if duplicate => {
            reassembly.duplicate_indices = reassembly.duplicate_indices.saturating_add(1);
            if reassembly.duplicate_indices as usize > limits.max_pending_fragments {
                reassembly.duplicate_indices = 0;
                StoreOutcome::DuplicatePenalty
            } else {
                StoreOutcome::Ignored
            }
        }
        () if len_violation || stored_final_violates || over_message || over_layout => {
            StoreOutcome::Violation
        }
        () if over_budget => StoreOutcome::Ignored,
        () => {
            reassembly.fragment_len = learned_len;
            reassembly.received.insert(index, fragment.fragment_data);
            reassembly.received_bytes += len;
            budget.reassembly_bytes += charge;
            if reassembly.received.len() as u64 == u64::from(reassembly.total_fragments) {
                StoreOutcome::Completed { charged: charge }
            } else {
                StoreOutcome::Stored { charged: charge }
            }
        }
    }
}

/// Splits an encoded message into fragments of at most `fragment_size` bytes.
///
/// The bytes fragmented are the encoded `proto::Message` (the same bytes a
/// legacy peer would receive inside an RPC), so a receiver that concatenates
/// the fragments can decode, verify the signature, and recompute the message
/// id. Every fragment except the final one is exactly `fragment_size` bytes,
/// which is what receive-side check 3 expects of us. Errors when the message
/// would need more than [`MAX_FRAGMENTS_HARD_CAP`] fragments.
pub(crate) fn fragment_message(
    message_id: &MessageId,
    raw_message: &RawMessage,
    fragment_size: usize,
) -> Result<Vec<LargeMessageFragment>, PublishError> {
    let proto_message: proto::Message = raw_message.clone().into();
    let encoded = proto_message.encode_to_vec();
    let chunk = fragment_size.max(1);
    let total = encoded.len().div_ceil(chunk);
    if total > MAX_FRAGMENTS_HARD_CAP as usize {
        Err(PublishError::MessageTooLarge)
    } else {
        let total_fragments = total as u32;
        Ok(encoded
            .chunks(chunk)
            .enumerate()
            .map(|(index, fragment_data)| LargeMessageFragment {
                message_id: message_id.clone(),
                fragment_index: index as u32,
                total_fragments,
                fragment_data: fragment_data.to_vec(),
                topic_hash: raw_message.topic.clone(),
            })
            .collect())
    }
}

#[cfg(test)]
impl State {
    /// Total payload bytes currently charged.
    pub(crate) fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Reassembly buffers currently open across every peer.
    pub(crate) fn total_reassemblies(&self) -> usize {
        self.total_reassemblies
    }

    /// Open reassembly buffers held for one peer.
    pub(crate) fn pending_reassemblies(&self, peer_id: &PeerId) -> usize {
        self.peers
            .get(peer_id)
            .map_or(0, |peer_state| peer_state.reassembly.len())
    }

    /// PREAMBLE announcements held for one peer.
    pub(crate) fn announcements_len(&self, peer_id: &PeerId) -> usize {
        self.peers
            .get(peer_id)
            .map_or(0, |peer_state| peer_state.announcements.len())
    }

    /// Whether an announcement for `(peer, message id)` is currently held.
    pub(crate) fn has_announcement(&self, peer_id: &PeerId, message_id: &MessageId) -> bool {
        self.peers
            .get(peer_id)
            .is_some_and(|peer_state| peer_state.announcements.contains_key(message_id))
    }

    /// Poisoned message ids held for one peer.
    pub(crate) fn poisoned_len(&self, peer_id: &PeerId) -> usize {
        self.peers
            .get(peer_id)
            .map_or(0, |peer_state| peer_state.poisoned.len())
    }

    /// Live sender count for one message id.
    pub(crate) fn senders_for(&self, message_id: &MessageId) -> u8 {
        self.senders_per_message
            .get(message_id)
            .copied()
            .unwrap_or(0)
    }

    /// Relay ledger records currently held.
    pub(crate) fn relayed_records(&self) -> usize {
        self.relayed.len()
    }

    /// Remaining relay bytes for one peer this heartbeat, when the peer is known.
    pub(crate) fn relay_budget(&self, peer_id: &PeerId) -> Option<usize> {
        self.peers
            .get(peer_id)
            .map(|peer_state| peer_state.budget.relay_bytes_this_heartbeat)
    }

    /// Whether relaying for the peer is currently paused.
    pub(crate) fn relay_paused(&self, peer_id: &PeerId) -> bool {
        self.peers
            .get(peer_id)
            .is_some_and(|peer_state| peer_state.budget.relay_paused_until.is_some())
    }
}
