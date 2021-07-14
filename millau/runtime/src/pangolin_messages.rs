//! Everything required to serve Millau <-> Pangolin messages.

// --- crates.io ---
use codec::{Decode, Encode};
// --- substrate ---
use bp_messages::{
	source_chain::TargetHeaderChain,
	target_chain::{ProvedMessages, SourceHeaderChain},
	InboundLaneData, LaneId, Message, MessageNonce, Parameter as MessagesParameter,
};
use bp_runtime::{ChainId, MILLAU_CHAIN_ID};
use bridge_runtime_common::messages::{
	self,
	source::{
		self, FromBridgedChainMessagesDeliveryProof, FromThisChainMessagePayload,
		FromThisChainMessageVerifier,
	},
	target::{
		self, FromBridgedChainEncodedMessageCall, FromBridgedChainMessageDispatch,
		FromBridgedChainMessagePayload, FromBridgedChainMessagesProof,
	},
	MessageBridge, MessageTransaction,
};
use frame_support::{
	weights::{DispatchClass, Weight},
	RuntimeDebug,
};
use pallet_bridge_messages::EXPECTED_DEFAULT_MESSAGE_LENGTH;
use sp_runtime::{traits::Zero, FixedPointNumber, FixedU128};
use sp_std::{convert::TryFrom, ops::RangeInclusive};
// --- darwinia ---
use crate::{Runtime, MILLAU_PANGOLIN_LANE};
use pangolin_bridge_primitives::PANGOLIN_CHAIN_ID;

/// Message payload for Millau -> Pangolin messages.
pub type ToPangolinMessagePayload = FromThisChainMessagePayload<WithPangolinMessageBridge>;
/// Message verifier for Millau -> Pangolin messages.
pub type ToPangolinMessageVerifier = FromThisChainMessageVerifier<WithPangolinMessageBridge>;
/// Message payload for Pangolin -> Millau messages.
pub type FromPangolinMessagePayload = FromBridgedChainMessagePayload<WithPangolinMessageBridge>;
/// Encoded Millau Call as it comes from Pangolin.
pub type FromPangolinEncodedCall = FromBridgedChainEncodedMessageCall<WithPangolinMessageBridge>;
/// Messages proof for Pangolin -> Millau messages.
type FromPangolinMessagesProof = FromBridgedChainMessagesProof<drml_primitives::Hash>;
/// Messages delivery proof for Millau -> Pangolin messages.
type ToPangolinMessagesDeliveryProof = FromBridgedChainMessagesDeliveryProof<drml_primitives::Hash>;
/// Call-dispatch based message dispatch for Pangolin -> Millau messages.
pub type FromPangolinMessageDispatch = FromBridgedChainMessageDispatch<
	WithPangolinMessageBridge,
	Runtime,
	crate::WithPangolinDispatch,
>;

/// Initial value of `PangolinToMillauConversionRate` parameter.
pub const INITIAL_PANGOLIN_TO_MILLAU_CONVERSION_RATE: FixedU128 =
	FixedU128::from_inner(FixedU128::DIV);

frame_support::parameter_types! {
	/// Pangolin to Millau conversion rate. Initially we treat both tokens as equal.
	pub storage PangolinToMillauConversionRate: FixedU128 = INITIAL_PANGOLIN_TO_MILLAU_CONVERSION_RATE;
}

/// Millau -> Pangolin message lane pallet parameters.
#[derive(Clone, PartialEq, Eq, Encode, Decode, RuntimeDebug)]
pub enum MillauToPangolinMessagesParameter {
	/// The conversion formula we use is: `MillauTokens = PangolinTokens * conversion_rate`.
	PangolinToMillauConversionRate(FixedU128),
}
impl MessagesParameter for MillauToPangolinMessagesParameter {
	fn save(&self) {
		match *self {
			MillauToPangolinMessagesParameter::PangolinToMillauConversionRate(
				ref conversion_rate,
			) => PangolinToMillauConversionRate::set(conversion_rate),
		}
	}
}

/// Millau <-> Pangolin message bridge.
#[derive(Clone, Copy, RuntimeDebug)]
pub struct WithPangolinMessageBridge;
impl MessageBridge for WithPangolinMessageBridge {
	const RELAYER_FEE_PERCENT: u32 = 10;

	type ThisChain = Millau;
	type BridgedChain = Pangolin;

	fn bridged_balance_to_this_balance(
		bridged_balance: drml_primitives::Balance,
	) -> millau_primitives::Balance {
		millau_primitives::Balance::try_from(
			PangolinToMillauConversionRate::get().saturating_mul_int(bridged_balance),
		)
		.unwrap_or(millau_primitives::Balance::MAX)
	}
}

/// Millau chain from message lane point of view.
#[derive(Clone, Copy, RuntimeDebug)]
pub struct Millau;
impl messages::ChainWithMessages for Millau {
	const ID: ChainId = MILLAU_CHAIN_ID;

	type Hash = millau_primitives::Hash;
	type AccountId = millau_primitives::AccountId;
	type Signer = millau_primitives::AccountPublic;
	type Signature = millau_primitives::Signature;
	type Weight = Weight;
	type Balance = millau_primitives::Balance;

	type MessagesInstance = crate::WithPangolinMessages;
}
impl messages::ThisChainWithMessages for Millau {
	type Call = crate::Call;

	fn is_outbound_lane_enabled(lane: &LaneId) -> bool {
		*lane == [0, 0, 0, 0] || *lane == [0, 0, 0, 1] || *lane == MILLAU_PANGOLIN_LANE
	}

	fn maximal_pending_messages_at_outbound_lane() -> MessageNonce {
		MessageNonce::MAX
	}

	fn estimate_delivery_confirmation_transaction() -> MessageTransaction<Weight> {
		let inbound_data_size = InboundLaneData::<millau_primitives::AccountId>::encoded_size_hint(
			millau_primitives::MAXIMAL_ENCODED_ACCOUNT_ID_SIZE,
			1,
		)
		.unwrap_or(u32::MAX);

		MessageTransaction {
			dispatch_weight: millau_primitives::MAX_SINGLE_MESSAGE_DELIVERY_CONFIRMATION_TX_WEIGHT,
			size: inbound_data_size
				.saturating_add(pangolin_bridge_primitives::EXTRA_STORAGE_PROOF_SIZE)
				.saturating_add(millau_primitives::TX_EXTRA_BYTES),
		}
	}

	fn transaction_payment(transaction: MessageTransaction<Weight>) -> millau_primitives::Balance {
		// in our testnets, both per-byte fee and weight-to-fee are 1:1
		messages::transaction_payment(
			millau_primitives::RuntimeBlockWeights::get()
				.get(DispatchClass::Normal)
				.base_extrinsic,
			1,
			FixedU128::zero(),
			|weight| weight as _,
			transaction,
		)
	}
}

/// Pangolin chain from message lane point of view.
#[derive(Clone, Copy, RuntimeDebug)]
pub struct Pangolin;
impl messages::ChainWithMessages for Pangolin {
	const ID: ChainId = PANGOLIN_CHAIN_ID;

	type Hash = drml_primitives::Hash;
	type AccountId = drml_primitives::AccountId;
	type Signer = drml_primitives::AccountPublic;
	type Signature = drml_primitives::Signature;
	type Weight = Weight;
	type Balance = drml_primitives::Balance;

	type MessagesInstance = crate::WithPangolinMessages;
}
impl messages::BridgedChainWithMessages for Pangolin {
	fn maximal_extrinsic_size() -> u32 {
		pangolin_runtime_system_params::max_extrinsic_size()
	}

	fn message_weight_limits(_message_payload: &[u8]) -> RangeInclusive<Weight> {
		// we don't want to relay too large messages + keep reserve for future upgrades
		let upper_limit = messages::target::maximal_incoming_message_dispatch_weight(
			pangolin_runtime_system_params::max_extrinsic_weight(),
		);

		// we're charging for payload bytes in `WithPangolinMessageBridge::transaction_payment` function
		//
		// this bridge may be used to deliver all kind of messages, so we're not making any assumptions about
		// minimal dispatch weight here

		0..=upper_limit
	}

	fn estimate_delivery_transaction(
		message_payload: &[u8],
		message_dispatch_weight: Weight,
	) -> MessageTransaction<Weight> {
		let message_payload_len = u32::try_from(message_payload.len()).unwrap_or(u32::MAX);
		let extra_bytes_in_payload = Weight::from(message_payload_len)
			.saturating_sub(EXPECTED_DEFAULT_MESSAGE_LENGTH.into());

		MessageTransaction {
			dispatch_weight: extra_bytes_in_payload
				.saturating_mul(pangolin_bridge_primitives::ADDITIONAL_MESSAGE_BYTE_DELIVERY_WEIGHT)
				.saturating_add(pangolin_bridge_primitives::DEFAULT_MESSAGE_DELIVERY_TX_WEIGHT)
				.saturating_add(message_dispatch_weight),
			size: message_payload_len
				.saturating_add(millau_primitives::EXTRA_STORAGE_PROOF_SIZE)
				.saturating_add(pangolin_bridge_primitives::TX_EXTRA_BYTES),
		}
	}

	fn transaction_payment(transaction: MessageTransaction<Weight>) -> drml_primitives::Balance {
		// in our testnets, both per-byte fee and weight-to-fee are 1:1
		messages::transaction_payment(
			pangolin_runtime_system_params::RuntimeBlockWeights::get()
				.get(DispatchClass::Normal)
				.base_extrinsic,
			1,
			FixedU128::zero(),
			|weight| weight as _,
			transaction,
		)
	}
}
impl TargetHeaderChain<ToPangolinMessagePayload, drml_primitives::AccountId> for Pangolin {
	type Error = &'static str;
	// The proof is:
	// - hash of the header this proof has been created with;
	// - the storage proof or one or several keys;
	// - id of the lane we prove state of.
	type MessagesDeliveryProof = ToPangolinMessagesDeliveryProof;

	fn verify_message(payload: &ToPangolinMessagePayload) -> Result<(), Self::Error> {
		source::verify_chain_message::<WithPangolinMessageBridge>(payload)
	}

	fn verify_messages_delivery_proof(
		proof: Self::MessagesDeliveryProof,
	) -> Result<(LaneId, InboundLaneData<millau_primitives::AccountId>), Self::Error> {
		source::verify_messages_delivery_proof::<
			WithPangolinMessageBridge,
			Runtime,
			crate::WithPangolinGrandpa,
		>(proof)
	}
}
impl SourceHeaderChain<drml_primitives::Balance> for Pangolin {
	type Error = &'static str;
	// The proof is:
	// - hash of the header this proof has been created with;
	// - the storage proof or one or several keys;
	// - id of the lane we prove messages for;
	// - inclusive range of messages nonces that are proved.
	type MessagesProof = FromPangolinMessagesProof;

	fn verify_messages_proof(
		proof: Self::MessagesProof,
		messages_count: u32,
	) -> Result<ProvedMessages<Message<drml_primitives::Balance>>, Self::Error> {
		target::verify_messages_proof::<
			WithPangolinMessageBridge,
			Runtime,
			crate::WithPangolinGrandpa,
		>(proof, messages_count)
	}
}
