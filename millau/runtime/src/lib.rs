//! The Millau runtime. This can be compiled with `#[no_std]`, ready for Wasm.

#![cfg_attr(not(feature = "std"), no_std)]
#![recursion_limit = "256"]

#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

pub mod opaque {
	pub use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;

	// --- darwinia ---
	use crate::*;

	pub type Header = generic::Header<BlockNumber, Hashing>;
	pub type Block = generic::Block<Header, UncheckedExtrinsic>;
	pub type BlockId = generic::BlockId<Block>;
}

pub mod impls {
	pub use darwinia_balances::{Instance1 as RingInstance, Instance2 as KtonInstance};

	// --- substrate ---
	use sp_runtime::RuntimeDebug;
	// --- darwinia ---
	use crate::*;

	darwinia_support::impl_account_data! {
		struct AccountData<Balance>
		for
			RingInstance,
			KtonInstance
		where
			Balance = Balance
		{
			// other data
		}
	}
}
pub use impls::*;

// <--- pangolin
pub mod pangolin_messages;
use pangolin_messages::{
	PangolinCallToPayload, ToPangolinMessagePayload, WithPangolinMessageBridge,
};
// pangolin --->

pub use darwinia_balances::Call as BalancesCall;
use darwinia_relay_primitives::RelayAccount;
use darwinia_s2s_relay::MessageRelayCall;
use dp_asset::{token::Token, BridgedAssetReceiver};
pub use frame_system::Call as SystemCall;
pub use pallet_bridge_grandpa::Call as BridgeGrandpaCall;
pub use pallet_bridge_messages::Call as BridgeMessagesCall;
use pallet_bridge_messages::Instance1 as Pangolin;
pub use pallet_sudo::Call as SudoCall;
use sp_core::H160;

// --- crates.io ---
use codec::{Decode, Encode};
// --- substrate ---
use bridge_runtime_common::messages::{
	source::estimate_message_dispatch_and_delivery_fee, MessageBridge,
};
use frame_support::{
	construct_runtime, parameter_types,
	traits::KeyOwnerProofSystem,
	weights::{IdentityFee, RuntimeDbWeight, Weight},
	PalletId,
};
use pallet_grandpa::{
	fg_primitives, AuthorityId as GrandpaId, AuthorityList as GrandpaAuthorityList,
};
use pallet_transaction_payment::{FeeDetails, RuntimeDispatchInfo};
use sp_api::impl_runtime_apis;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_core::{crypto::KeyTypeId, OpaqueMetadata};
use sp_runtime::{
	create_runtime_str, generic, impl_opaque_keys,
	traits::{Block as BlockT, IdentityLookup, NumberFor, OpaqueKeys},
	transaction_validity::{TransactionSource, TransactionValidity},
	ApplyExtrinsicResult, MultiSignature, MultiSigner,
};
use sp_std::prelude::*;
#[cfg(feature = "std")]
use sp_version::NativeVersion;
use sp_version::RuntimeVersion;

pub type BlockNumber = bp_millau::BlockNumber;
pub type Signature = bp_millau::Signature;
pub type AccountId = bp_millau::AccountId;
pub type AccountIndex = u32;
pub type Balance = bp_millau::Balance;
pub type Index = u32;
pub type Hash = bp_millau::Hash;
pub type Hashing = bp_millau::Hasher;
pub type DigestItem = generic::DigestItem<Hash>;

pub type Address = AccountId;
pub type Header = generic::Header<BlockNumber, Hashing>;
pub type Block = generic::Block<Header, UncheckedExtrinsic>;
pub type SignedBlock = generic::SignedBlock<Block>;
pub type BlockId = generic::BlockId<Block>;
pub type SignedExtra = (
	frame_system::CheckSpecVersion<Runtime>,
	frame_system::CheckTxVersion<Runtime>,
	frame_system::CheckGenesis<Runtime>,
	frame_system::CheckEra<Runtime>,
	frame_system::CheckNonce<Runtime>,
	frame_system::CheckWeight<Runtime>,
	pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
);
pub type SignedPayload = generic::SignedPayload<Call, SignedExtra>;
pub type UncheckedExtrinsic = generic::UncheckedExtrinsic<Address, Call, Signature, SignedExtra>;
pub type CheckedExtrinsic = generic::CheckedExtrinsic<AccountId, Call, SignedExtra>;
pub type Executive = frame_executive::Executive<
	Runtime,
	Block,
	frame_system::ChainContext<Runtime>,
	Runtime,
	AllPallets,
>;

pub type Ring = Balances;

pub const VERSION: RuntimeVersion = RuntimeVersion {
	spec_name: create_runtime_str!("millau-runtime"),
	impl_name: create_runtime_str!("millau-runtime"),
	authoring_version: 1,
	spec_version: 1,
	impl_version: 1,
	apis: RUNTIME_API_VERSIONS,
	transaction_version: 1,
};

#[cfg(feature = "std")]
pub fn native_version() -> NativeVersion {
	NativeVersion {
		runtime_version: VERSION,
		can_author_with: Default::default(),
	}
}

parameter_types! {
	pub const BlockHashCount: BlockNumber = 250;
	pub const Version: RuntimeVersion = VERSION;
	pub const DbWeight: RuntimeDbWeight = RuntimeDbWeight {
		read: 60_000_000,
		write: 200_000_000,
	};
	pub const SS58Prefix: u8 = 60;
}
impl frame_system::Config for Runtime {
	type BaseCallFilter = ();
	type AccountId = AccountId;
	type Call = Call;
	type Lookup = IdentityLookup<AccountId>;
	type Index = Index;
	type BlockNumber = BlockNumber;
	type Hash = Hash;
	type Hashing = Hashing;
	type Header = generic::Header<BlockNumber, Hashing>;
	type Event = Event;
	type Origin = Origin;
	type BlockHashCount = BlockHashCount;
	type Version = Version;
	type PalletInfo = PalletInfo;
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type AccountData = AccountData<Balance>;
	type SystemWeightInfo = ();
	type BlockWeights = bp_millau::BlockWeights;
	type BlockLength = bp_millau::BlockLength;
	type DbWeight = DbWeight;
	type SS58Prefix = SS58Prefix;
	type OnSetCode = ();
}

impl pallet_aura::Config for Runtime {
	type AuthorityId = AuraId;
}

parameter_types! {
	pub const MinimumPeriod: u64 = bp_millau::SLOT_DURATION / 2;
}
impl pallet_timestamp::Config for Runtime {
	type Moment = u64;
	type OnTimestampSet = Aura;
	type MinimumPeriod = MinimumPeriod;
	type WeightInfo = ();
}

parameter_types! {
	pub const ExistentialDeposit: bp_millau::Balance = 500;
	pub const MaxLocks: u32 = 50;
}
impl darwinia_balances::Config<RingInstance> for Runtime {
	type Balance = Balance;
	type DustRemoval = ();
	type Event = Event;
	type ExistentialDeposit = ExistentialDeposit;
	type BalanceInfo = AccountData<Balance>;
	type AccountStore = System;
	type MaxLocks = MaxLocks;
	type OtherCurrencies = (Kton,);
	type WeightInfo = ();
}
impl darwinia_balances::Config<KtonInstance> for Runtime {
	type Balance = Balance;
	type DustRemoval = ();
	type Event = Event;
	type ExistentialDeposit = ExistentialDeposit;
	type BalanceInfo = AccountData<Balance>;
	type AccountStore = System;
	type MaxLocks = MaxLocks;
	type OtherCurrencies = (Ring,);
	type WeightInfo = ();
}

parameter_types! {
	pub const TransactionBaseFee: Balance = 0;
	pub const TransactionByteFee: Balance = 1;
}
impl pallet_transaction_payment::Config for Runtime {
	type OnChargeTransaction = pallet_transaction_payment::CurrencyAdapter<Balances, ()>;
	type TransactionByteFee = TransactionByteFee;
	type WeightToFee = IdentityFee<Balance>;
	type FeeMultiplierUpdate = ();
}

impl_opaque_keys! {
	pub struct SessionKeys {
		pub aura: Aura,
		pub grandpa: Grandpa,
	}
}
parameter_types! {
	pub const Period: BlockNumber = bp_millau::SESSION_LENGTH;
	pub const Offset: BlockNumber = 0;
}
impl pallet_session::Config for Runtime {
	type Event = Event;
	type ValidatorId = <Self as frame_system::Config>::AccountId;
	type ValidatorIdOf = ();
	type ShouldEndSession = pallet_session::PeriodicSessions<Period, Offset>;
	type NextSessionRotation = pallet_session::PeriodicSessions<Period, Offset>;
	type SessionManager = pallet_shift_session_manager::Pallet<Runtime>;
	type SessionHandler = <SessionKeys as OpaqueKeys>::KeyTypeIdProviders;
	type Keys = SessionKeys;
	type DisabledValidatorsThreshold = ();
	type WeightInfo = ();
}

impl pallet_grandpa::Config for Runtime {
	type Event = Event;
	type Call = Call;
	type KeyOwnerProofSystem = ();
	type KeyOwnerProof =
		<Self::KeyOwnerProofSystem as KeyOwnerProofSystem<(KeyTypeId, GrandpaId)>>::Proof;
	type KeyOwnerIdentification = <Self::KeyOwnerProofSystem as KeyOwnerProofSystem<(
		KeyTypeId,
		GrandpaId,
	)>>::IdentificationTuple;
	type HandleEquivocation = ();
	type WeightInfo = ();
}

impl pallet_sudo::Config for Runtime {
	type Event = Event;
	type Call = Call;
}

// <--- pangolin
parameter_types! {
	pub const MaxMessagesToPruneAtOnce: bp_messages::MessageNonce = 8;
	pub const MaxUnrewardedRelayerEntriesAtInboundLane: bp_messages::MessageNonce =
		bp_millau::MAX_UNREWARDED_RELAYER_ENTRIES_AT_INBOUND_LANE;
	pub const MaxUnconfirmedMessagesAtInboundLane: bp_messages::MessageNonce =
		bp_millau::MAX_UNCONFIRMED_MESSAGES_AT_INBOUND_LANE;
	// `IdentityFee` is used by Millau => we may use weight directly
	pub const GetDeliveryConfirmationTransactionFee: Balance =
		bp_millau::MAX_SINGLE_MESSAGE_DELIVERY_CONFIRMATION_TX_WEIGHT as _;
	pub const RootAccountForPayments: Option<AccountId> = None;
}
pub type WithPangolinMessages = pallet_bridge_messages::Instance1;
impl pallet_bridge_messages::Config<WithPangolinMessages> for Runtime {
	type Event = Event;
	// FIXME
	type WeightInfo = pallet_bridge_messages::weights::RialtoWeight<Runtime>;
	type Parameter = pangolin_messages::MillauToPangolinMessagesParameter;
	type MaxMessagesToPruneAtOnce = MaxMessagesToPruneAtOnce;
	type MaxUnrewardedRelayerEntriesAtInboundLane = MaxUnrewardedRelayerEntriesAtInboundLane;
	type MaxUnconfirmedMessagesAtInboundLane = MaxUnconfirmedMessagesAtInboundLane;

	type OutboundPayload = pangolin_messages::ToPangolinMessagePayload;
	type OutboundMessageFee = Balance;

	type InboundPayload = pangolin_messages::FromPangolinMessagePayload;
	type InboundMessageFee = drml_primitives::Balance;
	type InboundRelayer = drml_primitives::AccountId;

	type AccountIdConverter = pangolin_bridge_primitives::AccountIdConverter;

	type TargetHeaderChain = pangolin_messages::Pangolin;
	type LaneMessageVerifier = pangolin_messages::ToPangolinMessageVerifier;
	type MessageDeliveryAndDispatchPayment =
		pallet_bridge_messages::instant_payments::InstantCurrencyPayments<
			Runtime,
			darwinia_balances::Pallet<Runtime, RingInstance>,
			GetDeliveryConfirmationTransactionFee,
			RootAccountForPayments,
		>;

	type SourceHeaderChain = pangolin_messages::Pangolin;
	type MessageDispatch = pangolin_messages::FromPangolinMessageDispatch;
}

pub type WithPangolinDispatch = pallet_bridge_dispatch::Instance1;
impl pallet_bridge_dispatch::Config<WithPangolinDispatch> for Runtime {
	type Event = Event;
	type MessageId = (bp_messages::LaneId, bp_messages::MessageNonce);
	type Call = Call;
	type CallFilter = ();
	type EncodedCall = pangolin_messages::FromPangolinEncodedCall;
	type SourceChainAccountId = drml_primitives::AccountId;
	type TargetChainAccountPublic = MultiSigner;
	type TargetChainSignature = MultiSignature;
	type AccountIdConverter = bp_millau::AccountIdConverter;
}

parameter_types! {
	// This is a pretty unscientific cap.
	//
	// Note that once this is hit the pallet will essentially throttle incoming requests down to one
	// call per block.
	pub const MaxRequests: u32 = 50;
	// Number of headers to keep.
	//
	// Assuming the worst case of every header being finalized, we will keep headers for at least a
	// week.
	pub const HeadersToKeep: u32 = 7 * bp_millau::DAYS as u32;
}
pub type WithPangolinGrandpa = pallet_bridge_grandpa::Instance1;
impl pallet_bridge_grandpa::Config<WithPangolinGrandpa> for Runtime {
	type BridgedChain = pangolin_bridge_primitives::Pangolin;
	type MaxRequests = MaxRequests;
	type HeadersToKeep = HeadersToKeep;
	// FIXME
	type WeightInfo = pallet_bridge_grandpa::weights::RialtoWeight<Runtime>;
}
// pangolin --->

impl pallet_shift_session_manager::Config for Runtime {}

construct_runtime!(
	pub enum Runtime where
		Block = Block,
		NodeBlock = opaque::Block,
		UncheckedExtrinsic = UncheckedExtrinsic
	{
		System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
		RandomnessCollectiveFlip: pallet_randomness_collective_flip::{Pallet, Call, Storage},

		Aura: pallet_aura::{Pallet, Config<T>},
		Timestamp: pallet_timestamp::{Pallet, Call, Storage, Inherent},
		Balances: darwinia_balances::<Instance1>::{Pallet, Call, Storage, Config<T>, Event<T>},
		Kton: darwinia_balances::<Instance2>::{Pallet, Call, Storage, Config<T>, Event<T>},
		TransactionPayment: pallet_transaction_payment::{Pallet, Storage},

		Session: pallet_session::{Pallet, Call, Storage, Event, Config<T>},
		Grandpa: pallet_grandpa::{Pallet, Call, Storage, Config, Event},

		Sudo: pallet_sudo::{Pallet, Call, Config<T>, Storage, Event<T>},

		// <--- pangolin
		BridgePangolinMessages: pallet_bridge_messages::<Instance1>::{Pallet, Call, Storage, Event<T>},
		BridgePangolinDispatch: pallet_bridge_dispatch::<Instance1>::{Pallet, Event<T>},
		BridgePangolinGrandpa: pallet_bridge_grandpa::<Instance1>::{Pallet, Call, Storage},
		// pangolin --->
		ShiftSessionManager: pallet_shift_session_manager::{Pallet},

		Substrate2SubstrateRelay: darwinia_s2s_relay::<Instance1>::{Pallet, Call, Storage, Config<T>, Event<T>},
		Substrate2SubstrateBacking: darwinia_s2s_backing::{Pallet, Call, Storage, Config<T>, Event<T>},
	}
);

// backing used
parameter_types! {
	pub const S2sRelayPalletId: PalletId = PalletId(*b"da/s2sre");
	pub const PangolinChainId: bp_runtime::ChainId = pangolin_bridge_primitives::PANGOLIN_CHAIN_ID;
}

pub struct ToPangolinMessageRelayCall;
impl MessageRelayCall<ToPangolinMessagePayload, Call> for ToPangolinMessageRelayCall {
	fn encode_call(payload: ToPangolinMessagePayload) -> Call {
		return BridgeMessagesCall::<Runtime, Pangolin>::send_message([0; 4], payload, 0u64.into())
			.into();
	}
}

// remote chain millau's dispatch info
#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub enum PangolinRuntime {
	/// s2s bridge backing pallet.
	/// this index must be the same as the backing pallet in millau runtime
	#[codec(index = 49)]
	Sub2SubIssing(PangolinSub2SubIssuingCall),
}

#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone)]
#[allow(non_camel_case_types)]
pub enum PangolinSub2SubIssuingCall {
	#[codec(index = 0)]
	cross_receive_and_issue((Token, H160)),
}

pub struct PangolinIssuingReceiver;
impl BridgedAssetReceiver<RelayAccount<AccountId>> for PangolinIssuingReceiver {
	fn encode_call(token: Token, recipient: RelayAccount<AccountId>) -> Result<Vec<u8>, ()> {
		match recipient {
			RelayAccount::<AccountId>::EthereumAccount(r) => {
				return Ok(PangolinRuntime::Sub2SubIssing(
					PangolinSub2SubIssuingCall::cross_receive_and_issue((token, r)),
				)
				.encode())
			}
			_ => Err(()),
		}
	}
}

impl darwinia_s2s_relay::Config<darwinia_s2s_relay::Instance1> for Runtime {
	type PalletId = S2sRelayPalletId;
	type Event = Event;
	type WeightInfo = ();
	type BridgedChainId = PangolinChainId;
	type OutboundPayload = ToPangolinMessagePayload;
	type OutboundMessageFee = Balance;
	type CallToPayload = PangolinCallToPayload;
	type BridgedAssetReceiverT = PangolinIssuingReceiver;
	type BridgedAccountIdConverter = pangolin_bridge_primitives::AccountIdConverter;
	type ToEthAddressT = darwinia_s2s_relay::TruncateToEthAddress;
	type MessageRelayCallT = ToPangolinMessageRelayCall;
}

parameter_types! {
	pub const S2sBackingPalletId: PalletId = PalletId(*b"da/s2sba");
	pub const S2sBackingFeePalletId: PalletId = PalletId(*b"da/s2sbf");
	pub const RingLockLimit: Balance = 10_000_000 * 1_000_000_000;
	pub const AdvancedFee: Balance = 50 * 1_000_000_000;
}

impl darwinia_s2s_backing::Config for Runtime {
	type PalletId = S2sBackingPalletId;
	type Event = Event;
	type WeightInfo = ();
	type FeePalletId = S2sBackingFeePalletId;
	type IssuingRelay = Substrate2SubstrateRelay;
	type RingLockMaxLimit = RingLockLimit;
	type AdvancedFee = AdvancedFee;
	type RingCurrency = Ring;
}
//----- s2s backing used ---------

impl_runtime_apis! {
	impl sp_api::Core<Block> for Runtime {
		fn version() -> RuntimeVersion {
			VERSION
		}

		fn execute_block(block: Block) {
			Executive::execute_block(block);
		}

		fn initialize_block(header: &<Block as BlockT>::Header) {
			Executive::initialize_block(header)
		}
	}

	impl sp_api::Metadata<Block> for Runtime {
		fn metadata() -> OpaqueMetadata {
			Runtime::metadata().into()
		}
	}

	impl sp_block_builder::BlockBuilder<Block> for Runtime {
		fn apply_extrinsic(extrinsic: <Block as BlockT>::Extrinsic) -> ApplyExtrinsicResult {
			Executive::apply_extrinsic(extrinsic)
		}

		fn finalize_block() -> <Block as BlockT>::Header {
			Executive::finalize_block()
		}

		fn inherent_extrinsics(data: sp_inherents::InherentData) -> Vec<<Block as BlockT>::Extrinsic> {
			data.create_extrinsics()
		}

		fn check_inherents(
			block: Block,
			data: sp_inherents::InherentData,
		) -> sp_inherents::CheckInherentsResult {
			data.check_extrinsics(&block)
		}
	}

	impl frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId, Index> for Runtime {
		fn account_nonce(account: AccountId) -> Index {
			System::account_nonce(account)
		}
	}

	impl sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block> for Runtime {
		fn validate_transaction(
			source: TransactionSource,
			tx: <Block as BlockT>::Extrinsic,
		) -> TransactionValidity {
			Executive::validate_transaction(source, tx)
		}
	}

	impl sp_offchain::OffchainWorkerApi<Block> for Runtime {
		fn offchain_worker(header: &<Block as BlockT>::Header) {
			Executive::offchain_worker(header)
		}
	}

	impl sp_consensus_aura::AuraApi<Block, AuraId> for Runtime {
		fn slot_duration() -> sp_consensus_aura::SlotDuration {
			sp_consensus_aura::SlotDuration::from_millis(Aura::slot_duration())
		}

		fn authorities() -> Vec<AuraId> {
			Aura::authorities()
		}
	}

	impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<
		Block,
		Balance,
	> for Runtime {
		fn query_info(uxt: <Block as BlockT>::Extrinsic, len: u32) -> RuntimeDispatchInfo<Balance> {
			TransactionPayment::query_info(uxt, len)
		}
		fn query_fee_details(uxt: <Block as BlockT>::Extrinsic, len: u32) -> FeeDetails<Balance> {
			TransactionPayment::query_fee_details(uxt, len)
		}
	}

	impl sp_session::SessionKeys<Block> for Runtime {
		fn generate_session_keys(seed: Option<Vec<u8>>) -> Vec<u8> {
			SessionKeys::generate(seed)
		}

		fn decode_session_keys(
			encoded: Vec<u8>,
		) -> Option<Vec<(Vec<u8>, sp_core::crypto::KeyTypeId)>> {
			SessionKeys::decode_into_raw_public_keys(&encoded)
		}
	}

	impl fg_primitives::GrandpaApi<Block> for Runtime {
		fn grandpa_authorities() -> GrandpaAuthorityList {
			Grandpa::grandpa_authorities()
		}

		fn submit_report_equivocation_unsigned_extrinsic(
			equivocation_proof: fg_primitives::EquivocationProof<
				<Block as BlockT>::Hash,
				NumberFor<Block>,
			>,
			key_owner_proof: fg_primitives::OpaqueKeyOwnershipProof,
		) -> Option<()> {
			let key_owner_proof = key_owner_proof.decode()?;

			Grandpa::submit_unsigned_equivocation_report(
				equivocation_proof,
				key_owner_proof,
			)
		}

		fn generate_key_ownership_proof(
			_set_id: fg_primitives::SetId,
			_authority_id: GrandpaId,
		) -> Option<fg_primitives::OpaqueKeyOwnershipProof> {
			// NOTE: this is the only implementation possible since we've
			// defined our key owner proof type as a bottom type (i.e. a type
			// with no values).
			None
		}
	}

	// <--- pangolin
	impl pangolin_bridge_primitives::PangolinFinalityApi<Block> for Runtime {
		fn best_finalized() -> (drml_primitives::BlockNumber, drml_primitives::Hash) {
			let header = BridgePangolinGrandpa::best_finalized();
			(header.number, header.hash())
		}

		fn is_known_header(hash: drml_primitives::Hash) -> bool {
			BridgePangolinGrandpa::is_known_header(hash)
		}
	}

	impl pangolin_bridge_primitives::ToPangolinOutboundLaneApi<Block, Balance, ToPangolinMessagePayload> for Runtime {
		fn estimate_message_delivery_and_dispatch_fee(
			_lane_id: bp_messages::LaneId,
			payload: ToPangolinMessagePayload,
		) -> Option<Balance> {
			estimate_message_dispatch_and_delivery_fee::<WithPangolinMessageBridge>(
				&payload,
				WithPangolinMessageBridge::RELAYER_FEE_PERCENT,
			).ok()
		}

		fn messages_dispatch_weight(
			lane: bp_messages::LaneId,
			begin: bp_messages::MessageNonce,
			end: bp_messages::MessageNonce,
		) -> Vec<(bp_messages::MessageNonce, Weight, u32)> {
			(begin..=end).filter_map(|nonce| {
				let encoded_payload = BridgePangolinMessages::outbound_message_payload(lane, nonce)?;
				let decoded_payload = pangolin_messages::ToPangolinMessagePayload::decode(
					&mut &encoded_payload[..]
				).ok()?;
				Some((nonce, decoded_payload.weight, encoded_payload.len() as _))
			})
			.collect()
		}

		fn latest_received_nonce(lane: bp_messages::LaneId) -> bp_messages::MessageNonce {
			BridgePangolinMessages::outbound_latest_received_nonce(lane)
		}

		fn latest_generated_nonce(lane: bp_messages::LaneId) -> bp_messages::MessageNonce {
			BridgePangolinMessages::outbound_latest_generated_nonce(lane)
		}
	}

	impl pangolin_bridge_primitives::FromPangolinInboundLaneApi<Block> for Runtime {
		fn latest_received_nonce(lane: bp_messages::LaneId) -> bp_messages::MessageNonce {
			BridgePangolinMessages::inbound_latest_received_nonce(lane)
		}

		fn latest_confirmed_nonce(lane: bp_messages::LaneId) -> bp_messages::MessageNonce {
			BridgePangolinMessages::inbound_latest_confirmed_nonce(lane)
		}

		fn unrewarded_relayers_state(lane: bp_messages::LaneId) -> bp_messages::UnrewardedRelayersState {
			BridgePangolinMessages::inbound_unrewarded_relayers_state(lane)
		}
	}
	// pangolin --->
}

// <--- pangolin
/// Pangolin account ownership digest from Millau.
///
/// The byte vector returned by this function should be signed with a Pangolin account private key.
/// This way, the owner of `millau_account_id` on Millau proves that the Pangolin account private key
/// is also under his control.
pub fn millau_to_pangolin_account_ownership_digest<Call, AccountId, SpecVersion>(
	pangolin_call: &Call,
	millau_account_id: AccountId,
	pangolin_spec_version: SpecVersion,
) -> sp_std::vec::Vec<u8>
where
	Call: Encode,
	AccountId: Encode,
	SpecVersion: Encode,
{
	pallet_bridge_dispatch::account_ownership_digest(
		pangolin_call,
		millau_account_id,
		pangolin_spec_version,
		bp_runtime::MILLAU_CHAIN_ID,
		pangolin_bridge_primitives::PANGOLIN_CHAIN_ID,
	)
}
// pangolin --->
