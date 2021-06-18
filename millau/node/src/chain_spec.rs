// --- substrate ---
use bp_runtime::SourceAccount;
use millau_runtime::*;
use pangolin_bridge_primitives::AccountIdConverter;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_core::{sr25519, Pair, Public};
use sp_finality_grandpa::AuthorityId as GrandpaId;
use sp_runtime::traits::{Convert, IdentifyAccount};

pub type ChainSpec = sc_service::GenericChainSpec<GenesisConfig>;

type AccountPublic = bp_millau::AccountSigner;

#[derive(Clone, Debug)]
pub enum Alternative {
	Development,
	LocalTestnet,
}
impl Alternative {
	pub(crate) fn load(self) -> ChainSpec {
		let properties = Some(
			serde_json::json!({
				"tokenDecimals": 9,
				"tokenSymbol": "MLAU",
				"bridgeIds": {
					"Pangolin": pangolin_bridge_primitives::PANGOLIN_CHAIN_ID,
				}
			})
			.as_object()
			.expect("Map given; qed")
			.clone(),
		);
		match self {
			Alternative::Development => ChainSpec::from_genesis(
				"Development",
				"dev",
				sc_service::ChainType::Development,
				|| {
					testnet_genesis(
						vec![get_authority_keys_from_seed("Alice")],
						get_account_id_from_seed::<sr25519::Public>("Alice"),
						vec![
							get_account_id_from_seed::<sr25519::Public>("Alice"),
							get_account_id_from_seed::<sr25519::Public>("Bob"),
							get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
							get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
							derive_account_from_pangolin_id(SourceAccount::Account(
								get_account_id_from_seed::<sr25519::Public>("Alice"),
							)),
						],
						true,
					)
				},
				vec![],
				None,
				None,
				properties,
				None,
			),
			Alternative::LocalTestnet => ChainSpec::from_genesis(
				"Local Testnet",
				"local_testnet",
				sc_service::ChainType::Local,
				|| {
					testnet_genesis(
						vec![
							get_authority_keys_from_seed("Alice"),
							get_authority_keys_from_seed("Bob"),
							get_authority_keys_from_seed("Charlie"),
							get_authority_keys_from_seed("Dave"),
							get_authority_keys_from_seed("Eve"),
						],
						get_account_id_from_seed::<sr25519::Public>("Alice"),
						vec![
							get_account_id_from_seed::<sr25519::Public>("Alice"),
							get_account_id_from_seed::<sr25519::Public>("Bob"),
							get_account_id_from_seed::<sr25519::Public>("Charlie"),
							get_account_id_from_seed::<sr25519::Public>("Dave"),
							get_account_id_from_seed::<sr25519::Public>("Eve"),
							get_account_id_from_seed::<sr25519::Public>("Ferdie"),
							get_account_id_from_seed::<sr25519::Public>("George"),
							get_account_id_from_seed::<sr25519::Public>("Harry"),
							get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
							get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
							get_account_id_from_seed::<sr25519::Public>("Charlie//stash"),
							get_account_id_from_seed::<sr25519::Public>("Dave//stash"),
							get_account_id_from_seed::<sr25519::Public>("Eve//stash"),
							get_account_id_from_seed::<sr25519::Public>("Ferdie//stash"),
							get_account_id_from_seed::<sr25519::Public>("George//stash"),
							get_account_id_from_seed::<sr25519::Public>("Harry//stash"),
							pallet_bridge_messages::Pallet::<
								millau_runtime::Runtime,
								pallet_bridge_messages::Instance1,
							>::relayer_fund_account_id(),
							derive_account_from_pangolin_id(SourceAccount::Account(
								get_account_id_from_seed::<sr25519::Public>("Alice"),
							)),
							derive_account_from_pangolin_id(SourceAccount::Account(
								get_account_id_from_seed::<sr25519::Public>("Charlie"),
							)),
							derive_account_from_pangolin_id(SourceAccount::Account(
								get_account_id_from_seed::<sr25519::Public>("Eve"),
							)),
						],
						true,
					)
				},
				vec![],
				None,
				None,
				properties,
				None,
			),
		}
	}
}

fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
	TPublic::Pair::from_string(&format!("//{}", seed), None)
		.expect("static values are valid; qed")
		.public()
}

fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
	AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
	AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

fn get_authority_keys_from_seed(s: &str) -> (AccountId, AuraId, GrandpaId) {
	(
		get_account_id_from_seed::<sr25519::Public>(s),
		get_from_seed::<AuraId>(s),
		get_from_seed::<GrandpaId>(s),
	)
}

/// We use this to get the account on Millau (target) which is derived from Pangolin's (source)
/// account. We do this so we can fund the derived account on Millau at Genesis to it can pay
/// transaction fees.
///
/// The reason we can use the same `AccountId` type for both chains is because they share the same
/// development seed phrase.
///
/// Note that this should only be used for testing.
pub fn derive_account_from_pangolin_id(id: bp_runtime::SourceAccount<AccountId>) -> AccountId {
	let encoded_id =
		bp_runtime::derive_account_id(pangolin_bridge_primitives::PANGOLIN_CHAIN_ID, id);
	AccountIdConverter::convert(encoded_id)
}

fn session_keys(aura: AuraId, grandpa: GrandpaId) -> SessionKeys {
	SessionKeys { aura, grandpa }
}

fn testnet_genesis(
	initial_authorities: Vec<(AccountId, AuraId, GrandpaId)>,
	root_key: AccountId,
	endowed_accounts: Vec<AccountId>,
	_enable_println: bool,
) -> GenesisConfig {
	GenesisConfig {
		frame_system: SystemConfig {
			code: WASM_BINARY
				.expect("Millau development WASM not available")
				.to_vec(),
			changes_trie_config: Default::default(),
		},
		darwinia_balances_Instance1: BalancesConfig {
			balances: endowed_accounts
				.iter()
				.cloned()
				.map(|k| (k, 1 << 50))
				.collect(),
		},
		darwinia_balances_Instance2: KtonConfig {
			balances: endowed_accounts
				.iter()
				.cloned()
				.map(|k| (k, 1 << 50))
				.collect(),
		},
		darwinia_s2s_backing: Default::default(),
		pallet_aura: AuraConfig {
			authorities: Vec::new(),
		},
		pallet_grandpa: GrandpaConfig {
			authorities: Vec::new(),
		},
		pallet_sudo: SudoConfig { key: root_key },
		pallet_session: SessionConfig {
			keys: initial_authorities
				.iter()
				.map(|x| {
					(
						x.0.clone(),
						x.0.clone(),
						session_keys(x.1.clone(), x.2.clone()),
					)
				})
				.collect::<Vec<_>>(),
		},
	}
}
