// Copyright 2020 The Grin Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Public types for config modules

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::path::PathBuf;
use std::str::FromStr;

use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use crate::core::global::{self, ChainTypes, DEFAULT_FUTURE_TIME_LIMIT};
use crate::core::ser;
use crate::core::ser::Readable;
use crate::core::ser::Reader;
use crate::core::ser::Writeable;
use crate::core::ser::Writer;
use crate::core::ser_multiwrite;
use crate::core::try_iter_map_vec;
use crate::pool;
use crate::util::logger::LoggingConfig;
use crate::{Error, ErrorKind};

/// Maximum number of block headers a peer should ever send
pub const MAX_BLOCK_HEADERS: u32 = 512;

/// Maximum number of block bodies a peer should ever ask for and send
#[allow(dead_code)]
pub const MAX_BLOCK_BODIES: u32 = 16;

/// Maximum number of peer addresses a peer should ever send
pub const MAX_PEER_ADDRS: u32 = 256;

/// Maximum number of block header hashes to send as part of a locator
pub const MAX_LOCATORS: u32 = 20;

/// How long a banned peer should be banned for
const BAN_WINDOW: i64 = 10800;

/// The max inbound peer count
const PEER_MAX_INBOUND_COUNT: u32 = 128;

/// The max outbound peer count
const PEER_MAX_OUTBOUND_COUNT: u32 = 8;

/// The min preferred outbound peer count
const PEER_MIN_PREFERRED_OUTBOUND_COUNT: u32 = 8;

/// The peer listener buffer count. Allows temporarily accepting more connections
/// than allowed by PEER_MAX_INBOUND_COUNT to encourage network bootstrapping.
const PEER_LISTENER_BUFFER_COUNT: u32 = 8;

/// The enum that holds the connection info for this Peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PeerAddr {
	/// An IP based PeerAddr
	Ip(SocketAddr),
	/// An onion based Address
	Onion(String),
}

impl Writeable for PeerAddr {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		match self {
			PeerAddr::Ip(ip) => match ip {
				SocketAddr::V4(sav4) => {
					ser_multiwrite!(
						writer,
						[write_u8, 0],
						[write_fixed_bytes, &sav4.ip().octets().to_vec()],
						[write_u16, sav4.port()]
					);
				}
				SocketAddr::V6(sav6) => {
					writer.write_u8(1)?;
					for seg in &sav6.ip().segments() {
						writer.write_u16(*seg)?;
					}
					writer.write_u16(sav6.port())?;
				}
			},
			PeerAddr::Onion(onion) => {
				if onion.len() > 100 {
					return Err(ser::Error::TooLargeWriteErr);
				}
				writer.write_u8(2)?;
				writer.write_bytes(onion)?;
			}
		}
		Ok(())
	}
}

impl Readable for PeerAddr {
	fn read<R: Reader>(reader: &mut R) -> Result<PeerAddr, ser::Error> {
		let v4_or_v6 = reader.read_u8()?;
		if v4_or_v6 == 0 {
			let ip = reader.read_fixed_bytes(4)?;
			let port = reader.read_u16()?;
			Ok(PeerAddr::Ip(SocketAddr::V4(SocketAddrV4::new(
				Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]),
				port,
			))))
		} else if v4_or_v6 == 1 {
			let ip = try_iter_map_vec!(0..8, |_| reader.read_u16());
			let ipv6 = Ipv6Addr::new(ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7]);
			let port = reader.read_u16()?;
			if let Some(ipv4) = ipv6.to_ipv4() {
				Ok(PeerAddr::Ip(SocketAddr::V4(SocketAddrV4::new(ipv4, port))))
			} else {
				Ok(PeerAddr::Ip(SocketAddr::V6(SocketAddrV6::new(
					ipv6, port, 0, 0,
				))))
			}
		} else {
			// '2' is used for onion addresses now
			let oa = reader.read_bytes_len_prefix()?;
			let onion_address = String::from_utf8(oa).unwrap_or("".to_string());
			Ok(PeerAddr::Onion(onion_address))
		}
	}
}

impl<'de> Visitor<'de> for PeerAddrs {
	type Value = PeerAddrs;

	fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
		formatter.write_str("an array of dns names or IP addresses")
	}

	fn visit_seq<M>(self, mut access: M) -> Result<Self::Value, M::Error>
	where
		M: SeqAccess<'de>,
	{
		let mut peers = Vec::with_capacity(access.size_hint().unwrap_or(0));

		while let Some(entry) = access.next_element::<&str>()? {
			// There is Onion addresses, we need to handle them
			peers.push(PeerAddr::from_str(entry));
		}
		Ok(PeerAddrs { peers })
	}
}

impl<'de> Deserialize<'de> for PeerAddrs {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		deserializer.deserialize_seq(PeerAddrs { peers: vec![] })
	}
}

impl std::hash::Hash for PeerAddr {
	/// If loopback address then we care about ip and port.
	/// If regular address then we only care about the ip and ignore the port.
	fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
		match self {
			PeerAddr::Ip(ip) => {
				if ip.ip().is_loopback() {
					ip.hash(state);
				} else {
					ip.ip().hash(state);
				}
			}
			PeerAddr::Onion(onion) => {
				onion.hash(state);
			}
		}
	}
}

impl PartialEq for PeerAddr {
	/// If loopback address then we care about ip and port.
	/// If regular address then we only care about the ip and ignore the port.
	fn eq(&self, other: &PeerAddr) -> bool {
		match self {
			PeerAddr::Ip(ip) => match other {
				PeerAddr::Ip(other_ip) => {
					if ip.ip().is_loopback() {
						ip == other_ip
					} else {
						ip.ip() == other_ip.ip()
					}
				}
				_ => false,
			},
			PeerAddr::Onion(onion) => match other {
				PeerAddr::Onion(other_onion) => onion == other_onion,
				_ => false,
			},
		}
	}
}

impl Eq for PeerAddr {}

/// Peer addresses we know of that are fresh enough, in response to
/// GetPeerAddrs.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PeerAddrs {
	/// The vector of peers that are known to this node
	pub peers: Vec<PeerAddr>,
}

impl Writeable for PeerAddrs {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u32(self.peers.len() as u32)?;
		for p in &self.peers {
			p.write(writer)?;
		}
		Ok(())
	}
}

impl Readable for PeerAddrs {
	fn read<R: Reader>(reader: &mut R) -> Result<PeerAddrs, ser::Error> {
		let peer_count = reader.read_u32()?;
		if peer_count > MAX_PEER_ADDRS {
			return Err(ser::Error::TooLargeReadErr);
		} else if peer_count == 0 {
			return Ok(PeerAddrs { peers: vec![] });
		}
		let mut peers = Vec::with_capacity(peer_count as usize);
		for _ in 0..peer_count {
			peers.push(PeerAddr::read(reader)?);
		}
		Ok(PeerAddrs { peers })
	}
}

impl std::fmt::Display for PeerAddr {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match self {
			PeerAddr::Ip(ip) => write!(f, "{}", ip),
			PeerAddr::Onion(onion) => {
				let onion_address = &onion.to_string();
				write!(f, "tor://{}", onion_address)
			}
		}
	}
}

impl PeerAddr {
	/// Convenient way of constructing a new peer_addr from an ip_addr
	/// defaults to port 3414 on mainnet and 13414 on floonet.
	pub fn from_ip(addr: IpAddr) -> PeerAddr {
		let port = if global::is_testnet() { 13414 } else { 3414 };
		PeerAddr::Ip(SocketAddr::new(addr, port))
	}

	/// Convenient way of constructing a new peer_addr from a String
	pub fn from_str(addr: &str) -> PeerAddr {
		let socket_addr = SocketAddr::from_str(addr);
		if socket_addr.is_err() {
			let socket_addrs = addr.to_socket_addrs();
			if socket_addrs.is_ok() {
				let vec: Vec<SocketAddr> = socket_addrs.unwrap().collect();
				PeerAddr::Ip(vec[0])
			} else {
				PeerAddr::Onion(addr.to_string())
			}
		} else {
			PeerAddr::Ip(socket_addr.unwrap())
		}
	}

	/// If the ip is loopback then our key is "ip:port" (mainly for local usernet testing).
	/// Otherwise we only care about the ip (we disallow multiple peers on the same ip address).
	pub fn as_key(&self) -> String {
		match self {
			PeerAddr::Ip(ip) => {
				if ip.ip().is_loopback() {
					format!("{}:{}", ip.ip(), ip.port())
				} else {
					format!("{}", ip.ip())
				}
			}
			PeerAddr::Onion(onion) => format!("{}", onion),
		}
	}

	/// get the tor_pubkey for this PeerAddr
	pub fn tor_pubkey(&self) -> Result<String, Error> {
		match self {
			PeerAddr::Ip(_ip) => {
				return Err(ErrorKind::P2P("tor can't be used with IP".to_string()).into())
			}
			PeerAddr::Onion(onion) => {
				if onion.ends_with(".onion") {
					let onion = &onion[..(onion.len() - ".onion".len())];
					return Ok(onion.to_string());
				} else {
					return Ok(onion.clone());
				}
			}
		}
	}
}

/// Configuration for the peer-to-peer server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct P2PConfig {
	/// The host to bind to for the P2P network
	pub host: IpAddr,
	/// The port to bind to for the P2P network
	pub port: u16,

	/// Method used to get the list of seed nodes for initial bootstrap.
	#[serde(default)]
	pub seeding_type: Seeding,

	/// The list of seed nodes, if using Seeding as a seed type
	pub seeds: Option<PeerAddrs>,

	/// The peers to allow to connect to this node
	pub peers_allow: Option<PeerAddrs>,

	/// Peers to deny
	pub peers_deny: Option<PeerAddrs>,

	/// The list of preferred peers that we will try to connect to
	pub peers_preferred: Option<PeerAddrs>,

	/// How long to ban peers for
	pub ban_window: Option<i64>,

	/// maximum inbound peers to allow
	pub peer_max_inbound_count: Option<u32>,

	/// maximum outbound peers to allow
	pub peer_max_outbound_count: Option<u32>,

	/// the min preferred outbound count
	pub peer_min_preferred_outbound_count: Option<u32>,

	/// the peer listener buffer count
	pub peer_listener_buffer_count: Option<u32>,

	/// The dandelion peer
	pub dandelion_peer: Option<PeerAddr>,

	/// Whether to assume an external tor process is running
	pub tor_external: bool,

	/// what port to run (or expect) tor to run on
	pub tor_port: u16,

	/// the onion address to use (required for external tor)
	pub onion_address: Option<String>,
}

/// Default address for peer-to-peer connections.
impl Default for P2PConfig {
	fn default() -> P2PConfig {
		let ipaddr = "0.0.0.0".parse().unwrap();
		P2PConfig {
			host: ipaddr,
			port: 3414,
			seeding_type: Seeding::default(),
			seeds: None,
			peers_allow: None,
			peers_deny: None,
			peers_preferred: None,
			ban_window: None,
			peer_max_inbound_count: None,
			peer_max_outbound_count: None,
			peer_min_preferred_outbound_count: None,
			peer_listener_buffer_count: None,
			dandelion_peer: None,
			tor_external: false,
			tor_port: 3417,
			onion_address: None,
		}
	}
}

/// Note certain fields are options just so they don't have to be
/// included in grin-server.toml, but we don't want them to ever return none
impl P2PConfig {
	/// return ban window
	pub fn ban_window(&self) -> i64 {
		match self.ban_window {
			Some(n) => n,
			None => BAN_WINDOW,
		}
	}

	/// return maximum inbound peer connections count
	pub fn peer_max_inbound_count(&self) -> u32 {
		match self.peer_max_inbound_count {
			Some(n) => n,
			None => PEER_MAX_INBOUND_COUNT,
		}
	}

	/// return maximum outbound peer connections count
	pub fn peer_max_outbound_count(&self) -> u32 {
		match self.peer_max_outbound_count {
			Some(n) => n,
			None => PEER_MAX_OUTBOUND_COUNT,
		}
	}

	/// return minimum preferred outbound peer count
	pub fn peer_min_preferred_outbound_count(&self) -> u32 {
		match self.peer_min_preferred_outbound_count {
			Some(n) => n,
			None => PEER_MIN_PREFERRED_OUTBOUND_COUNT,
		}
	}

	/// return peer buffer count for listener
	pub fn peer_listener_buffer_count(&self) -> u32 {
		match self.peer_listener_buffer_count {
			Some(n) => n,
			None => PEER_LISTENER_BUFFER_COUNT,
		}
	}
}

/// Web hooks configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebHooksConfig {
	/// url to POST transaction data when a new transaction arrives from a peer
	pub tx_received_url: Option<String>,
	/// url to POST header data when a new header arrives from a peer
	pub header_received_url: Option<String>,
	/// url to POST block data when a new block arrives from a peer
	pub block_received_url: Option<String>,
	/// url to POST block data when a new block is accepted by our node (might be a reorg or a fork)
	pub block_accepted_url: Option<String>,
	/// number of worker threads in the tokio runtime
	#[serde(default = "default_nthreads")]
	pub nthreads: u16,
	/// timeout in seconds for the http request
	#[serde(default = "default_timeout")]
	pub timeout: u16,
}

fn default_future_time_limit() -> u64 {
	DEFAULT_FUTURE_TIME_LIMIT
}

fn default_timeout() -> u16 {
	10
}

fn default_nthreads() -> u16 {
	4
}

impl Default for WebHooksConfig {
	fn default() -> WebHooksConfig {
		WebHooksConfig {
			tx_received_url: None,
			header_received_url: None,
			block_received_url: None,
			block_accepted_url: None,
			nthreads: default_nthreads(),
			timeout: default_timeout(),
		}
	}
}

/// Stratum (Mining server) configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StratumServerConfig {
	/// Run a stratum mining server (the only way to communicate to mine this
	/// node via grin-miner
	pub enable_stratum_server: Option<bool>,

	/// If enabled, the address and port to listen on
	pub stratum_server_addr: Option<String>,

	/// How long to wait before stopping the miner, recollecting transactions
	/// and starting again
	pub attempt_time_per_block: u32,

	/// Minimum difficulty for worker shares
	pub minimum_share_difficulty: u64,

	/// Base address to the HTTP wallet receiver
	pub recipient_address: String,

	/// Attributes the reward to a random private key instead of contacting the
	/// wallet receiver. Mostly used for tests.
	pub burn_reward: bool,
}

impl Default for StratumServerConfig {
	fn default() -> StratumServerConfig {
		StratumServerConfig {
			recipient_address: "replace".to_string(),
			burn_reward: false,
			attempt_time_per_block: 15,
			minimum_share_difficulty: 1,
			enable_stratum_server: Some(false),
			stratum_server_addr: Some("127.0.0.1:3416".to_string()),
		}
	}
}

/// Type of seeding the server will use to find other peers on the network.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChainValidationMode {
	/// Run full chain validation after processing every block.
	EveryBlock,
	/// Do not automatically run chain validation during normal block
	/// processing.
	Disabled,
}

impl Default for ChainValidationMode {
	fn default() -> ChainValidationMode {
		ChainValidationMode::Disabled
	}
}

/// Full server configuration, aggregating configurations required for the
/// different components.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerConfig {
	/// Directory under which the rocksdb stores will be created
	pub db_root: String,

	/// Network address for the Rest API HTTP server.
	pub api_http_addr: String,

	/// Location of secret for basic auth on Rest API HTTP and V2 Owner API server.
	pub api_secret_path: Option<String>,

	/// Location of secret for basic auth on v2 Foreign API server.
	pub foreign_api_secret_path: Option<String>,

	/// TLS certificate file
	pub tls_certificate_file: Option<String>,
	/// TLS certificate private key file
	pub tls_certificate_key: Option<String>,

	/// Location of the bitcoin utxo binary
	pub binary_location: Option<String>,

	/// Setup the server for tests, testnet or mainnet
	#[serde(default)]
	pub chain_type: ChainTypes,

	/// Future Time Limit
	#[serde(default = "default_future_time_limit")]
	pub future_time_limit: u64,

	/// Automatically run full chain validation during normal block processing?
	#[serde(default)]
	pub chain_validation_mode: ChainValidationMode,

	/// Whether this node is a full archival node or a fast-sync, pruned node
	pub archive_mode: Option<bool>,

	/// Whether to skip the sync timeout on startup
	/// (To assist testing on solo chains)
	pub skip_sync_wait: Option<bool>,

	/// Whether to skip sync altogether (used in testing)
	pub skip_sync: Option<bool>,

	/// Whether to run the TUI
	/// if enabled, this will disable logging to stdout
	pub run_tui: Option<bool>,

	/// Whether to run the test miner (internal, cuckoo 16)
	pub run_test_miner: Option<bool>,

	/// Test miner wallet URL
	pub test_miner_wallet_url: Option<String>,

	/// Configuration for the peer-to-peer server
	pub p2p_config: P2PConfig,

	/// Transaction pool configuration
	#[serde(default)]
	pub pool_config: pool::PoolConfig,

	/// Dandelion configuration
	#[serde(default)]
	pub dandelion_config: pool::DandelionConfig,

	/// Configuration for the mining daemon
	#[serde(default)]
	pub stratum_mining_config: Option<StratumServerConfig>,

	/// Configuration for the webhooks that trigger on certain events
	#[serde(default)]
	pub webhook_config: WebHooksConfig,

	/// Bypass the checksum check for the utxo_data (must only be used for testing)
	pub bypass_checksum: Option<bool>,
}

impl Default for ServerConfig {
	fn default() -> ServerConfig {
		ServerConfig {
			db_root: "bmw_chain".to_string(),
			api_http_addr: "127.0.0.1:3413".to_string(),
			api_secret_path: Some(".api_secret".to_string()),
			foreign_api_secret_path: Some(".foreign_api_secret".to_string()),
			tls_certificate_file: None,
			tls_certificate_key: None,
			p2p_config: P2PConfig::default(),
			dandelion_config: pool::DandelionConfig::default(),
			stratum_mining_config: Some(StratumServerConfig::default()),
			chain_type: ChainTypes::default(),
			future_time_limit: default_future_time_limit(),
			archive_mode: Some(false),
			chain_validation_mode: ChainValidationMode::default(),
			pool_config: pool::PoolConfig::default(),
			skip_sync_wait: Some(false),
			skip_sync: Some(false),
			run_tui: Some(true),
			run_test_miner: Some(false),
			test_miner_wallet_url: None,
			webhook_config: WebHooksConfig::default(),
			binary_location: None,
			bypass_checksum: None,
		}
	}
}

/// Type of seeding the server will use to find other peers on the network.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum Seeding {
	/// No seeding, mostly for tests that programmatically connect
	None,
	/// A list of seeds provided to the server (can be addresses or DNS names)
	List,
	/// Automatically get a list of seeds from multiple DNS
	DNSSeed,
	/// Mostly for tests, where connections are initiated programmatically
	Programmatic,
}

impl Default for Seeding {
	fn default() -> Seeding {
		Seeding::DNSSeed
	}
}

/// Going to hold all of the various configuration types
/// separately for now, then put them together as a single
/// ServerConfig object afterwards. This is to flatten
/// out the configuration file into logical sections,
/// as they tend to be quite nested in the code
/// Most structs optional, as they may or may not
/// be needed depending on what's being run
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct GlobalConfig {
	/// Keep track of the file we've read
	pub config_file_path: Option<PathBuf>,
	/// Global member config
	pub members: Option<ConfigMembers>,
}

/// Keeping an 'inner' structure here, as the top
/// level GlobalConfigContainer options might want to keep
/// internal state that we don't necessarily
/// want serialised or deserialised
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ConfigMembers {
	/// Server config
	#[serde(default)]
	pub server: ServerConfig,
	/// Logging config
	pub logging: Option<LoggingConfig>,
}
