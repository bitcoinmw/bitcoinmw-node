// Copyright 2021 The BMW Developers
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

#[macro_use]
extern crate clap;

use bmw_node_util as util;

use bmw_node_error::Error;
use bmw_node_p2p::P2PServer;
use bmw_node_tor::TorServer;
use clap::App;
use util::core::global;

// include build information
pub mod built_info {
	include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

fn main() {
	let exit_code = real_main();
	std::process::exit(exit_code);
}

fn real_main() -> i32 {
	let yml = load_yaml!("bmw-node.yml");
	let args = App::from_yaml(yml)
		.version(built_info::PKG_VERSION)
		.get_matches();

	let chain_type = if args.is_present("testnet") {
		global::ChainTypes::Testnet
	} else if args.is_present("usernet") {
		global::ChainTypes::UserTesting
	} else {
		// at the moment we exit for mainnet
		println!("Mainnet not activated yet. Please run with the --testnet parameter.");
		std::process::exit(-1);
		//global::ChainTypes::Mainnet
	};

	println!("chain type = {:?}", chain_type);
	let result = start_server();
	if result.is_err() {
		println!("Server Start resulted in an error: {:?}", result);
		-1
	} else {
		0
	}
}

fn start_server() -> Result<(), Error> {
	let tor = TorServer::new()?;
	let p2p = P2PServer::new()?;
	tor.start()?;
	p2p.start()?;

	Ok(())
}
