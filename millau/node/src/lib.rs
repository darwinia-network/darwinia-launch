pub mod chain_spec;
#[macro_use]
mod service;
mod cli;
mod command;

// --- paritytech ---
use sc_cli::Result;

pub fn run() -> Result<()> {
	command::run()
}
