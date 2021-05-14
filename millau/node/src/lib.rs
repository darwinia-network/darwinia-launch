mod chain_spec;
#[macro_use]
mod service;
mod cli;
mod command;

pub type Result = sc_cli::Result<()>;

pub fn run() -> Result {
	command::run()
}
