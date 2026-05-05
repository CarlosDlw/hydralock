pub mod args;
pub mod decrypt;
pub mod encrypt;
pub mod gen_recipient;
pub mod inspect;
pub mod keys;
pub mod passphrase;
pub mod rewrap_cmd;
pub mod test_vectors_cmd;
pub mod verify;

use clap::Parser;

use args::{Cli, Command};

pub fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Encrypt(args) => encrypt::run(args),
        Command::Decrypt(args) => decrypt::run(args),
        Command::Inspect(args) => inspect::run(args),
        Command::Verify(args) => verify::run(args),
        Command::Rewrap(args) => rewrap_cmd::run(args),
        Command::GenRecipient(args) => gen_recipient::run(args),
        Command::TestVectors => test_vectors_cmd::run(),
    }
}
