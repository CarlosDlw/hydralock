use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "hydralock",
    about = "HydraLock v1 — quantum-resistant file encryption",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Encrypt a file into a HydraLock container.
    Encrypt(EncryptArgs),
    /// Decrypt a HydraLock container to recover the original file.
    Decrypt(DecryptArgs),
    /// Display non-sensitive metadata from a container without decrypting.
    Inspect(InspectArgs),
    /// Verify the structural integrity and footer auth tag of a container.
    Verify(VerifyArgs),
    /// Re-wrap a container with a new set of recipients (without re-encrypting payload).
    Rewrap(RewrapArgs),
    /// Generate a new recipient keypair.
    GenRecipient(GenRecipientArgs),
    /// Run built-in known-answer tests (encrypt → decrypt roundtrip).
    TestVectors,
}

#[derive(Args)]
pub struct EncryptArgs {
    /// Input file to encrypt.
    #[arg(short, long, value_name = "FILE")]
    pub input: PathBuf,

    /// Output container file.
    #[arg(short, long, value_name = "FILE")]
    pub output: PathBuf,

    /// Encrypt with a passphrase (prompted securely from TTY).
    #[arg(long, conflicts_with_all = &["recipient", "recipient_pq"])]
    pub passphrase: bool,

    /// X25519 recipient public key file (hex-encoded, .pub file from gen-recipient).
    #[arg(long, value_name = "FILE", conflicts_with = "passphrase")]
    pub recipient: Option<PathBuf>,

    /// ML-KEM-768+X25519 recipient public key file (.pub file from gen-recipient).
    #[arg(long, value_name = "FILE", conflicts_with = "passphrase")]
    pub recipient_pq: Option<PathBuf>,

    /// Logical name to embed in metadata (defaults to input filename).
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,

    /// MIME type to embed in metadata.
    #[arg(long, value_name = "MIME")]
    pub mime: Option<String>,

    /// Argon2id cost profile for passphrase mode.
    #[arg(long, value_enum, default_value = "balanced")]
    pub argon2_profile: Argon2ProfileArg,

    /// Chunk size in bytes (default: 65536).
    #[arg(long, default_value = "65536")]
    pub chunk_size: u32,

    /// Epoch size in chunks (default: 256).
    #[arg(long, default_value = "256")]
    pub epoch_size: u32,

    /// Overwrite output file if it exists.
    #[arg(long)]
    pub force: bool,
}

#[derive(Args)]
pub struct DecryptArgs {
    /// Input container file.
    #[arg(short, long, value_name = "FILE")]
    pub input: PathBuf,

    /// Output file for decrypted plaintext.
    #[arg(short, long, value_name = "FILE")]
    pub output: PathBuf,

    /// Decrypt using a passphrase (prompted securely from TTY).
    #[arg(long, conflicts_with = "key")]
    pub passphrase: bool,

    /// Secret key file for X25519 or ML-KEM-768+X25519 decryption.
    #[arg(long, value_name = "FILE", conflicts_with = "passphrase")]
    pub key: Option<PathBuf>,

    /// Overwrite output file if it exists.
    #[arg(long)]
    pub force: bool,
}

#[derive(Args)]
pub struct InspectArgs {
    /// Container file to inspect.
    #[arg(short, long, value_name = "FILE")]
    pub input: PathBuf,
}

#[derive(Args)]
pub struct VerifyArgs {
    /// Container file to verify.
    #[arg(short, long, value_name = "FILE")]
    pub input: PathBuf,

    /// Verify footer auth tag using passphrase (requires decrypting FMK).
    #[arg(long, conflicts_with = "key")]
    pub passphrase: bool,

    /// Secret key file for FMK recovery during footer verification.
    #[arg(long, value_name = "FILE", conflicts_with = "passphrase")]
    pub key: Option<PathBuf>,
}

#[derive(Args)]
pub struct RewrapArgs {
    /// Input container file.
    #[arg(short, long, value_name = "FILE")]
    pub input: PathBuf,

    /// Output container file.
    #[arg(short, long, value_name = "FILE")]
    pub output: PathBuf,

    /// Recover FMK from existing passphrase wrapper.
    #[arg(long, conflicts_with = "old_key")]
    pub old_passphrase: bool,

    /// Recover FMK from existing key file.
    #[arg(long, value_name = "FILE", conflicts_with = "old_passphrase")]
    pub old_key: Option<PathBuf>,

    /// Add a passphrase wrapper to the new container.
    #[arg(long)]
    pub add_passphrase: bool,

    /// Add an X25519 recipient public key file to the new container.
    #[arg(long, value_name = "FILE")]
    pub add_recipient: Option<PathBuf>,

    /// Add an ML-KEM-768+X25519 recipient public key file to the new container.
    #[arg(long, value_name = "FILE")]
    pub add_recipient_pq: Option<PathBuf>,

    /// Overwrite output file if it exists.
    #[arg(long)]
    pub force: bool,
}

#[derive(Args)]
pub struct GenRecipientArgs {
    /// Key type to generate.
    #[arg(long, value_enum, default_value = "x25519")]
    pub key_type: KeyTypeArg,

    /// Output file prefix. Writes <prefix>.pub and <prefix>.key.
    #[arg(short, long, value_name = "PREFIX")]
    pub output: Option<PathBuf>,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum Argon2ProfileArg {
    Interactive,
    Balanced,
    Paranoid,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum KeyTypeArg {
    X25519,
    #[value(name = "mlkem768-x25519")]
    MlKem768X25519,
}
