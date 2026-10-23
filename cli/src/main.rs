//! VeilGov CLI — research prototype.

mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "veilgov", about = "Unlinkable heterogeneous cross-chain voting power consolidation (experimental)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate DEVELOPMENT ONLY Paillier keypair fixture metadata
    Setup,
    /// Create a master identity secret
    CreateIdentity,
    /// Run Alice/Bob end-to-end demo
    Demo {
        /// Generate and verify real RISC Zero receipts (CPU: multi-hour for ETH+SOL ballots)
        #[arg(long, default_value_t = false)]
        zk_prove: bool,
    },
    /// Run microbenchmarks (native ballot/tally/paillier)
    Benchmark,
    /// Verify a tally result JSON
    VerifyResult { path: String },
    /// Generate a cryptographic ballot proof from a private input JSON file
    ProveBallot {
        input: String,
        proof: String,
        statement: String,
    },
    /// Verify a ballot proof using only public election configuration
    VerifyBallot { proof: String, config: String },
    /// Execute the ballot guest without proving (cycle measurement)
    ZkCycles,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Setup => commands::setup::run(),
        Commands::CreateIdentity => commands::identity::run(),
        Commands::Demo { zk_prove } => commands::demo::run(zk_prove),
        Commands::Benchmark => commands::benchmark::run(),
        Commands::VerifyResult { path } => commands::verify::run(&path),
        Commands::ProveBallot {
            input,
            proof,
            statement,
        } => commands::ballot_proof::prove(&input, &proof, &statement),
        Commands::VerifyBallot { proof, config } => {
            commands::ballot_proof::verify(&proof, &config)
        }
        Commands::ZkCycles => commands::zk_cycles::run(),
    }
}
