use clap::Parser;
use fibonacci_verifier_contract::SP1Groth16Proof;
use solana_program_test::{processor, BanksClient, ProgramTest};
use solana_sdk::{
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair},
    signer::Signer,
    transaction::Transaction,
    compute_budget::ComputeBudgetInstruction,
};

use shellexpand;
use solana_client::rpc_client::RpcClient;
use sp1_sdk::{include_elf, utils, ProverClient, SP1ProofWithPublicValues, SP1Stdin};
use std::str::FromStr;

#[derive(clap::Parser)]
#[command(name = "zkVM Proof Generator")]
struct Cli {
    #[arg(
        long,
        value_name = "prove",
        default_value = "false",
        help = "Specifies whether to generate a proof for the program."
    )]
    prove: bool,

    #[arg(
        long,
        value_name = "devnet",
        default_value = "false",
        help = "Specifies whether to use the devnet program ID."
    )]
    devnet: bool,

    #[arg(
        long,
        value_name = "rpc_url",
        default_value = "https://api.devnet.solana.com",
        help = "The RPC URL to connect to the Solana cluster."
    )]
    rpc_url: String,

    #[arg(
        long,
        value_name = "program_id",
        help = "The program ID to use for verification.",
        default_value = ""
    )]
    program_id: String,
}

/// The ELF binary of the SP1 program.
const ELF: &[u8] = include_elf!("fibonacci-program");

#[tokio::main]
async fn main() {
    // Setup logging for the application.
    utils::setup_logger();
    let args = Cli::parse();
    if args.devnet {
        println!(
            "Running main example script on devnet\nRPC URL: {}\nProgram ID: {}",
            args.rpc_url, args.program_id
        );
    } else {
        println!("Running main example script locally");
    }

    // Parse the program ID from the arguments
    let program_id = if !args.devnet {
        if args.program_id.is_empty() {
            Pubkey::new_unique()
        } else {
            Pubkey::from_str(&args.program_id).expect("Invalid program ID")
        }
    } else {
        Pubkey::from_str(&args.program_id).expect("Program ID required for devnet")
    };

    // Initialize payer based on devnet flag
    let payer = if args.devnet {
        // Load the default keypair from the Solana CLI configuration for devnet
        let keypair_path = shellexpand::tilde("~/.config/solana/id.json").to_string();
        let payer = read_keypair_file(keypair_path).expect("Failed to read keypair file");
        println!("Using payer with public key: {}", payer.pubkey());
        payer
    } else {
        // For local testing, payer will be set later
        Keypair::new()
    };

    // Where to save / load the sp1 proof from.
    let proof_file = "../../proofs/fibonacci_proof.bin";

    // Only generate a proof if the prove flag is set.
    if args.prove {
        // Initialize the prover client
        let client = ProverClient::new();
        let (pk, vk) = client.setup(ELF);

        println!(
            "Program Verification Key Bytes {:?}",
            sp1_sdk::HashableKey::bytes32(&vk)
        );

        // In our SP1 program, compute the 20th fibonacci number.
        let mut stdin = SP1Stdin::new();
        stdin.write(&20u32);

        // Generate a proof for the fibonacci program.
        let proof = client
            .prove(&pk, stdin)
            .groth16()
            .run()
            .expect("Groth16 proof generation failed");

        // Save the generated proof to `proof_file`.
        proof.save(&proof_file).unwrap();
    }

    // Load the proof from the file, and convert it to a Borsh-serializable `SP1Groth16Proof`.
    let sp1_proof_with_public_values = SP1ProofWithPublicValues::load(&proof_file).unwrap();
    let groth16_proof = SP1Groth16Proof {
        proof: sp1_proof_with_public_values.bytes(),
        sp1_public_inputs: sp1_proof_with_public_values.public_values.to_vec(),
    };
    println!("Created Groth16 proof with {} public inputs", groth16_proof.sp1_public_inputs.len());

    if args.devnet {
        // Use RpcClient for devnet
        let client = RpcClient::new(args.rpc_url);
        run_verify_instruction_devnet(groth16_proof, program_id, client, payer).await;
    } else {
        // Use BanksClient for local testing
        let (banks_client, payer_local, recent_blockhash) = ProgramTest::new(
            "fibonacci-verifier-contract",
            program_id,
            processor!(fibonacci_verifier_contract::process_instruction),
        )
        .start()
        .await;
        run_verify_instruction_local(
            groth16_proof,
            program_id,
            banks_client,
            payer_local,
            recent_blockhash,
        )
        .await;
    }
}

// Function for devnet verification
async fn run_verify_instruction_devnet(
    groth16_proof: SP1Groth16Proof,
    program_id: Pubkey,
    client: RpcClient,
    payer: Keypair,
) {
    println!("Running verify instruction on devnet");
    println!("Program ID: {:?}", program_id);

    // Request more compute units
    let compute_budget_instruction = ComputeBudgetInstruction::set_compute_unit_limit(400_000);

    let instruction = Instruction::new_with_borsh(
        program_id,
        &groth16_proof,
        vec![AccountMeta::new(payer.pubkey(), false)],
    );

    println!("Created instruction with {} bytes of proof data", groth16_proof.proof.len());

    // Create and send transaction
    let mut transaction = Transaction::new_with_payer(
        &[compute_budget_instruction, instruction],
        Some(&payer.pubkey()),
    );
    let recent_blockhash = client.get_latest_blockhash().unwrap();
    transaction.sign(&[&payer], recent_blockhash);

    println!("Sending transaction...");
    let signature = client.send_and_confirm_transaction(&transaction).unwrap();
    println!("Transaction confirmed!");
    println!("Transaction signature: {}", signature);
}

// Function for local testing
async fn run_verify_instruction_local(
    groth16_proof: SP1Groth16Proof,
    program_id: Pubkey,
    banks_client: BanksClient,
    payer: Keypair,
    recent_blockhash: Hash,
) {
    println!("Running verify instruction locally");
    println!("Program ID: {:?}", program_id);

    let instruction = Instruction::new_with_borsh(
        program_id,
        &groth16_proof,
        vec![AccountMeta::new(payer.pubkey(), false)],
    );

    // Create and send transaction
    let mut transaction = Transaction::new_with_payer(&[instruction], Some(&payer.pubkey()));
    transaction.sign(&[&payer], recent_blockhash);

    banks_client.process_transaction(transaction).await.unwrap();
}
