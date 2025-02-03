use core::panic;
use std::path::PathBuf;

use litesvm::LiteSVM;
use openbook_dex::state::MarketState;
use solana_sdk::{clock::Clock, instruction::Instruction, native_token::LAMPORTS_PER_SOL, program_pack::Pack, pubkey::Pubkey, rent::Rent, signature::Keypair, signer::Signer, transaction::Transaction};

pub fn find_file(filename: &str) -> Option<PathBuf> {
    for dir in default_shared_object_dirs() {
        let candidate = dir.join(filename);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn default_shared_object_dirs() -> Vec<PathBuf> {
    let mut search_path = vec![];
    if let Ok(bpf_out_dir) = std::env::var("BPF_OUT_DIR") {
        search_path.push(PathBuf::from(bpf_out_dir));
    } else if let Ok(bpf_out_dir) = std::env::var("SBF_OUT_DIR") {
        search_path.push(PathBuf::from(bpf_out_dir));
    }
    search_path.push(PathBuf::from("programs"));
    if let Ok(dir) = std::env::current_dir() {
        search_path.push(dir);
    }
    log::trace!("SBF .so search path: {:?}", search_path);
    search_path
}

fn send_tx_fail_err(ctx: &mut LiteSVM, ixs: &[Instruction], signers: &[&Keypair]) {
    let mut transaction = Transaction::new_with_payer(ixs, None);
    transaction.sign(signers, ctx.latest_blockhash());
    if let Err(e) = ctx.send_transaction(transaction) {
        log::error!("Failed to send transaction: {:?} instructions : [{:?}]", e, ixs);
        panic!("Failed to send transaction");
    }
}

pub fn create_program_account(ctx: &mut LiteSVM, payer: &Keypair, size: usize, owner: &Pubkey) -> Pubkey {
    log::info!("creating account");
    let rent = Rent::default();
    let account = Keypair::new();
    let lamport = rent.minimum_balance(size) * 2;
    let ix = solana_sdk::system_instruction::create_account(&payer.pubkey(), &account.pubkey(), lamport, size as u64, owner);
    send_tx_fail_err(ctx, &[ix], &[payer, &account]);
    account.pubkey()
}

pub fn create_mint(ctx: &mut LiteSVM, payer: &Keypair, authority: &Pubkey) -> Pubkey {
    log::info!("creating mint");
    let mint = create_program_account(ctx, payer, spl_token::state::Mint::LEN, &spl_token::ID);
    let ix = spl_token::instruction::initialize_mint(&spl_token::ID, &mint, authority, None, 6).unwrap();
    send_tx_fail_err(ctx, &[ix], &[payer]);
    mint
}

pub fn create_token_account(ctx: &mut LiteSVM, payer: &Keypair, mint: &Pubkey, owner: &Pubkey) -> Pubkey {
    log::info!("creating token account");
    let token_account = create_program_account(ctx, payer, spl_token::state::Account::LEN, &spl_token::ID);
    let ix = spl_token::instruction::initialize_account(&spl_token::ID, &token_account, mint, owner).unwrap();
    send_tx_fail_err(ctx, &[ix], &[payer]);
    token_account
}

#[derive(Debug, Clone, Copy)]
pub struct Market {
    pub market: Pubkey,
    pub bids: Pubkey,
    pub asks: Pubkey,
    pub req_q: Pubkey,
    pub event_q: Pubkey,
    pub coin_vault: Pubkey,
    pub pc_vault: Pubkey,
    pub vault_signer: Pubkey,
}

pub fn create_market(ctx: &mut LiteSVM, payer: &Keypair, openbook_id: &Pubkey, mint_coin: &Pubkey, mint_pc: &Pubkey) -> Market{
    log::info!("creating market");
    let market = create_program_account( ctx, payer, std::mem::size_of::<MarketState>(), openbook_id);
    let bids_pk = create_program_account( ctx, payer, 1 << 16, openbook_id);
    let asks_pk = create_program_account( ctx, payer, 1 << 16, openbook_id);
    let req_q_pk = create_program_account( ctx, payer, 640, openbook_id);
    let event_q_pk = create_program_account( ctx, payer, 65536, openbook_id);

    
    let mut i = 0;
    let (vault_signer_nonce, vault_signer_pk) = loop {
        assert!(i < 255);
        if let Ok(pk) = openbook_dex::state::gen_vault_signer_key(i, &market, &spl_token::ID) {
            break (i, pk);
        }
        i += 1;
    };
    let coin_vault_pk = create_token_account(ctx, payer, mint_coin, &vault_signer_pk);
    let pc_vault_pk = create_token_account(ctx, payer, mint_pc, &vault_signer_pk);

    let ix = openbook_dex::instruction::initialize_market(&market, openbook_id, &mint_coin, &mint_pc, &coin_vault_pk, &pc_vault_pk, None, None, None, &bids_pk, &asks_pk, &req_q_pk, &event_q_pk, 100_000, 100, vault_signer_nonce, 500).unwrap();
    send_tx_fail_err(ctx, &[ix], &[payer]);
    Market {
        market,
        bids: bids_pk,
        asks: asks_pk,
        req_q: req_q_pk,
        event_q: event_q_pk,
        coin_vault: coin_vault_pk,
        pc_vault: pc_vault_pk,
        vault_signer: vault_signer_pk,
    }
}

pub fn create_users() {
    log::info!("create_users");
}

fn setup_test_chain(openbook_id: Pubkey) -> anyhow::Result<LiteSVM> {
    let mut program_test = LiteSVM::new();
    program_test.set_sysvar(&Clock::default());
    program_test.set_sysvar(&Rent::default());

    // deploy obk program
    let obk_path = find_file(format!("openbook.so").as_str()).unwrap();
    program_test.add_program_from_file(openbook_id, obk_path)?;

    //deploy token program
    let token_path = find_file(format!("token.so").as_str()).unwrap();
    program_test.add_program_from_file(spl_token::ID, token_path)?;

    Ok(program_test)
}

fn main() {
    let openbook_id = Pubkey::new_unique();

    let mut  litesvm = setup_test_chain(openbook_id).unwrap();

    let payer = Keypair::new();
    litesvm.airdrop(&payer.pubkey(), LAMPORTS_PER_SOL * 1000).unwrap();
    let coin_mint = create_mint(&mut litesvm, &payer, &payer.pubkey());
    let pc_mint = create_mint(&mut litesvm, &payer, &payer.pubkey());
    let market = create_market(&mut litesvm, &payer, &openbook_id, &coin_mint, &pc_mint);

    println!("market sucessfully created: {:?}", market);
}
