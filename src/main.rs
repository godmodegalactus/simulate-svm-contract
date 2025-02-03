use core::{hash, panic};
use std::{collections::HashMap, num::NonZero, path::PathBuf, str::FromStr};

use litesvm::{types::TransactionResult, LiteSVM};
use openbook_dex::{
    matching::Side,
    state::{MarketState, OpenOrders},
};
use rand::{rngs::ThreadRng, Rng};
use solana_sdk::{
    clock::Clock, instruction::Instruction, native_token::LAMPORTS_PER_SOL, program_pack::Pack,
    pubkey::Pubkey, rent::Rent, signature::Keypair, signer::Signer, transaction::Transaction,
};

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
    let mut transaction = Transaction::new_with_payer(ixs, Some(&signers[0].pubkey()));
    transaction.sign(signers, ctx.latest_blockhash());
    if let Err(e) = ctx.send_transaction(transaction) {
        log::error!(
            "Failed to send transaction: {:?} instructions : [{:?}]",
            e,
            ixs
        );
        panic!("Failed to send transaction");
    }
}

fn send_transaction_return_result(
    ctx: &mut LiteSVM,
    ixs: &[Instruction],
    signers: &[&Keypair],
) -> TransactionResult {
    let mut transaction = Transaction::new_with_payer(ixs, Some(&signers[0].pubkey()));
    transaction.sign(signers, ctx.latest_blockhash());
    ctx.send_transaction(transaction)
}

pub fn create_program_account(
    ctx: &mut LiteSVM,
    payer: &Keypair,
    size: usize,
    owner: &Pubkey,
) -> Pubkey {
    log::debug!("creating account");
    let rent = Rent::default();
    let account = Keypair::new();
    let lamport = rent.minimum_balance(size);

    let ix = solana_sdk::system_instruction::create_account(
        &payer.pubkey(),
        &account.pubkey(),
        lamport,
        size as u64,
        owner,
    );
    send_tx_fail_err(ctx, &[ix], &[payer, &account]);
    account.pubkey()
}

pub fn create_mint(ctx: &mut LiteSVM, payer: &Keypair, authority: &Pubkey) -> Pubkey {
    log::debug!("creating mint");
    let mint = create_program_account(ctx, payer, spl_token::state::Mint::LEN, &spl_token::ID);
    let ix =
        spl_token::instruction::initialize_mint(&spl_token::ID, &mint, authority, None, 6).unwrap();
    send_tx_fail_err(ctx, &[ix], &[payer]);
    mint
}

fn mint_tokens(
    ctx: &mut LiteSVM,
    authority: &Keypair,
    mint: &Pubkey,
    account: &Pubkey,
    amount: u64,
) {
    log::debug!("minting tokens");
    let ix = spl_token::instruction::mint_to(
        &spl_token::ID,
        mint,
        account,
        &authority.pubkey(),
        &[&authority.pubkey()],
        amount,
    )
    .unwrap();
    send_tx_fail_err(ctx, &[ix], &[authority]);
}

pub fn create_token_account(
    ctx: &mut LiteSVM,
    payer: &Keypair,
    mint: &Pubkey,
    owner: &Pubkey,
) -> Pubkey {
    log::debug!("creating token account");
    let token_account =
        create_program_account(ctx, payer, spl_token::state::Account::LEN, &spl_token::ID);
    let ix =
        spl_token::instruction::initialize_account(&spl_token::ID, &token_account, mint, owner)
            .unwrap();
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

pub fn create_market(
    ctx: &mut LiteSVM,
    payer: &Keypair,
    openbook_id: &Pubkey,
    mint_coin: &Pubkey,
    mint_pc: &Pubkey,
) -> Market {
    log::info!("creating market");
    let market = create_program_account(
        ctx,
        payer,
        std::mem::size_of::<MarketState>() + 12,
        openbook_id,
    );
    let bids_pk = create_program_account(ctx, payer, 65536 + 12, openbook_id);
    let asks_pk = create_program_account(ctx, payer, 65536 + 12, openbook_id);
    let req_q_pk = create_program_account(ctx, payer, 5120 + 12, openbook_id);
    let event_q_pk = create_program_account(ctx, payer, 262144 + 12, openbook_id);

    let mut i = 0;
    let (vault_signer_nonce, vault_signer_pk) = loop {
        assert!(i < 100);
        if let Ok(pk) = openbook_dex::state::gen_vault_signer_key(i, &market, openbook_id) {
            break (i, pk);
        }
        i += 1;
    };
    let coin_vault_pk = create_token_account(ctx, payer, mint_coin, &vault_signer_pk);
    let pc_vault_pk = create_token_account(ctx, payer, mint_pc, &vault_signer_pk);

    log::debug!("market : {market:?}");
    log::debug!("bids : {bids_pk:?}");
    log::debug!("asks : {asks_pk:?}");
    log::debug!("req_q : {req_q_pk:?}");
    log::debug!("event_q : {event_q_pk:?}");
    log::debug!("coin_vault : {coin_vault_pk:?}");
    log::debug!("pc_vault : {pc_vault_pk:?}");
    log::debug!("vault_signer : {vault_signer_pk:?}");
    log::debug!("vault_signer_nonce : {vault_signer_nonce:?}");
    log::debug!("mint_coin : {mint_coin:?}");
    log::debug!("mint_pc : {mint_pc:?}");
    log::debug!("openbook_id : {openbook_id:?}");

    log::debug!(
        "len : {} : {}",
        ctx.get_account(&market).unwrap().data.len(),
        ctx.get_account(&market).unwrap().data.len() % 8
    );
    log::debug!(
        "len : {} : {}",
        ctx.get_account(&bids_pk).unwrap().data.len(),
        ctx.get_account(&bids_pk).unwrap().data.len() % 8
    );
    log::debug!(
        "len : {} : {}",
        ctx.get_account(&asks_pk).unwrap().data.len(),
        ctx.get_account(&asks_pk).unwrap().data.len() % 8
    );
    log::debug!(
        "len : {} : {}",
        ctx.get_account(&req_q_pk).unwrap().data.len(),
        ctx.get_account(&req_q_pk).unwrap().data.len() % 8
    );
    log::debug!(
        "len : {} : {}",
        ctx.get_account(&event_q_pk).unwrap().data.len(),
        ctx.get_account(&event_q_pk).unwrap().data.len() % 8
    );

    let ix = openbook_dex::instruction::initialize_market(
        &market,
        openbook_id,
        mint_coin,
        mint_pc,
        &coin_vault_pk,
        &pc_vault_pk,
        None,
        None,
        None,
        &bids_pk,
        &asks_pk,
        &req_q_pk,
        &event_q_pk,
        100,
        100,
        vault_signer_nonce,
        500,
    )
    .unwrap();
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

fn send_market_order(
    ctx: &mut LiteSVM,
    openbook_id: &Pubkey,
    market: &Market,
    user: &mut User,
    side: Side,
    price: u64,
    size: u64,
) -> TransactionResult {
    log::debug!("creating market order");
    let open_orders = user.open_orders.get(&market.market).unwrap();

    log::debug!("market: {:?}", ctx.get_account(&market.market));
    log::debug!("open_orders: {:?}", ctx.get_account(&open_orders));
    log::debug!("req_q: {:?}", ctx.get_account(&market.req_q));
    log::debug!("event_q: {:?}", ctx.get_account(&market.event_q));
    log::debug!("bids: {:?}", ctx.get_account(&market.bids));
    log::debug!("asks: {:?}", ctx.get_account(&market.asks));
    log::debug!("coin_vault: {:?}", ctx.get_account(&market.coin_vault));
    log::debug!("pc_vault: {:?}", ctx.get_account(&market.pc_vault));

    let payer = match side {
        Side::Bid => &user.pc_account,
        Side::Ask => &user.coin_account,
    };

    let ix = openbook_dex::instruction::new_order(
        &market.market,
        open_orders,
        &market.req_q,
        &market.event_q,
        &market.bids,
        &market.asks,
        payer,
        &user.kp.pubkey(),
        &market.coin_vault,
        &market.pc_vault,
        &spl_token::ID,
        &solana_sdk::sysvar::rent::ID,
        None,
        openbook_id,
        side,
        NonZero::new(price).unwrap(),
        NonZero::new(size).unwrap(),
        openbook_dex::matching::OrderType::Limit,
        user.client_order_id,
        openbook_dex::instruction::SelfTradeBehavior::DecrementTake,
        u16::MAX,
        NonZero::new(20000).unwrap(),
        i64::MAX,
    )
    .unwrap();
    send_transaction_return_result(ctx, &[ix], &[&user.kp])
}

pub struct User {
    pub kp: Keypair,
    pub coin_account: Pubkey,
    pub pc_account: Pubkey,
    pub open_orders: HashMap<Pubkey, Pubkey>,
    pub client_order_id: u64,
}

pub fn create_user(
    ctx: &mut LiteSVM,
    markets: &Vec<&Market>,
    openbook_id: &Pubkey,
    authority: &Keypair,
    mint_coin: &Pubkey,
    mint_pc: &Pubkey,
) -> User {
    log::debug!("creating user");
    let kp = Keypair::new();
    ctx.airdrop(&kp.pubkey(), LAMPORTS_PER_SOL * 1000).unwrap();
    let coin_account = create_token_account(ctx, &kp, mint_coin, &kp.pubkey());
    let pc_account = create_token_account(ctx, &kp, mint_pc, &kp.pubkey());
    mint_tokens(
        ctx,
        authority,
        mint_coin,
        &coin_account,
        1_000_000 * 1_000_000,
    );
    mint_tokens(ctx, authority, mint_pc, &pc_account, 1_000_000 * 1_000_000);

    let mut hash_map = HashMap::new();
    for market in markets {
        let open_orders = create_program_account(
            ctx,
            authority,
            size_of::<openbook_dex::state::OpenOrders>() + 12,
            openbook_id,
        );
        let oo_ix = openbook_dex::instruction::init_open_orders(
            openbook_id,
            &open_orders,
            &kp.pubkey(),
            &market.market,
            None,
        )
        .unwrap();
        send_tx_fail_err(ctx, &[oo_ix], &[&kp]);
        hash_map.insert(market.market, open_orders);
    }
    User {
        kp,
        coin_account,
        pc_account,
        open_orders: hash_map,
        client_order_id: 0,
    }
}

pub fn create_users(
    ctx: &mut LiteSVM,
    markets: &Vec<&Market>,
    openbook_id: &Pubkey,
    authority: &Keypair,
    mint_coin: &Pubkey,
    mint_pc: &Pubkey,
    nb_users: usize,
) -> Vec<User> {
    log::debug!("creating {nb_users} users");
    (0..nb_users)
        .map(|_| create_user(ctx, markets, openbook_id, authority, mint_coin, mint_pc))
        .collect()
}

fn setup_test_chain(openbook_id: Pubkey) -> anyhow::Result<LiteSVM> {
    let mut program_test = LiteSVM::new();
    program_test.set_sysvar(&Clock::default());
    program_test.set_sysvar(&Rent::default());

    // deploy obk program
    let obk_path = find_file("openbook.so").unwrap();
    program_test.add_program_from_file(openbook_id, obk_path)?;

    //deploy token program
    let token_path = find_file("token.so").unwrap();
    program_test.add_program_from_file(spl_token::ID, token_path)?;

    Ok(program_test)
}

fn main() {
    tracing_subscriber::fmt::init();
    let openbook_id = Pubkey::from_str("srmqPvymJeFKQ4zGQed1GFppgkRHL9kaELCbyksJtPX").unwrap();

    let mut litesvm = setup_test_chain(openbook_id).unwrap();

    let payer = Keypair::new();
    litesvm
        .airdrop(&payer.pubkey(), LAMPORTS_PER_SOL * 1000)
        .unwrap();
    let coin_mint = create_mint(&mut litesvm, &payer, &payer.pubkey());
    let pc_mint = create_mint(&mut litesvm, &payer, &payer.pubkey());

    litesvm.warp_to_slot(1);
    let market = create_market(&mut litesvm, &payer, &openbook_id, &coin_mint, &pc_mint);
    litesvm.warp_to_slot(2);
    println!("market sucessfully created: {:?}", market);

    let mut users = create_users(
        &mut litesvm,
        &vec![&market],
        &openbook_id,
        &payer,
        &coin_mint,
        &pc_mint,
        100,
    );
    litesvm.warp_to_slot(3);
    println!("users sucessfully created: {:?}", users.len());

    let price = 1_000_000;
    let mut rng = ThreadRng::default();
    let mut orders_sent = 0;
    loop {
        let amount = rng.random_range(1000..10000);
        let price_diff: i64 = rng.random_range(-1000..1000);
        let new_price = price + price_diff;

        let user_index = rng.random_range(0..users.len());
        let user = &mut users[user_index];
        let is_bid = rng.random_bool(0.5);
        let side = if is_bid { Side::Bid } else { Side::Ask };

        if let Err(e) = send_market_order(
            &mut litesvm,
            &openbook_id,
            &market,
            user,
            side,
            new_price as u64,
            amount,
        ) {
            log::error!(
                "Failed to send order: {:?} {orders_sent:?} orders were sent",
                e
            );
            break;
        }
        orders_sent += 1;
    }
}
