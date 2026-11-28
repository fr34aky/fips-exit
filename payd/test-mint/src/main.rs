//! The test mint, for a test that runs outside Rust (test/netns.sh):
//!
//! ```text
//! fips-exit-test-mint serve <[address]:port> [fee-ppk]   prints its URL, serves until killed
//! fips-exit-test-mint token <mint URL> <sat> [with-fee]  prints a token from that mint
//! fips-exit-test-mint hold <mint URL>                    its invoices are paid by `pay` from now on
//! fips-exit-test-mint pay <mint URL> <invoice>           that invoice of the mint's is paid
//! ```

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("a runtime");
    let done = runtime.block_on(async {
        match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
            ["serve", listen, ref fee @ ..] => {
                let listen = listen.parse().map_err(|_| format!("{listen}: [address]:port"))?;
                let fee = fee.first().map_or(Ok(0), |fee| fee.parse().map_err(|_| format!("{fee}: per mille")))?;
                let url = fips_exit_test_mint::start(listen, fee).await?;
                println!("{url}");
                std::future::pending::<()>().await;
                Ok(())
            }
            ["token", mint, sat, ref with_fee @ ..] => {
                let sat = sat.parse().map_err(|_| format!("{sat}: sat"))?;
                let token = fips_exit_test_mint::new_token(mint, sat, with_fee == ["with-fee"]).await?;
                println!("{token}");
                Ok(())
            }
            ["hold", mint] => fips_exit_test_mint::hold(mint).await,
            ["pay", mint, invoice] => fips_exit_test_mint::pay(mint, invoice).await,
            _ => {
                Err("usage: fips-exit-test-mint serve <[address]:port> [fee-ppk] | token <mint URL> <sat> [with-fee] \
                      | hold <mint URL> | pay <mint URL> <invoice>"
                    .to_string())
            }
        }
    });
    if let Err(e) = done {
        eprintln!("fips-exit-test-mint: {e}");
        std::process::exit(1);
    }
}
