//! `fips-exit-pay`: see the library.

use std::io::IsTerminal;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (out, err, input) = (std::io::stdout(), std::io::stderr(), std::io::stdin());
    let tty = out.is_terminal();
    let ended = fips_exit_pay::run(
        &args,
        &mut fips_exit_pay::Around {
            out: &mut out.lock(),
            err: &mut err.lock(),
            input: &mut input.lock(),
            env: &|name| std::env::var(name).ok(),
            tty,
            pace: None,
        },
    );
    ExitCode::from(ended)
}
