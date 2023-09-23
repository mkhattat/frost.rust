//! Generate documentation for a ciphersuite based on another ciphersuite implementation.
//!
//! This is an internal tool used for development.
//!
//! The documentation for each ciphersuite is very similar, with the only difference being
//! the ciphersuite name.
//!
//! To make it easier to update all ciphersuite documentation when a change is needed,
//! this binary allows updating all of them based on a single one. This binary
//! uses frost-ristretto255 as the "canonical" one, so:
//!
//! - Change any documentation of a public function or struct in `frost-ristretto255/src/lib.rs`
//! - Run `cargo run --manifest-path gencode/Cargo.toml` to update the documentation
//!   of the other ciphersuites.
//!
//! This tool is also used to automatically generate similar files in each
//! ciphersuite, such as:
//! - README.md
//! - The dkg.rs module and the dkg.md docs
//! - The repairable.rs module (it uses the frost-core docs as canonical)

mod lib;

use lib::run_frost;
use std::process::ExitCode;

use std::env;

extern crate getopts;
use self::getopts::{Matches, Options};

// options from bench_sign; update for n party
pub fn process_options() -> Option<Matches> {
    let args: Vec<String> = env::args().collect();

    println!("args: {:?}", args);

    let mut opts = Options::new();
    opts.optopt("o", "", "set output file name", "NAME");
    opts.optopt(
        "p",
        "port",
        "lowest port (the required number will be allocated above)",
        "PORT",
    );
    opts.optopt("n", "iterations", "number of iterations", "ITERS");
    opts.optopt(
        "a",
        "addresses",
        "comma-delimited list of IP Addresses",
        "IP",
    );

    opts.optflag("h", "help", "print this help menu");
    opts.optflag("", "bench_proactive", "benchmark with proactive refreshes");

    // threshold flags
    opts.optopt("N", "size", "number of parties", "SIZE");
    opts.optopt("P", "party", "party number", "PARTY");
    opts.optopt("T", "threshold", "min number of signer", "THRES");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            panic!("{}", f.to_string())
        }
    };

    if matches.opt_present("h") {
        let program = args[0].clone();
        let brief = format!("Usage: {} [options]", program);
        print!("{}", opts.usage(&brief));
        return Option::None;
    }

    return Option::Some(matches);
}

fn main() -> ExitCode {
    let matches = process_options();
    if let None = matches {
        ::std::process::exit(1);
    }
    let matches = matches.unwrap();

    // number of parties
    let n = matches
        .opt_str("N")
        .unwrap_or("2".to_owned())
        .parse::<usize>()
        .unwrap();
    let thres = matches
        .opt_str("T")
        .unwrap_or("2".to_owned())
        .parse::<usize>()
        .unwrap();
    // If party index isn't specified, assume 2P
    let index = matches.opt_str("P").unwrap().parse::<usize>().unwrap();
    if !matches.opt_present("p") && n != 2 {
        println!("Please add ports");
        ::std::process::exit(1);
    }

    // ports should be separated by commas
    let addrs = matches.opt_str("a").unwrap_or("0.0.0.0".to_owned());
    let port: usize = matches
        .opt_str("p")
        .unwrap_or("12345".to_owned())
        .parse()
        .unwrap();

    let message = "my message".as_bytes();
    println!("message: {:?}", message);
    let _x = run_frost(n, thres, index, addrs, port, message);

    ExitCode::SUCCESS
}
