#[allow(unused_imports)]
use std::env;
#[allow(unused_imports)]
use std::fs;

use flate2::read::ZlibDecoder;
use std::io::prelude::*;

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    eprintln!("Logs from your program will appear here!");

    // Uncomment this block to pass the first stage
    let args: Vec<String> = env::args().collect();
    if args[1] == "init" {
        fs::create_dir(".git").unwrap();
        fs::create_dir(".git/objects").unwrap();
        fs::create_dir(".git/refs").unwrap();
        fs::write(".git/HEAD", "ref: refs/heads/main\n").unwrap();
        println!("Initialized git directory")
    } else if args[1] == "cat-file" {
        let content =
            fs::read(format!(".git/objects/{}/{}", &args[3][..2], &args[3][2..])).unwrap();
        let mut z = ZlibDecoder::new(&content[..]);
        let mut s = String::new();
        z.read_to_string(&mut s).unwrap();
        print!("{}", &s[8..]);
    } else {
        println!("unknown command: {}", args[1])
    }
}
