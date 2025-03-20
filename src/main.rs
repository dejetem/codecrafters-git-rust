#[allow(unused_imports)]
use std::env;
#[allow(unused_imports)]
use std::fs;
use std::path::Path;

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::prelude::*;
use sha1::{Sha1, Digest};

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    eprintln!("Logs from your program will appear here!");

    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Not enough arguments");
        return;
    }

    if args[1] == "init" {
        fs::create_dir(".git").unwrap();
        fs::create_dir(".git/objects").unwrap();
        fs::create_dir(".git/refs").unwrap();
        fs::write(".git/HEAD", "ref: refs/heads/main\n").unwrap();
        println!("Initialized git directory")
    } else if args[1] == "cat-file" {
        if args.len() < 4 {
            eprintln!("Not enough arguments for cat-file");
            return;
        }
        
        let content =
            fs::read(format!(".git/objects/{}/{}", &args[3][..2], &args[3][2..])).unwrap();
        let mut z = ZlibDecoder::new(&content[..]);
        let mut s = String::new();
        z.read_to_string(&mut s).unwrap();
        print!("{}", &s[8..]);
    } else if args[1] == "hash-object" {
        if args.len() < 3 {
            eprintln!("Not enough arguments for hash-object");
            return;
        }
        
        let write_object = args.contains(&"-w".to_string());
        let file_path = &args[args.len() - 1];
        
        // Read file content
        let content = match fs::read(file_path) {
            Ok(content) => content,
            Err(e) => {
                eprintln!("Failed to read file {}: {}", file_path, e);
                return;
            }
        };
        
        // Create blob header
        let header = format!("blob {}\0", content.len());
        
        // Concatenate header and content
        let mut blob = Vec::new();
        blob.extend_from_slice(header.as_bytes());
        blob.extend_from_slice(&content);
        
        // Compute SHA-1 hash
        let mut hasher = Sha1::new();
        hasher.update(&blob);
        let hash = hasher.finalize();
        let hash_hex = format!("{:x}", hash);
        
        // Write to object store if -w flag is present
        if write_object {
            let dir_path = format!(".git/objects/{}", &hash_hex[..2]);
            let file_path = format!("{}/{}", dir_path, &hash_hex[2..]);
            
            // Create directory if it doesn't exist
            if !Path::new(&dir_path).exists() {
                fs::create_dir_all(&dir_path).unwrap();
            }
            
            // Compress the blob with zlib
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&blob).unwrap();
            let compressed = encoder.finish().unwrap();
            
            // Write compressed blob to file
            fs::write(file_path, compressed).unwrap();
        }
        
        // Print the hash
        println!("{}", hash_hex);
    } else {
        println!("unknown command: {}", args[1])
    }
}