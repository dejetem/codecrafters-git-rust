#[allow(unused_imports)]
use std::env;
#[allow(unused_imports)]
use std::fs;
use std::path::{Path, PathBuf};

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::prelude::*;
use sha1::{Sha1, Digest};

fn main() {
    eprintln!("Logs from your program will appear here!");

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Not enough arguments");
        return;
    }

    match args[1].as_str() {
        "init" => {
            fs::create_dir(".git").unwrap();
            fs::create_dir(".git/objects").unwrap();
            fs::create_dir(".git/refs").unwrap();
            fs::write(".git/HEAD", "ref: refs/heads/main\n").unwrap();
            println!("Initialized git directory");
        }
        "cat-file" => {
            if args.len() < 4 {
                eprintln!("Not enough arguments for cat-file");
                return;
            }

            let content = fs::read(format!(".git/objects/{}/{}", &args[3][..2], &args[3][2..])).unwrap();
            let mut z = ZlibDecoder::new(&content[..]);
            let mut s = String::new();
            z.read_to_string(&mut s).unwrap();
            print!("{}", &s[8..]);
        }
        "hash-object" => {
            if args.len() < 3 {
                eprintln!("Not enough arguments for hash-object");
                return;
            }

            let write_object = args.contains(&"-w".to_string());
            let file_path = &args[args.len() - 1];

            let content = match fs::read(file_path) {
                Ok(content) => content,
                Err(e) => {
                    eprintln!("Failed to read file {}: {}", file_path, e);
                    return;
                }
            };

            let header = format!("blob {}\0", content.len());
            let mut blob = Vec::new();
            blob.extend_from_slice(header.as_bytes());
            blob.extend_from_slice(&content);

            let mut hasher = Sha1::new();
            hasher.update(&blob);
            let hash = hasher.finalize();
            let hash_hex = format!("{:x}", hash);

            if write_object {
                let dir_path = format!(".git/objects/{}", &hash_hex[..2]);
                let file_path = format!("{}/{}", dir_path, &hash_hex[2..]);

                if !Path::new(&dir_path).exists() {
                    fs::create_dir_all(&dir_path).unwrap();
                }

                let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(&blob).unwrap();
                let compressed = encoder.finish().unwrap();

                fs::write(file_path, compressed).unwrap();
            }

            println!("{}", hash_hex);
        }
        "ls-tree" => {
            if args.len() < 4 || args[2] != "--name-only" {
                eprintln!("Usage: ls-tree --name-only <tree_sha>");
                return;
            }

            let sha = &args[3];
            let path = format!(".git/objects/{}/{}", &sha[..2], &sha[2..]);

            let content = fs::read(path).expect("Failed to read object file");
            let mut decoder = ZlibDecoder::new(&content[..]);
            let mut decoded = Vec::new();
            decoder.read_to_end(&mut decoded).unwrap();

            let mut i = 0;
            while i < decoded.len() && decoded[i] != 0 {
                i += 1;
            }
            i += 1;

            while i < decoded.len() {
                let mode_start = i;
                while decoded[i] != b' ' {
                    i += 1;
                }
                let _mode = std::str::from_utf8(&decoded[mode_start..i]).unwrap();
                i += 1;

                let name_start = i;
                while decoded[i] != 0 {
                    i += 1;
                }
                let name = std::str::from_utf8(&decoded[name_start..i]).unwrap();
                i += 1;

                i += 20;

                println!("{}", name);
            }
        }
        "write-tree" => {
            let sha = write_tree(Path::new("."));
            println!("{}", sha);
        }
        _ => println!("unknown command: {}", args[1]),
    }
}

fn write_tree(path: &Path) -> String {
    let mut entries = Vec::new();

    for entry in fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name.to_str().unwrap();

        if name == ".git" {
            continue;
        }

        let metadata = fs::metadata(&path).unwrap();

        if metadata.is_file() {
            let content = fs::read(&path).unwrap();
            let header = format!("blob {}\0", content.len());

            let mut blob = Vec::new();
            blob.extend_from_slice(header.as_bytes());
            blob.extend_from_slice(&content);

            let mut hasher = Sha1::new();
            hasher.update(&blob);
            let hash = hasher.finalize();
            let hash_bytes = hash.clone();

            let hash_hex = format!("{:x}", hash);

            let dir = format!(".git/objects/{}", &hash_hex[..2]);
            let file = format!("{}/{}", dir, &hash_hex[2..]);

            if !Path::new(&file).exists() {
                fs::create_dir_all(&dir).unwrap();

                let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(&blob).unwrap();
                let compressed = encoder.finish().unwrap();
                fs::write(file, compressed).unwrap();
            }

            entries.push((format!("100644 {}", name), hash_bytes[..].to_vec()));
        } else if metadata.is_dir() {
            let tree_sha = write_tree(&path);
            let tree_bin = hex::decode(tree_sha).unwrap();
            entries.push((format!("40000 {}", name), tree_bin));
        }
    }

    let mut tree_data = Vec::new();

    for (header, hash_bytes) in entries {
        tree_data.extend_from_slice(header.as_bytes());
        tree_data.push(0);
        tree_data.extend_from_slice(&hash_bytes);
    }

    let header = format!("tree {}\0", tree_data.len());
    let mut full = Vec::new();
    full.extend_from_slice(header.as_bytes());
    full.extend_from_slice(&tree_data);

    let mut hasher = Sha1::new();
    hasher.update(&full);
    let tree_hash = hasher.finalize();
    let tree_hash_hex = format!("{:x}", tree_hash);

    let dir = format!(".git/objects/{}", &tree_hash_hex[..2]);
    let file = format!("{}/{}", dir, &tree_hash_hex[2..]);

    if !Path::new(&file).exists() {
        fs::create_dir_all(&dir).unwrap();
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&full).unwrap();
        let compressed = encoder.finish().unwrap();
        fs::write(file, compressed).unwrap();
    }

    tree_hash_hex
}
