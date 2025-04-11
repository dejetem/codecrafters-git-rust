#[allow(unused_imports)]
use std::env;
#[allow(unused_imports)]
use std::fs::{self, File};
use std::io::{self, Cursor, Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use sha1::{Sha1, Digest};
use reqwest::blocking::Client;



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
            let tree_sha = write_tree(".").unwrap();
            println!("{}", tree_sha);
        }
        "commit-tree" => {
            if args.len() < 6 {
                eprintln!("Usage: commit-tree <tree-sha> -p <parent-commit-sha> -m <message>");
                return;
            }
            
            let tree_sha = &args[2];
            
            // Find the parent commit SHA
            let parent_index = args.iter().position(|arg| arg == "-p").unwrap();
            let parent_sha = &args[parent_index + 1];
            
            // Find the commit message
            let message_index = args.iter().position(|arg| arg == "-m").unwrap();
            let message = &args[message_index + 1];
            
            match commit_tree(tree_sha, parent_sha, message) {
                Ok(commit_sha) => println!("{}", commit_sha),
                Err(e) => eprintln!("Error creating commit: {}", e),
            }
        }

        "clone" => {
            if args.len() < 3 {
                eprintln!("Usage: clone <repository> [<directory>]");
                return;
            }
            let repo_url = &args[2];
            let target_dir = args.get(3).cloned().unwrap_or_else(|| {
                let url = repo_url.trim_end_matches('/');
                url.split('/').last().unwrap_or("repo").to_string()
            });

            if let Err(e) = clone_repository(repo_url, &target_dir) {
                eprintln!("Failed to clone repository: {}", e);
            }
        }

        _ => {
            println!("unknown command: {}", args[1]);
        }
    }
}
    
// Function to convert a hex string to bytes
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for i in 0..(hex.len() / 2) {
        let b = u8::from_str_radix(&hex[i*2..i*2+2], 16).unwrap();
        bytes.push(b);
    }
    bytes
}


// Helper function to hash and write a blob
fn hash_object(path: &str, write: bool) -> Result<String, std::io::Error> {
    let content = fs::read(path)?;
    
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
    
    // Write to object store if requested
    if write {
        let dir_path = format!(".git/objects/{}", &hash_hex[..2]);
        let file_path = format!("{}/{}", dir_path, &hash_hex[2..]);
        
        // Create directory if it doesn't exist
        if !Path::new(&dir_path).exists() {
            fs::create_dir_all(&dir_path)?;
        }
        
        // Compress the blob with zlib
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&blob)?;
        let compressed = encoder.finish()?;
        
        // Write compressed blob to file
        fs::write(file_path, compressed)?;
    }
    
    Ok(hash_hex)
}

// Structure to represent a tree entry
struct TreeEntry {
    mode: String,
    name: String,
    sha: String,
}

// Function to recursively create a tree object
fn write_tree(dir_path: &str) -> Result<String, std::io::Error> {
    let mut entries = Vec::new();
    
    // Read directory contents
    for entry in fs::read_dir(dir_path)? {
        let entry = entry?;
        let path = entry.path();
        let file_name = entry.file_name().into_string().unwrap();
        
        // Skip .git directory
        if file_name == ".git" {
            continue;
        }
        
        let metadata = entry.metadata()?;
        let relative_path = if dir_path == "." {
            file_name.clone()
        } else {
            format!("{}/{}", dir_path, file_name)
        };
        
        if metadata.is_file() {
            // For files, create a blob object
            let sha = hash_object(&relative_path, true)?;
            entries.push(TreeEntry {
                mode: "100644".to_string(), // Regular file
                name: file_name,
                sha,
            });
        } else if metadata.is_dir() {
            // For directories, recursively create a tree object
            let sha = write_tree(&relative_path)?;
            entries.push(TreeEntry {
                mode: "40000".to_string(), // Directory
                name: file_name,
                sha,
            });
        }
    }
    
    // Sort entries by name (Git requires this)
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    
    // Construct tree content
    let mut tree_content = Vec::new();
    for entry in &entries {
        tree_content.extend_from_slice(format!("{} {}\0", entry.mode, entry.name).as_bytes());
        tree_content.extend_from_slice(&hex_to_bytes(&entry.sha));
    }
    
    // Create tree header
    let header = format!("tree {}\0", tree_content.len());
    
    // Combine header and content
    let mut tree_object = Vec::new();
    tree_object.extend_from_slice(header.as_bytes());
    tree_object.extend_from_slice(&tree_content);
    
    // Compute SHA-1 hash
    let mut hasher = Sha1::new();
    hasher.update(&tree_object);
    let hash = hasher.finalize();
    let hash_hex = format!("{:x}", hash);
    
    // Write tree object to .git/objects
    let dir_path = format!(".git/objects/{}", &hash_hex[..2]);
    let file_path = format!("{}/{}", dir_path, &hash_hex[2..]);
    
    // Create directory if it doesn't exist
    if !Path::new(&dir_path).exists() {
        fs::create_dir_all(&dir_path)?;
    }
    
    // Compress the tree with zlib
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tree_object)?;
    let compressed = encoder.finish()?;
    
    // Write compressed tree to file
    fs::write(file_path, compressed)?;
    
    Ok(hash_hex)
}

// Function to create a commit object
fn commit_tree(tree_sha: &str, parent_sha: &str, message: &str) -> Result<String, std::io::Error> {
    // Get current timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    // Hardcoded author and committer information
    let author = "Example Author <author@example.com>";
    let committer = "Example Committer <committer@example.com>";
    
    // Format the commit content with a newline after the message
    let commit_content = format!(
        "tree {}\nparent {}\nauthor {} {}\ncommitter {} {}\n\n{}\n",
        tree_sha,
        parent_sha,
        author,
        timestamp,
        committer,
        timestamp,
        message
    );
    
    // Create commit header
    let header = format!("commit {}\0", commit_content.len());
    
    // Combine header and content
    let mut commit_object = Vec::new();
    commit_object.extend_from_slice(header.as_bytes());
    commit_object.extend_from_slice(commit_content.as_bytes());
    
    // Compute SHA-1 hash
    let mut hasher = Sha1::new();
    hasher.update(&commit_object);
    let hash = hasher.finalize();
    let hash_hex = format!("{:x}", hash);
    
    // Write commit object to .git/objects
    let dir_path = format!(".git/objects/{}", &hash_hex[..2]);
    let file_path = format!("{}/{}", dir_path, &hash_hex[2..]);
    
    // Create directory if it doesn't exist
    if !Path::new(&dir_path).exists() {
        fs::create_dir_all(&dir_path)?;
    }
    
    // Compress the commit with zlib
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&commit_object)?;
    let compressed = encoder.finish()?;
    
    // Write compressed commit to file
    fs::write(file_path, compressed)?;
    
    Ok(hash_hex)
}

fn clone_repository(repo_url: &str, target_dir: &str) -> io::Result<()> {
    // Create target directory and initialize repository
    fs::create_dir_all(target_dir)?;
    env::set_current_dir(target_dir)?;
    fs::create_dir(".git")?;
    fs::create_dir(".git/objects")?;
    fs::create_dir(".git/refs")?;
    fs::write(".git/HEAD", "ref: refs/heads/main\n")?;

    // Fetch refs from info/refs
    let info_refs_url = format!("{}/info/refs?service=git-upload-pack", repo_url);
    let response = reqwest::blocking::get(&info_refs_url)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let body = response.text().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let (refs, head_symref) = parse_info_refs(&body);

    // Fetch packfile
    let upload_pack_url = format!("{}/git-upload-pack", repo_url);
    let request_body = build_upload_pack_request(&refs);
    let client = Client::new();
    let response = client.post(&upload_pack_url)
        .header("Content-Type", "application/x-git-upload-pack-request")
        .body(request_body)
        .send()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let packfile = response.bytes().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    // Process packfile with sideband handling
    let actual_packfile = parse_sideband_packets(&packfile)?;
   
    
    // Process packfile
    process_packfile(&actual_packfile)?;
    // Update refs and HEAD
    update_refs(&refs, head_symref)?;

    Ok(())
}

fn parse_info_refs(body: &str) -> (Vec<(String, String)>, Option<String>) {
    let mut refs = Vec::new();
    let mut head_symref = None;
    let lines = read_packet_lines(body.as_bytes());

    for line in lines.iter().skip(1) { // Skip service line and flush
        let line_str = String::from_utf8_lossy(line);
        if line_str.starts_with("symref=HEAD:") {
            head_symref = Some(line_str["symref=HEAD:".len()..].to_string());
            continue;
        }
        if let Some((oid, ref_name)) = line_str.split_once(' ') {
            let ref_name = ref_name.split('\0').next().unwrap();
            refs.push((oid.to_string(), ref_name.to_string()));
        }
    }

    (refs, head_symref)
}

fn read_packet_lines(data: &[u8]) -> Vec<Vec<u8>> {
    let mut lines = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        if pos + 4 > data.len() { break; }
        let len_str = match std::str::from_utf8(&data[pos..pos+4]) {
            Ok(s) => s,
            Err(_) => break,
        };
        let len = match u32::from_str_radix(len_str, 16) {
            Ok(l) => l as usize,
            Err(_) => break,
        };
        if len == 0 {
            pos += 4;
            break;
        }
        let end = pos + len;
        if end > data.len() { break; }
        lines.push(data[pos+4..end].to_vec());
        pos = end;
    }
    lines
}

fn read_be_u32(r: &mut Cursor<&[u8]>) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

fn read_object_header(r: &mut Cursor<&[u8]>) -> io::Result<(u8, usize, usize)> {
    let mut byte = [0u8];
    r.read_exact(&mut byte)?;
    let mut header = byte[0];
    let mut shift = 4;
    let mut obj_type = (header >> 4) & 0x07;
    let mut size = (header & 0x0F) as usize;
    let mut bytes_read = 1;

    while (header & 0x80) != 0 {
        r.read_exact(&mut byte)?;
        header = byte[0];
        size |= ((header & 0x7F) as usize) << shift;
        shift += 7;
        bytes_read += 1;
    }

    Ok((obj_type, size, bytes_read))
}

fn write_object_file(hash: &str, data: &[u8]) -> io::Result<()> {
    let dir = format!(".git/objects/{}", &hash[..2]);
    fs::create_dir_all(&dir)?;
    let path = format!("{}/{}", dir, &hash[2..]);
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    let compressed = encoder.finish()?;
    fs::write(path, compressed)
}

fn update_refs(refs: &[(String, String)], head_symref: Option<String>) -> io::Result<()> {
    if let Some(head) = head_symref {
        fs::write(".git/HEAD", format!("ref: {}\n", head))?;
    }

    for (oid, refname) in refs {
        if refname.starts_with("refs/heads/") {
            let path = format!(".git/{}", refname);
            fs::create_dir_all(Path::new(&path).parent().unwrap())?;
            fs::write(path, oid)?;
        } else if refname.starts_with("refs/tags/") {
            let path = format!(".git/{}", refname);
            fs::create_dir_all(Path::new(&path).parent().unwrap())?;
            fs::write(path, oid)?;
        }
    }

    Ok(())
}





// helo
fn parse_sideband_packets(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut cursor = Cursor::new(data);
    let mut actual_packfile = Vec::new();

    while cursor.position() < data.len() as u64 {
        let mut len_buf = [0u8; 4];
        cursor.read_exact(&mut len_buf)?;
        let len = match u32::from_str_radix(std::str::from_utf8(&len_buf).unwrap(), 16) {
            Ok(l) => l as usize,
            Err(_) => break, // Possibly encountered flush packet (0000)
        };

        if len == 0 {
            break; // Flush packet
        }

        if len < 4 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid packet length"));
        }

        let data_len = len - 4; // Subtract header length
        let mut packet_data = vec![0u8; data_len];
        cursor.read_exact(&mut packet_data)?;

        if packet_data.is_empty() {
            continue;
        }

        let band = packet_data[0];
        match band {
            1 => actual_packfile.extend_from_slice(&packet_data[1..]), // Skip band byte
            2 => eprint!("{}", String::from_utf8_lossy(&packet_data[1..])), // Progress messages
            3 => return Err(io::Error::new(io::ErrorKind::Other, 
                format!("Error: {}", String::from_utf8_lossy(&packet_data[1..])))),
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid sideband")),
        }
    }

    Ok(actual_packfile)
}

fn build_upload_pack_request(refs: &[(String, String)]) -> Vec<u8> {
    let mut body = Vec::new();
    let mut first_want = true;
    for (oid, _) in refs {
        let mut line = format!("want {}\n", oid);
        if first_want {
            line = format!("want {} side-band-64k agent=my-git-client\n", oid);
            first_want = false;
        }
        let pkt_line = format!("{:04x}{}", line.len() + 4, line);
        body.extend(pkt_line.as_bytes());
    }
    body.extend(b"0000"); // Flush after wants
    body.extend(b"0009done\n"); // "done" command in a pkt-line
    body.extend(b"0000"); // Final flush
    body
}

fn process_packfile(packfile: &[u8]) -> io::Result<()> {
    let mut cursor = Cursor::new(packfile);
    let mut header = [0u8; 4];
    cursor.read_exact(&mut header)?;
    if &header != b"PACK" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid packfile header"));
    }
    let version = read_be_u32(&mut cursor)?;
    if version != 2 && version != 3 {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "Unsupported packfile version"));
    }
    let num_objects = read_be_u32(&mut cursor)?;

    for _ in 0..num_objects {
        let (obj_type, obj_size, header_bytes) = read_object_header(&mut cursor)?;
        let compressed_start = cursor.position() as usize;
        let mut decoder = ZlibDecoder::new(&mut cursor);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)?;
        let compressed_end = cursor.position() as usize;

        match obj_type {
            1 | 2 | 3 | 4 => { // Commit, Tree, Blob, Tag
                let hash = Sha1::digest(&decompressed);
                write_object_file(&hex::encode(hash), &decompressed)?;
            }
            6 | 7 => { // OFS_DELTA, REF_DELTA (not implemented)
                return Err(io::Error::new(io::ErrorKind::Unsupported, "Delta objects not supported"));
            }
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid object type")),
        }

        cursor.set_position(compressed_end as u64);
    }

    // Read and verify packfile trailer (20-byte SHA-1)
    let mut trailer = [0u8; 20];
    cursor.read_exact(&mut trailer)?;

    Ok(())
}