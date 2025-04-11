#[allow(unused_imports)]
use std::env;
#[allow(unused_imports)]
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use std::io::{self, prelude::*, Cursor};
use std::collections::HashMap;

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use sha1::{Sha1, Digest};
use hex;
use reqwest;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Logs from your program will appear here!");

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Not enough arguments");
        return Ok(());
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
                return Ok(());
            }

            let content = fs::read(format!(".git/objects/{}/{}", &args[3][..2], &args[3][2..]))?;
            let mut z = ZlibDecoder::new(&content[..]);
            let mut s = String::new();
            z.read_to_string(&mut s)?;
            print!("{}", &s[8..]);
        }
        "hash-object" => {
            if args.len() < 3 {
                eprintln!("Not enough arguments for hash-object");
                return Ok(());
            }

            let write_object = args.contains(&"-w".to_string());
            let file_path = &args[args.len() - 1];

            let content = match fs::read(file_path) {
                Ok(content) => content,
                Err(e) => {
                    eprintln!("Failed to read file {}: {}", file_path, e);
                    return Ok(());
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
                    fs::create_dir_all(&dir_path)?;
                }

                let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(&blob)?;
                let compressed = encoder.finish()?;

                fs::write(file_path, compressed)?;
            }

            println!("{}", hash_hex);
        }
        "ls-tree" => {
            if args.len() < 4 || args[2] != "--name-only" {
                eprintln!("Usage: ls-tree --name-only <tree_sha>");
                return Ok(());
            }

            let sha = &args[3];
            let path = format!(".git/objects/{}/{}", &sha[..2], &sha[2..]);

            let content = fs::read(path)?;
            let mut decoder = ZlibDecoder::new(&content[..]);
            let mut decoded = Vec::new();
            decoder.read_to_end(&mut decoded)?;

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
            let tree_sha = write_tree(".")?;
            println!("{}", tree_sha);
        }
        "commit-tree" => {
            if args.len() < 6 {
                eprintln!("Usage: commit-tree <tree-sha> -p <parent-commit-sha> -m <message>");
                return Ok(());
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
                eprintln!("Usage: clone <repository-url> [directory]");
                return Ok(());
            }
            
            let repo_url = &args[2];
            let target_dir = if args.len() > 3 {
                &args[3]
            } else {
                // Extract repo name from URL
                let url_parts: Vec<&str> = repo_url.split('/').collect();
                let repo_name = url_parts.last().unwrap()
                    .strip_suffix(".git").unwrap_or(url_parts.last().unwrap());
                repo_name
            };
            
            clone_repository(repo_url, target_dir)?;
        }
        _ => {
            println!("unknown command: {}", args[1]);
        }
    }
    
    Ok(())
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
    
    // Format the commit content with a newline at the end of the message
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

// Parse the repository URL into components
fn parse_repo_url(url: &str) -> (String, String, String) {
    let url = url.trim_end_matches(".git");
    let parts: Vec<&str> = url.split('/').collect();
    let host = parts[2].to_string(); // e.g., github.com
    let owner = parts[3].to_string(); // e.g., username or organization
    let repo = parts[4].to_string(); // e.g., repo-name
    
    (host, owner, repo)
}

// Function to clone a Git repository
fn clone_repository(repo_url: &str, target_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Cloning {} into {}", repo_url, target_dir);
    
    // Create target directory if it doesn't exist
    fs::create_dir_all(target_dir)?;
    
    // Change to target directory
    std::env::set_current_dir(target_dir)?;
    
    // Initialize git repository
    fs::create_dir(".git")?;
    fs::create_dir_all(".git/objects")?;
    fs::create_dir_all(".git/refs/heads")?;
    fs::write(".git/HEAD", "ref: refs/heads/main\n")?;
    
    // Parse repository URL
    let (host, owner, repo) = parse_repo_url(repo_url);
    
    // First, get the refs from the remote repository
    let info_refs_url = format!("https://{}/{}/{}/info/refs?service=git-upload-pack", host, owner, repo);
    eprintln!("Fetching refs from {}", info_refs_url);
    
    let client = reqwest::blocking::Client::new();
    let response = client.get(&info_refs_url)
        .header("User-Agent", "git/codecrafters-git")
        .send()?;
    
    if !response.status().is_success() {
        return Err(format!("Failed to fetch refs: {}", response.status()).into());
    }
    
    let body = response.bytes()?;
    
    // Parse the info/refs response
    let mut lines = std::str::from_utf8(&body)?
        .lines()
        .collect::<Vec<&str>>();
    
    // Skip the first line (which is the service announcement)
    lines.remove(0);
    
    // Parse the refs
    let mut refs = HashMap::new();
    for line in lines {
        if line.starts_with("0000") || line.is_empty() {
            continue;
        }
        
        if line.len() < 4 {
            continue;
        }
        
        let line = &line[4..]; // Skip the 4-byte length prefix
        if line.starts_with("refs/") {
            let parts: Vec<&str> = line.split('\0').collect();
            if parts.len() >= 1 {
                let ref_parts: Vec<&str> = parts[0].split(' ').collect();
                if ref_parts.len() >= 2 {
                    let sha = ref_parts[0];
                    let refname = ref_parts[1];
                    refs.insert(refname.to_string(), sha.to_string());
                    eprintln!("Found ref: {} -> {}", refname, sha);
                }
            }
        }
    }
    
    // Get the main branch reference (HEAD)
    let head_ref = refs.get("HEAD").or_else(|| refs.get("refs/heads/main").or_else(|| refs.get("refs/heads/master")))
        .ok_or("No HEAD, main, or master reference found")?;
    
    eprintln!("Using HEAD reference: {}", head_ref);
    
    // Now, download the pack file
    let url = format!("https://{}/{}/{}/git-upload-pack", host, owner, repo);
    eprintln!("Requesting packfile from {}", url);
    
    // Prepare the request body for git-upload-pack
    let want_line = format!("want {}\n", head_ref);
    let request_body = format!("0032want {}\n00000009done\n", head_ref);
    
    // Send the request
    let response = client.post(&url)
        .header("Content-Type", "application/x-git-upload-pack-request")
        .header("User-Agent", "git/codecrafters-git")
        .body(request_body)
        .send()?;
    
    if !response.status().is_success() {
        return Err(format!("Failed to fetch pack: {}", response.status()).into());
    }
    
    let pack_data = response.bytes()?;
    eprintln!("Received {} bytes of pack data", pack_data.len());
    
    // Process the pack file
    let mut pack_cursor = Cursor::new(&pack_data[..]);
    
    // Skip the first line which contains the NAK
    let mut line = String::new();
    pack_cursor.read_line(&mut line)?;
    
    // Skip any additional header lines
    loop {
        line.clear();
        let bytes_read = pack_cursor.read_line(&mut line)?;
        if bytes_read <= 0 || line.trim().is_empty() || line.starts_with("PACK") {
            break;
        }
    }
    
    // Now we should be at the PACK header
    let mut header_buf = [0u8; 12];
    pack_cursor.read_exact(&mut header_buf)?;
    
    // Verify PACK signature
    if &header_buf[0..4] != b"PACK" {
        return Err("Invalid pack file (missing PACK signature)".into());
    }
    
    // Parse version and number of objects
    let version = u32::from_be_bytes([header_buf[4], header_buf[5], header_buf[6], header_buf[7]]);
    let num_objects = u32::from_be_bytes([header_buf[8], header_buf[9], header_buf[10], header_buf[11]]);
    
    eprintln!("Pack version: {}, contains {} objects", version, num_objects);
    
    // Process each object in the pack
    for i in 0..num_objects {
        eprintln!("Processing object {} of {}", i+1, num_objects);
        
        // Read object header
        let mut byte = [0u8; 1];
        pack_cursor.read_exact(&mut byte)?;
        
        // Extract object type and size from the header
        let type_id = (byte[0] >> 4) & 0x7;
        let mut size = (byte[0] & 0xF) as u64;
        let mut shift = 4;
        
        // Handle variable-length size encoding
        while byte[0] & 0x80 != 0 {
            pack_cursor.read_exact(&mut byte)?;
            size |= ((byte[0] & 0x7F) as u64) << shift;
            shift += 7;
        }
        
        // Determine object type
        let obj_type = match type_id {
            1 => "commit",
            2 => "tree",
            3 => "blob",
            4 => "tag",
            6 => "ofs-delta",
            7 => "ref-delta",
            _ => return Err(format!("Unknown object type: {}", type_id).into()),
        };
        
        eprintln!("Object type: {}, size: {}", obj_type, size);
        
        // Handle delta references if needed
        let base_obj_sha = if type_id == 7 { // ref-delta
            let mut sha_buf = [0u8; 20];
            pack_cursor.read_exact(&mut sha_buf)?;
            Some(hex::encode(&sha_buf))
        } else {
            None
        };
        
        // Read and decompress the object data
        let mut z = ZlibDecoder::new(pack_cursor.by_ref());
        let mut obj_data = Vec::new();
        let bytes_read = z.read_to_end(&mut obj_data)?;
        
        eprintln!("Read {} bytes of decompressed data", bytes_read);
        
        // Process the object based on its type
        match type_id {
            1 | 2 | 3 | 4 => { // commit, tree, blob, tag
                // Create header for the object
                let header = format!("{} {}\0", obj_type, obj_data.len());
                
                // Concatenate header and data
                let mut object = Vec::new();
                object.extend_from_slice(header.as_bytes());
                object.extend_from_slice(&obj_data);
                
                // Calculate SHA-1 hash
                let mut hasher = Sha1::new();
                hasher.update(&object);
                let hash = hasher.finalize();
                let hash_hex = format!("{:x}", hash);
                
                // Save object to .git/objects
                let dir_path = format!(".git/objects/{}", &hash_hex[..2]);
                let file_path = format!("{}/{}", dir_path, &hash_hex[2..]);
                
                if !Path::new(&dir_path).exists() {
                    fs::create_dir_all(&dir_path)?;
                }
                
                // Compress the object
                let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(&object)?;
                let compressed = encoder.finish()?;
                
                // Write compressed object to file
                fs::write(file_path, compressed)?;
                
                // If this is the HEAD commit, update the refs
                if hash_hex == *head_ref {
                    fs::create_dir_all(".git/refs/heads")?;
                    fs::write(".git/refs/heads/main", &hash_hex)?;
                }
            },
            6 | 7 => { // delta object
                eprintln!("Delta object, base: {:?}", base_obj_sha);
                // Handle delta objects (advanced, not implemented in basic clone)
                // This would require fetching the base object and applying the delta
            },
            _ => return Err(format!("Unexpected object type: {}", type_id).into()),
        }
    }
    
    // Update refs
    for (refname, sha) in &refs {
        if refname.starts_with("refs/heads/") {
            let parts: Vec<&str> = refname.split('/').collect();
            if parts.len() >= 3 {
                let branch = parts[2];
                fs::create_dir_all(".git/refs/heads")?;
                fs::write(format!(".git/refs/heads/{}", branch), sha)?;
            }
        }
    }
    
    // Write config
    let config = format!(
        "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote \"origin\"]\n\turl = {}\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
        repo_url
    );
    fs::create_dir_all(".git")?;
    fs::write(".git/config", config)?;
    
    // Checkout the working directory
    checkout_head()?;
    
    println!("Cloned repository: {}", repo_url);
    Ok(())
}

// Function to checkout files from HEAD into the working directory
fn checkout_head() -> Result<(), Box<dyn std::error::Error>> {
    // Read HEAD to find which branch we're on
    let head_content = fs::read_to_string(".git/HEAD")?;
    let head_ref = head_content.trim().strip_prefix("ref: ").unwrap_or(&head_content);
    
    // Get the commit SHA of the HEAD reference
    let head_sha = if head_ref != head_content {
        fs::read_to_string(format!(".git/{}", head_ref))?.trim().to_string()
    } else {
        head_content.trim().to_string()
    };
    
    eprintln!("Checking out commit: {}", head_sha);
    
    // Read the commit object to get the tree SHA
    let commit_path = format!(".git/objects/{}/{}", &head_sha[..2], &head_sha[2..]);
    let content = fs::read(&commit_path)?;
    
    let mut z = ZlibDecoder::new(&content[..]);
    let mut commit_content = String::new();
    z.read_to_string(&mut commit_content)?;
    
    // Parse the tree SHA from the commit
    let tree_line = commit_content.lines().next().unwrap();
    let tree_sha = tree_line.strip_prefix("tree ").unwrap();
    
    eprintln!("Checking out tree: {}", tree_sha);
    
    // Recursively checkout the tree
    checkout_tree(tree_sha, "")?;
    
    Ok(())
}

// Recursively checkout a tree object
fn checkout_tree(tree_sha: &str, prefix: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Read the tree object
    let tree_path = format!(".git/objects/{}/{}", &tree_sha[..2], &tree_sha[2..]);
    let content = fs::read(&tree_path)?;
    
    let mut z = ZlibDecoder::new(&content[..]);
    let mut tree_data = Vec::new();
    z.read_to_end(&mut tree_data)?;
    
    // Skip the header (find the null byte)
    let mut i = 0;
    while i < tree_data.len() && tree_data[i] != 0 {
        i += 1;
    }
    i += 1; // Skip the null byte
    
    // Process each entry in the tree
    while i < tree_data.len() {
        // Parse mode
        let mode_start = i;
        while tree_data[i] != b' ' {
            i += 1;
        }
        let mode = std::str::from_utf8(&tree_data[mode_start..i]).unwrap();
        i += 1; // Skip the space
        
        // Parse name
        let name_start = i;
        while tree_data[i] != 0 {
            i += 1;
        }
        let name = std::str::from_utf8(&tree_data[name_start..i]).unwrap();
        i += 1; // Skip the null byte
        
        // Parse SHA
        let sha_bytes = &tree_data[i..i+20];
        let sha = hex::encode(sha_bytes);
        i += 20;
        
        // Create the path
        let path = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{}/{}", prefix, name)
        };
        
        // Handle the entry based on its mode
        if mode.starts_with("100") { // Regular file
            // Read the blob
            let blob_path = format!(".git/objects/{}/{}", &sha[..2], &sha[2..]);
            let content = fs::read(&blob_path)?;
            
            let mut z = ZlibDecoder::new(&content[..]);
            let mut blob_data = Vec::new();
            z.read_to_end(&mut blob_data)?;
            
            // Skip the header
            let mut j = 0;
            while j < blob_data.len() && blob_data[j] != 0 {
                j += 1;
            }
            j += 1;
            
            // Ensure parent directories exist
            if let Some(parent) = Path::new(&path).parent() {
                fs::create_dir_all(parent)?;
            }
            
            // Write the file content
            fs::write(&path, &blob_data[j..])?;
        } else if mode.starts_with("40") { // Directory
            // Create directory if it doesn't exist
            fs::create_dir_all(&path)?;
            
            // Recursively checkout the subtree
            checkout_tree(&sha, &path)?;
        }
    }
    
    Ok(())
}

// Process delta objects in a packfile
fn apply_delta(base_data: &[u8], delta_data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut i = 0;
    
    // Skip base object size
    while i < delta_data.len() {
        let cmd = delta_data[i];
        i += 1;
        if cmd & 0x80 == 0 {
            break;
        }
    }
    
    // Skip result object size
    while i < delta_data.len() {
        let cmd = delta_data[i];
        i += 1;
        if cmd & 0x80 == 0 {
            break;
        }
    }
    
    let mut result = Vec::new();
    
    // Apply delta operations
    while i < delta_data.len() {
        let cmd = delta_data[i];
        i += 1;
        
        if cmd & 0x80 != 0 {
            // Copy from base object
            let mut offset = 0;
            let mut size = 0;
            
            if cmd & 0x01 != 0 {
                offset = delta_data[i] as usize;
                i += 1;
            }
            if cmd & 0x02 != 0 {
                offset |= (delta_data[i] as usize) << 8;
                i += 1;
            }
            if cmd & 0x04 != 0 {
                offset |= (delta_data[i] as usize) << 16;
                i += 1;
            }
            if cmd & 0x08 != 0 {
                offset |= (delta_data[i] as usize) << 24;
                i += 1;
            }
            
            if cmd & 0x10 != 0 {
                size = delta_data[i] as usize;
                i += 1;
            }
            if cmd & 0x20 != 0 {
                size |= (delta_data[i] as usize) << 8;
                i += 1;
            }
            if cmd & 0x40 != 0 {
                size |= (delta_data[i] as usize) << 16;
                i += 1;
            }
            
            if size == 0 {
                size = 0x10000;
            }
            
            // Copy bytes from base object
            if offset + size <= base_data.len() {
                result.extend_from_slice(&base_data[offset..offset + size]);
            } else {
                return Err("Invalid delta: out of bounds".into());
            }
        } else if cmd != 0 {
            // Insert new data
            let size = cmd as usize;
            if i + size <= delta_data.len() {
                result.extend_from_slice(&delta_data[i..i + size]);
                i += size;
            } else {
                return Err("Invalid delta: out of bounds".into());
            }
        } else {
            return Err("Invalid delta command".into());
        }
    }
    
    Ok(result)
}

// Function to read an object from the Git object store
fn read_object(sha: &str) -> Result<(String, Vec<u8>), Box<dyn std::error::Error>> {
    let path = format!(".git/objects/{}/{}", &sha[..2], &sha[2..]);
    let content = fs::read(&path)?;
    
    let mut z = ZlibDecoder::new(&content[..]);
    let mut decoded = Vec::new();
    z.read_to_end(&mut decoded)?;
    
    // Parse header (e.g., "blob 12345\0")
    let mut i = 0;
    let header_start = i;
    
    // Find the space separator
    while i < decoded.len() && decoded[i] != b' ' {
        i += 1;
    }
    
    if i >= decoded.len() {
        return Err("Invalid object header: no space found".into());
    }
    
    // Extract object type
    let obj_type = std::str::from_utf8(&decoded[header_start..i]).unwrap().to_string();
    i += 1; // Skip the space
    
    // Find the null terminator
    let size_start = i;
    while i < decoded.len() && decoded[i] != 0 {
        i += 1;
    }
    
    if i >= decoded.len() {
        return Err("Invalid object header: no null terminator found".into());
    }
    
    // Extract size (as string)
    let _size_str = std::str::from_utf8(&decoded[size_start..i]).unwrap();
    i += 1; // Skip the null terminator
    
    // The rest is the object data
    let data = decoded[i..].to_vec();
    
    Ok((obj_type, data))
}

// Improved clone_repository function with delta object handling
fn clone_repository(repo_url: &str, target_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Cloning {} into {}", repo_url, target_dir);
    
    // Create target directory if it doesn't exist
    fs::create_dir_all(target_dir)?;
    
    // Change to target directory
    std::env::set_current_dir(target_dir)?;
    
    // Initialize git repository
    fs::create_dir(".git")?;
    fs::create_dir_all(".git/objects")?;
    fs::create_dir_all(".git/refs/heads")?;
    fs::write(".git/HEAD", "ref: refs/heads/main\n")?;
    
    // Parse repository URL
    let (host, owner, repo) = parse_repo_url(repo_url);
    
    // First, get the refs from the remote repository
    let info_refs_url = format!("https://{}/{}/{}/info/refs?service=git-upload-pack", host, owner, repo);
    eprintln!("Fetching refs from {}", info_refs_url);
    
    let client = reqwest::blocking::Client::new();
    let response = client.get(&info_refs_url)
        .header("User-Agent", "git/codecrafters-git")
        .send()?;
    
    if !response.status().is_success() {
        return Err(format!("Failed to fetch refs: {}", response.status()).into());
    }
    
    let body = response.bytes()?;
    
    // Skip the first line which contains pkt-line length and service announcement
    let mut lines = Vec::new();
    let mut i = 0;
    
    while i < body.len() {
        // Read pkt-line length
        if i + 4 > body.len() {
            break;
        }
        
        let mut len_hex = [0u8; 4];
        len_hex.copy_from_slice(&body[i..i+4]);
        let len_str = std::str::from_utf8(&len_hex).unwrap();
        
        if len_str == "0000" {
            i += 4; // Skip flush packet
            continue;
        }
        
        let len = usize::from_str_radix(len_str, 16).unwrap();
        if len < 4 || i + len > body.len() {
            break;
        }
        
        // Extract line without the length prefix
        let line = &body[i+4..i+len];
        let line_str = std::str::from_utf8(line).unwrap_or("").trim_end();
        
        if !line_str.is_empty() && !line_str.starts_with("# ") {
            lines.push(line_str.to_string());
        }
        
        i += len;
    }
    
    // Parse the refs
    let mut refs = HashMap::new();
    for line in &lines {
        if line.starts_with("refs/") || line.contains("refs/") {
            let parts: Vec<&str> = line.split(' ').collect();
            if parts.len() >= 2 {
                let sha = parts[0];
                let refname = parts[1].split('\0').next().unwrap_or(parts[1]);
                refs.insert(refname.to_string(), sha.to_string());
                eprintln!("Found ref: {} -> {}", refname, sha);
            }
        }
    }
    
    // Get the main branch reference (HEAD)
    let head_ref = refs.get("HEAD")
        .or_else(|| refs.get("refs/heads/main"))
        .or_else(|| refs.get("refs/heads/master"))
        .or_else(|| {
            // If no HEAD/main/master, use the first branch we find
            refs.iter()
                .find(|(k, _)| k.starts_with("refs/heads/"))
                .map(|(_, v)| v)
        })
        .ok_or("No branch reference found")?;
    
    eprintln!("Using reference: {}", head_ref);
    
    // Now, download the pack file
    let url = format!("https://{}/{}/{}/git-upload-pack", host, owner, repo);
    eprintln!("Requesting packfile from {}", url);
    
    // Prepare the request body for git-upload-pack
    let mut request_body = String::new();
    request_body.push_str(&format!("0032want {}\n", head_ref));
    request_body.push_str("00000009done\n");
    
    // Send the request
    let response = client.post(&url)
        .header("Content-Type", "application/x-git-upload-pack-request")
        .header("User-Agent", "git/codecrafters-git")
        .body(request_body)
        .send()?;
    
    if !response.status().is_success() {
        return Err(format!("Failed to fetch pack: {}", response.status()).into());
    }
    
    let pack_data = response.bytes()?;
    eprintln!("Received {} bytes of pack data", pack_data.len());
    
    // Process the pack file
    let mut pack_cursor = Cursor::new(&pack_data[..]);
    
    // Skip the protocol response lines (pkt-lines)
    let mut line = String::new();
    loop {
        line.clear();
        let bytes_read = pack_cursor.read_line(&mut line)?;
        if bytes_read == 0 || line.trim().is_empty() {
            break;
        }
        
        // We've found the PACK header line, go back to the beginning of it
        if line.starts_with("PACK") {
            pack_cursor.set_position(pack_cursor.position() - line.len() as u64);
            break;
        }
    }
    
    // Now we should be at the PACK header
    let mut header_buf = [0u8; 12];
    pack_cursor.read_exact(&mut header_buf)?;
    
    // Verify PACK signature
    if &header_buf[0..4] != b"PACK" {
        return Err("Invalid pack file (missing PACK signature)".into());
    }
    
    // Parse version and number of objects
    let version = u32::from_be_bytes([header_buf[4], header_buf[5], header_buf[6], header_buf[7]]);
    let num_objects = u32::from_be_bytes([header_buf[8], header_buf[9], header_buf[10], header_buf[11]]);
    
    eprintln!("Pack version: {}, contains {} objects", version, num_objects);
    
    // Store delta objects for later processing
    let mut delta_objects = Vec::new();
    
    // Process each object in the pack
    for i in 0..num_objects {
        eprintln!("Processing object {} of {}", i+1, num_objects);
        
        // Read object header
        let mut byte = [0u8; 1];
        pack_cursor.read_exact(&mut byte)?;
        
        // Extract object type and size from the header
        let type_id = (byte[0] >> 4) & 0x7;
        let mut size = (byte[0] & 0xF) as u64;
        let mut shift = 4;
        
        // Handle variable-length size encoding
        while byte[0] & 0x80 != 0 {
            pack_cursor.read_exact(&mut byte)?;
            size |= ((byte[0] & 0x7F) as u64) << shift;
            shift += 7;
        }
        
        // Determine object type
        let obj_type = match type_id {
            1 => "commit",
            2 => "tree",
            3 => "blob",
            4 => "tag",
            6 => "ofs-delta",
            7 => "ref-delta",
            _ => return Err(format!("Unknown object type: {}", type_id).into()),
        };
        
        eprintln!("Object type: {}, size: {}", obj_type, size);
        
        // Handle delta references
        let base_obj_sha = if type_id == 7 { // ref-delta
            let mut sha_buf = [0u8; 20];
            pack_cursor.read_exact(&mut sha_buf)?;
            Some(hex::encode(&sha_buf))
        } else {
            None
        };
        
        // Save the current position for calculating how many bytes we've read
        let pos_before = pack_cursor.position();
        
        // Read and decompress the object data
        let mut z = ZlibDecoder::new(pack_cursor.by_ref());
        let mut obj_data = Vec::new();
        z.read_to_end(&mut obj_data)?;
        
        let pos_after = pack_cursor.position();
        eprintln!("Read {} compressed bytes, {} decompressed bytes", 
                 pos_after - pos_before, obj_data.len());
        
        // Process the object based on its type
        match type_id {
            1 | 2 | 3 | 4 => { // commit, tree, blob, tag
                // Create header for the object
                let header = format!("{} {}\0", obj_type, obj_data.len());
                
                // Concatenate header and data
                let mut object = Vec::new();
                object.extend_from_slice(header.as_bytes());
                object.extend_from_slice(&obj_data);
                
                // Calculate SHA-1 hash
                let mut hasher = Sha1::new();
                hasher.update(&object);
                let hash = hasher.finalize();
                let hash_hex = format!("{:x}", hash);
                
                // Save object to .git/objects
                let dir_path = format!(".git/objects/{}", &hash_hex[..2]);
                let file_path = format!("{}/{}", dir_path, &hash_hex[2..]);
                
                if !Path::new(&dir_path).exists() {
                    fs::create_dir_all(&dir_path)?;
                }
                
                // Compress the object
                let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(&object)?;
                let compressed = encoder.finish()?;
                
                // Write compressed object to file
                fs::write(file_path, compressed)?;
                
                // If this is the HEAD commit, update the refs
                if hash_hex == *head_ref {
                    fs::create_dir_all(".git/refs/heads")?;
                    fs::write(".git/refs/heads/main", &hash_hex)?;
                }
            },
            6 | 7 => { // delta object
                // Store delta objects for later processing
                delta_objects.push((type_id, base_obj_sha, obj_data));
            },
            _ => return Err(format!("Unexpected object type: {}", type_id).into()),
        }
    }
    
    // Process delta objects (now that we have all base objects)
    for (type_id, base_sha_opt, delta_data) in delta_objects {
        match type_id {
            7 => { // ref-delta
                if let Some(base_sha) = base_sha_opt {
                    eprintln!("Processing ref-delta with base {}", base_sha);
                    
                    // Read the base object
                    let (obj_type, base_data) = read_object(&base_sha)?;
                    
                    // Apply the delta
                    let result_data = apply_delta(&base_data, &delta_data)?;
                    
                    // Create header for the object
                    let header = format!("{} {}\0", obj_type, result_data.len());
                    
                    // Concatenate header and data
                    let mut object = Vec::new();
                    object.extend_from_slice(header.as_bytes());
                    object.extend_from_slice(&result_data);
                    
                    // Calculate SHA-1 hash
                    let mut hasher = Sha1::new();
                    hasher.update(&object);
                    let hash = hasher.finalize();
                    let hash_hex = format!("{:x}", hash);
                    
                    // Save object to .git/objects
                    let dir_path = format!(".git/objects/{}", &hash_hex[..2]);
                    let file_path = format!("{}/{}", dir_path, &hash_hex[2..]);
                    
                    if !Path::new(&dir_path).exists() {
                        fs::create_dir_all(&dir_path)?;
                    }
                    
                    // Compress the object
                    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
                    encoder.write_all(&object)?;
                    let compressed = encoder.finish()?;
                    
                    // Write compressed object to file
                    fs::write(file_path, compressed)?;
                }
            },
            6 => { // ofs-delta
                eprintln!("Offset deltas not implemented");
                // Not implementing offset deltas for this basic clone
            },
            _ => unreachable!(),
        }
    }
    
    // Update refs
    for (refname, sha) in &refs {
        if refname.starts_with("refs/heads/") {
            let parts: Vec<&str> = refname.split('/').collect();
            if parts.len() >= 3 {
                let branch = parts[2];
                fs::create_dir_all(".git/refs/heads")?;
                fs::write(format!(".git/refs/heads/{}", branch), sha)?;
            }
        }
    }
    
    // Write config
    let config = format!(
        "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote \"origin\"]\n\turl = {}\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
        repo_url
    );
    fs::create_dir_all(".git")?;
    fs::write(".git/config", config)?;
    
    // Checkout the working directory
    checkout_head()?;
    
    println!("Cloned repository: {}", repo_url);
    Ok(())
}

// Enhanced version of checkout_tree with proper handling for executable files
fn checkout_tree(tree_sha: &str, prefix: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Read the tree object
    let tree_path = format!(".git/objects/{}/{}", &tree_sha[..2], &tree_sha[2..]);
    let content = fs::read(&tree_path)?;
    
    let mut z = ZlibDecoder::new(&content[..]);
    let mut tree_data = Vec::new();
    z.read_to_end(&mut tree_data)?;
    
    // Skip the header (find the null byte)
    let mut i = 0;
    while i < tree_data.len() && tree_data[i] != 0 {
        i += 1;
    }
    i += 1; // Skip the null byte
    
    // Process each entry in the tree
    while i < tree_data.len() {
        // Parse mode
        let mode_start = i;
        while i < tree_data.len() && tree_data[i] != b' ' {
            i += 1;
        }
        
        if i >= tree_data.len() {
            break;
        }
        
        let mode = std::str::from_utf8(&tree_data[mode_start..i]).unwrap();
        i += 1; // Skip the space
        
        // Parse name
        let name_start = i;
        while i < tree_data.len() && tree_data[i] != 0 {
            i += 1;
        }
        
        if i >= tree_data.len() {
            break;
        }
        
        let name = std::str::from_utf8(&tree_data[name_start..i]).unwrap();
        i += 1; // Skip the null byte
        
        // Parse SHA (20 bytes)
        if i + 20 > tree_data.len() {
            break;
        }
        
        let sha_bytes = &tree_data[i..i+20];
        let sha = hex::encode(sha_bytes);
        i += 20;
        
        // Create the path
        let path = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{}/{}", prefix, name)
        };
        
        // Handle the entry based on its mode
        if mode.starts_with("100") { // Regular file
            // Read the blob
            let blob_path = format!(".git/objects/{}/{}", &sha[..2], &sha[2..]);
            let content = fs::read(&blob_path)?;
            
            let mut z = ZlibDecoder::new(&content[..]);
            let mut blob_data = Vec::new();
            z.read_to_end(&mut blob_data)?;
            
            // Skip the header
            let mut j = 0;
            while j < blob_data.len() && blob_data[j] != 0 {
                j += 1;
            }
            j += 1;
            
            // Ensure parent directories exist
            if let Some(parent) = Path::new(&path).parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            
            // Write the file content
            fs::write(&path, &blob_data[j..])?;
            
            // Set executable permission if needed
            #[cfg(unix)]
            if mode == "100755" {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(&path)?.permissions();
                perms.set_mode(0o755);
                fs::set_permissions(&path, perms)?;
            }
        } else if mode.starts_with("40") { // Directory
            // Create directory if it doesn't exist
            fs::create_dir_all(&path)?;
            
            // Recursively checkout the subtree
            checkout_tree(&sha, &path)?;
        } else if mode.starts_with("120") { // Symlink
            // Read the blob containing the link target
            let blob_path = format!(".git/objects/{}/{}", &sha[..2], &sha[2..]);
            let content = fs::read(&blob_path)?;
            
            let mut z = ZlibDecoder::new(&content[..]);
            let mut blob_data = Vec::new();
            z.read_to_end(&mut blob_data)?;
            
            // Skip the header
            let mut j = 0;
            while j < blob_data.len() && blob_data[j] != 0 {
                j += 1;
            }
            j += 1;
            
            let link_target = std::str::from_utf8(&blob_data[j..]).unwrap();
            
            // Ensure parent directories exist
            if let Some(parent) = Path::new(&path).parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            
            // Create symlink (platform-specific)
            #[cfg(unix)]
            {
                use std::os::unix::fs;
                fs::symlink(link_target, &path)?;
            }
            
            // On Windows, just create a regular file with the target path
            #[cfg(not(unix))]
            {
                fs::write(&path, link_target.as_bytes())?;
            }
        }
    }
    
    Ok(())
}

// Improved function to parse the git protocol length-prefixed packets
fn parse_pkt_line(data: &[u8], offset: usize) -> Result<(usize, Option<&[u8]>), Box<dyn std::error::Error>> {
    if offset + 4 > data.len() {
        return Err("Invalid packet: too short".into());
    }
    
    let len_hex = std::str::from_utf8(&data[offset..offset+4])?;
    
    // Flush packet
    if len_hex == "0000" {
        return Ok((offset + 4, None));
    }
    
    // Parse length
    let len = usize::from_str_radix(len_hex, 16)?;
    if len < 4 {
        return Err("Invalid packet: length too small".into());
    }
    
    if offset + len > data.len() {
        return Err("Invalid packet: not enough data".into());
    }
    
    Ok((offset + len, Some(&data[offset+4..offset+len])))
}