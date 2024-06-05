// This program demonstrates the use of the `sha3_rust` crate to compute SHA3 hashes.
// It provides examples of hashing strings, files, multiple inputs, user passwords, and sensitive data securely.

// Import the required functions from the `sha3_rust` crate.
use sha3_rust::{sha3_224, sha3_256, sha3_384, sha3_512};

fn main() {
    // Example 1: Hashing a simple string
    // Create a string to hash.
    let input_str = "Hello, world!";
    // Compute the SHA3-256 hash of the string.
    let hash_256 = sha3_256(input_str.as_bytes());
    // Print the hash.
    println!("SHA3-256 hash of '{}': {:?}", input_str, hash_256);

    // Example 2: Hashing a file
    // Path to the file to hash.
    let file_path = "example.txt";
    // Read the contents of the file.
    let file_contents = std::fs::read(file_path).expect("Failed to read file");
    // Compute the SHA3-512 hash of the file.
    let hash_512 = sha3_512(&file_contents);
    // Print the hash.
    println!("SHA3-512 hash of file '{}': {:?}", file_path, hash_512);

    // Example 3: Hashing multiple inputs
    // An array of byte slices representing the inputs to hash.
    let inputs: [&[u8]; 3] = [&[1, 2, 3], &[4, 5, 6, 7], &[8, 9]];
    // Compute the SHA3-224 hash of each input.
    for input in &inputs {
        let hash = sha3_224(input);
        // Print the hash of each input.
        println!("SHA3-224 hash of {:?}: {:?}", input, hash);
    }

    // Example 4: Hashing user passwords
    // Password to hash.
    let user_password = "s3cr3t_p@ssw0rd";
    // Compute the SHA3-384 hash of the password.
    let hash_384 = sha3_384(user_password.as_bytes());
    // Print the hash.
    println!("SHA3-384 hash of user password: {:?}", hash_384);

    // Example 5: Hashing sensitive data securely
    // Sensitive data to hash.
    let sensitive_data = b"0123456789abcdef";
    // Compute the SHA3-256 hash of the sensitive data.
    let hash_256_secure = sha3_256(sensitive_data);
    // Print the hash.
    println!("Secure SHA3-256 hash of sensitive data: {:?}", hash_256_secure);
}

