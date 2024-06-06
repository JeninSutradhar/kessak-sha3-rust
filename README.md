# Keccak's Sha3 Rust 

This crate provides an implementation of the Keccak (SHA-3) cryptographic hash function family.

## Overview

The Sha3 crate is a Rust library that implements the Keccak (SHA-3) cryptographic hash function family. It offers several hash functions with different output lengths, including 224, 256, 384, and 512 bits. These hash functions are created using the `sha3!` macro, which defines the hash function with a specific output length. The crate also provides utility functions for converting bytes to bits and vice versa, which are used internally by the hash functions.

## Features

- **Implementation of SHA-3 Hash Functions**: The crate offers hash functions with different output lengths, making it suitable for various cryptographic applications.
- **Flexible Input Handling**: The hash functions accept byte slices as input, allowing you to hash strings, files, or any other binary data.
- **Customizable Padding and Sponge Functions**: The crate includes utility functions for padding input data and implementing sponge constructions, providing flexibility in cryptographic protocols.

## Usage

To use this crate in your Rust project, add the following line to your `Cargo.toml` file:

```toml
[dependencies]
sha3-rust = "0.1.1"
```

Then, in your Rust code, you can import and use the SHA-3 hash functions as follows:

```rust
use sha3_rust::*;

fn main() {
    let input = "Hello, world!";
    let hash = sha3_256(input.as_bytes());
    println!("SHA3-256 hash of '{}': {:?}", input, hash);
}
```
- output:
```bash
SHA3-256 hash of 'Hello, world!': [172, 79, 176, 238 ... 139, 93, 150]
```
## More use cases
- **Example 1:** Hashing a simple string
```rust
    // Create a string to hash.
    let input_str = "Hello, world!";
    // Compute the SHA3-256 hash of the string.
    let hash_256 = sha3_256(input_str.as_bytes());

    println!("SHA3-256 hash of '{}': {:?}", input_str, hash_256);
```

- **Example 2:** Hashing a file
```rust
    // Path to the file to hash.
    let file_path = "example.txt";
    // Read the contents of the file.
    let file_contents = std::fs::read(file_path).expect("Failed to read file");
    // Compute the SHA3-512 hash of the file.
    let hash_512 = sha3_512(&file_contents);

    println!("SHA3-512 hash of file '{}': {:?}", file_path, hash_512);
```

- **Example 3:** Hashing multiple inputs
```rust
    // An array of byte slices representing the inputs to hash.
    let inputs: [&[u8]; 3] = [&[1, 2, 3], &[4, 5, 6, 7], &[8, 9]];
    // Compute the SHA3-224 hash of each input.
    for input in &inputs {
        let hash = sha3_224(input);
        // Print the hash of each input.
        println!("SHA3-224 hash of {:?}: {:?}", input, hash);
    }
```

- **Example 4:** Hashing user passwords
```rust
    // Password to hash.
    let user_password = "s3cr3t_p@ssw0rd";
    // Compute the SHA3-384 hash of the password.
    let hash_384 = sha3_384(user_password.as_bytes());

    println!("SHA3-384 hash of user password: {:?}", hash_384);
```

- **Example 5:** Hashing sensitive data securely
```rust
    // Sensitive data to hash.
    let sensitive_data = b"0123456789abcdef";
    // Compute the SHA3-256 hash of the sensitive data.
    let hash_256_secure = sha3_256(sensitive_data);

    println!("Secure SHA3-256 hash of sensitive data: {:?}", hash_256_secure);
```

## Code Explanation

The crate's codebase consists of various functions and macros that implement the Keccak permutation and the SHA-3 hash functions. Here's a brief explanation of some key components:

- **State Representation**: The `State` type represents the state array used in the Keccak permutation. It is a 3-dimensional array of boolean values.
- **Round Functions**: Functions like `theta`, `rho`, `pi`, `chi`, and `iota` implement the different steps of the Keccak permutation, as specified in the SHA-3 standard.
- **Round Constants**: The `rc` function calculates the round constants used in the `iota` step of the permutation.
- **Round Function Application**: The `round` function applies a single round of the Keccak permutation.
- **Sponge Construction**: The `sponge` function implements the sponge construction used in the Keccak hash function. It takes a sponge function `f`, a padding function `pad`, a block size `r`, an input `n`, and a desired output size `d`.
- **Padding Functions**: The `pad101` function implements the padding scheme specified in the Keccak specification.
- **Hash Functions**: The `sha3!` macro defines SHA-3 hash functions with different output lengths, using the sponge construction and padding functions.

## Extra Use Cases

In addition to hashing strings and files, the Sha3 crate can be used in various cryptographic applications, such as:

- **Password Hashing**: Securely hash user passwords using SHA-3-384 or SHA-3-512 to protect sensitive user data.
- **Data Integrity Verification**: Compute hashes of data to verify its integrity during transmission or storage.
- **Digital Signatures**: Use SHA-3 hashes as part of digital signature schemes to ensure data authenticity and integrity.
- **Key Derivation**: Derive cryptographic keys from hashed data for use in key-based encryption schemes.
- **Blockchain**: Compute hashes of block data in blockchain applications to ensure immutability and integrity of the blockchain ledger.

## Contributing

Contributions are welcome! If you encounter any bugs or have suggestions for improvements, please open an issue or submit a pull request on [GitHub](https://github.com/example/sha3).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

- crates: https://crates.io/crates/sha3-rust
