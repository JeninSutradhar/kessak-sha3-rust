/// This crate provides an implementation of the Keccak (SHA-3) cryptographic hash function family.
/// 
/// # Simple Overview of the Sha3 Program
/// 
/// The Sha3 program is a Rust crate that provides an implementation of the Keccak (SHA-3)
/// cryptographic hash function family. The crate provides several Hash functions with
/// different output lengths (224, 256, 384, 512 bits). The hash functions are created using
/// the macro `sha3!`, which defines the Hash function with a specific output length.
/// The Hash functions are exported from the crate as public functions and can be used
/// in any Rust program.
///
/// The Hash functions take a byte slice as input and return a fixed-size array containing
/// the hash output. The hash functions can be used to hash strings, files, or any other
/// binary data.
///
/// The crate also provides utility functions to convert bytes to bits and vice versa.
/// These functions are used internally by the Hash functions but can also be used by
/// other parts of the program if needed.
///
/// The crate uses the Keccak permutation, which is the core of the SHA-3 algorithm.
/// The Keccak permutation is a sponge function that can be used to transform any
/// input data of any length into a fixed-size output. The crate defines the Keccak
/// permutation as a macro that can be used to create other sponge functions.
///
/// The crate also provides some example code in the `main.rs` file that demonstrates
/// how to use the Hash functions to hash strings, files, and multiple inputs.
///

use std::convert::TryInto;

/// The width of the Keccak permutation (1600 bits).
const B: usize = 1600;

/// The lane size (64 bits).
const W: usize = B / 25;

/// The number of rounds.
///
/// The number of rounds is calculated using the number of trailing zeros in the binary
/// representation of `B`. This ensures that the number of rounds is correct for the
/// specific Keccak permutation.
const L: usize = W.trailing_zeros() as usize;

/// Number of bits in a byte.
///
/// This constant is used to calculate the number of rounds in the Keccak permutation.
const U8BITS: usize = u8::BITS as usize;

/// A macro to iterate over the state array.
///
/// This macro is used to iterate over the state array in the Keccak permutation. It
/// allows for more concise code when performing operations on the state array. The macro
/// takes three identifiers `$x`, `$y`, and `$z` which represent the indices of the state
/// array. The body of the macro is executed for each iteration.
#[macro_export]
macro_rules! iterate {
    // The macro takes a pattern consisting of three identifiers and a block of code.
    ($x:ident, $y:ident, $z:ident => $body:block) => {
        // The macro iterates over the indices of the state array.
        for $y in 0..5 {
            for $x in 0..5 {
                for $z in 0..W {
                    // The code block is executed for each iteration.
                    $body
                }
            }
        }
    };
}

/// Type definition for padding functions.
type PadFn = fn(isize, isize) -> Vec<bool>;

/// Type definition for sponge functions.
type SpongeFn = fn(&[bool]) -> [bool; B];

/// The state of the Keccak permutation.
type State = [[[bool; W]; 5]; 5];

/// Creates a new state filled with `false`.
fn new_state() -> State {
    [[[false; W]; 5]; 5]
}

/// Fills the state array with the provided bits.
fn fill_state(state: &mut State, bits: &[bool]) {
    let mut i = 0usize;
    iterate!(x, y, z => {
        if i >= bits.len() {
            return;
        }
        state[x][y][z] = bits[i];
        i += 1;
    });
}

/// Copies the state from `src` to `dest`.
fn copy_state(dest: &mut State, src: &State) {
    iterate!(x, y, z => {
        dest[x][y][z] = src[x][y][z];
    });
}

/// Dumps the state array into a single array of bits.
///
/// # Returns
///
/// A vector of boolean values representing the state array.
fn dump_state(state: State) -> [bool; B] {
    let mut bits = [false; B];
    let mut i = 0usize;
    // Iterate over each element in the state array and assign it to the corresponding
    // element in the bits vector.
    iterate!(x, y, z => {
        if i >= bits.len() {
            return bits;
        }
        bits[i] = state[x][y][z];
        i += 1;
    });
    bits
}

/// The theta step mapping of Keccak.
///
/// This function computes the parity for each column in the state array and then
/// computes the intermediate array `d` by performing XOR operations on the elements
/// of the state array. Finally, it modifies the state array by performing XOR operations
/// on the elements of the `d` array.
fn theta(state: &mut State) {
    let mut c = [[false; W]; 5];
    let mut d = [[false; W]; 5];

    // Compute parity for each column
    for x in 0..5 {
        for z in 0..W {
            c[x][z] = state[x][0][z];
            for y in 1..5 {
                c[x][z] ^= state[x][y][z];
            }
        }
    }

    // Compute the intermediate array `d`
    for x in 0..5 {
        for z in 0..W {
            let x1 = (x + 4) % 5;
            let z2 = (z + W - 1) % W;
            d[x][z] = c[x1][z] ^ c[(x + 1) % 5][z2];
        }
    }

    // Modify the state with `d`
    iterate!(x, y, z => {
        state[x][y][z] ^= d[x][z];
    });
}

/// The rho step mapping of Keccak.
///
/// This function performs the permutation of the remaining bits in the state array.
/// It copies the bit from state`[0][0]` directly and performs permutation of the remaining
/// bits.
fn rho(state: &mut State) {
    let mut new_state = new_state();

    // Copy the bit from state[0][0] directly
    for z in 0..W {
        new_state[0][0][z] = state[0][0][z];
    }

    let mut x = 1;
    let mut y = 0;

    // Permutation of the remaining bits
    for t in 0..24 {
        for z in 0..W {
            let new_z = (z + (t * (t + 1)) / 2) % W;
            new_state[x][y][z] = state[x][y][new_z];
        }
        let (new_x, new_y) = (y, (2 * x + 3 * y) % 5);
        x = new_x;
        y = new_y;
    }

    copy_state(state, &new_state);
}

/// The pi step mapping of Keccak.
///
/// This function performs the permutation of the state array by swapping the elements
/// of the state array based on the given indices.
fn pi(state: &mut State) {
    let mut new_state = new_state();
    iterate!(x, y, z => {
        new_state[x][y][z] = state[(x + 3 * y) % 5][x][z];
    });
    copy_state(state, &new_state);
}

/// The chi step mapping of Keccak.
///
/// This function performs the permutation of the state array by performing XOR operations
/// on the elements of the state array.
fn chi(state: &mut State) {
    let mut new_state = new_state();
    iterate!(x, y, z => {
        new_state[x][y][z] = state[x][y][z] ^ ((!state[(x + 1) % 5][y][z]) & state[(x + 2) % 5][y][z]);
    });
    copy_state(state, &new_state);
}

/// The iota step mapping of Keccak, incorporating the round constants.
///
/// This function performs the XOR operation between the state array and the round constants.
fn iota(state: &mut State, round_index: u8) {
    let mut rc_arr = [false; W];
    for j in 0..=L {
        rc_arr[(1 << j) - 1] = rc(j as u8 + 7 * round_index);
    }
    for (z, bit) in rc_arr.iter().enumerate() {
        state[0][0][z] ^= *bit;
    }
}

/// Computes the round constants for the iota step.
///
/// This function computes the round constants for the iota step by performing a series
/// of bitwise operations.
fn rc(t: u8) -> bool {
    let mut r: u16 = 0x80;
    for _ in 0..(t % 255) {
        r = ((r << 1) ^ ((r >> 7) & 1) * 0x71) & 0xff;
    }
    (r >> 7) & 1 != 0
}

/// Performs a single round of the Keccak-f permutation.
///
/// This function performs a single round of the Keccak-f permutation by calling the
/// theta, rho, pi, chi, and iota steps.
fn round(state: &mut State, round_index: u8) {
    theta(state);
    rho(state);
    pi(state);
    chi(state);
    iota(state, round_index);
}

/// The Keccak-f permutation function.
///
/// This function performs the Keccak-f permutation on the given input bits.
/// It applies `num_rounds` rounds of the Keccak-f permutation, where
/// `num_rounds` is calculated based on the number of rounds used in the
/// Keccak hash function family.
///
/// # Arguments
///
/// * `bits` - A slice of boolean values representing the input bits.
///
/// # Returns
///
/// A vector of boolean values representing the output of the Keccak-f
/// permutation.
fn keccak_f(bits: &[bool]) -> [bool; B] {
    // Calculate the number of rounds to be applied
    let num_rounds = 12 + 2 * L;

    // Create a new state array and fill it with the input bits
    let mut state = new_state();
    fill_state(&mut state, bits);

    // Apply the Keccak-f permutation
    for i in 0..num_rounds {
        round(&mut state, i as u8);
    }

    // Dump the state array into a single array of bits
    dump_state(state)
}

/// Pads the input with the `101` pattern according to Keccak specifications.
fn pad101(x: isize, m: isize) -> Vec<bool> {
    let j = (x - (m % x) - 2).rem_euclid(x);
    let mut padding = vec![false; (j + 2) as usize];
    padding[0] = true;
    padding[j as usize + 1] = true;
    padding
}

/// The sponge construction used in Keccak.
///
/// This function implements the sponge construction used in the Keccak hash function.
/// It takes as input a sponge function `f`, a padding function `pad`, a block size `r`,
/// an input `n`, and a desired output size `d`. It then iteratively applies the sponge
/// construction to the input until the desired output size is reached.
///
/// # Arguments
///
/// * `f` - The sponge function to be used.
/// * `pad` - The padding function to be used.
/// * `r` - The block size of the sponge function.
/// * `n` - The input to be processed.
/// * `d` - The desired output size.
///
/// # Returns
///
/// A vector of boolean values representing the output of the sponge construction.
fn sponge(f: SpongeFn, pad: PadFn, r: usize, n: &[bool], d: usize) -> Vec<bool> {
    // Create a new vector `p` by extending `n` with the result of applying the padding function
    let mut p = Vec::from(n);
    p.append(&mut pad(r as isize, n.len() as isize));
    assert!(r < B);

    // Create a new state `s`
    let mut s = [false; B];

    // Iterate over the chunks of `p` of size `r`
    for chunk in p.chunks(r) {
        // XOR each element of `s` with the corresponding element of `chunk`
        for (s_i, c_i) in s.iter_mut().zip(chunk) {
            *s_i ^= *c_i;
        }
        // Apply the sponge function `f` to `s`
        s = f(&s);
    }

    // Create an empty vector `z`
    let mut z = Vec::new();
    // Repeat the following process until `z` has a length of `d`
    while z.len() < d {
        // Extend `z` with the elements of `s`
        z.extend_from_slice(&s);
        // Apply the sponge function `f` to `s`
        s = f(&s);
    }

    // Truncate `z` to a length of `d`
    z.truncate(d);
    // Return `z`
    z
}

/// The Keccak hash function.
fn keccak(c: usize, n: &[bool], d: usize) -> Vec<bool> {
    sponge(keccak_f, pad101, B - c, n, d)
}

/// Converts a byte array to a bit array.
///
/// # Arguments
///
/// * `h` - The byte array to convert.
/// * `n` - The number of bits to take from the byte array.
///
/// # Returns
///
/// A vector of `n` bits.
fn h2b(h: &[u8], n: usize) -> Vec<bool> {
    // Map each byte to a vector of its bits, then flatten the result.
    h.iter()
        .flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1 == 1))
        // Take only the first `n` bits.
        .take(n)
        // Collect the bits into a vector.
        .collect()
}

/// Converts a bit array to a byte array.
///
/// # Arguments
///
/// * `s` - The bit array to convert.
///
/// # Returns
///
/// A vector of bytes.
fn b2h(s: &[bool]) -> Vec<u8> {
    // Chunk the bit array into chunks of 8 bits.
    s.chunks(U8BITS)
        // For each chunk, fold the bits into a byte.
        .map(|chunk| chunk.iter().enumerate().fold(0, |byte, (i, &bit)| byte | ((bit as u8) << i)))
        // Collect the bytes into a vector.
        .collect()
}

/// A macro to define SHA-3 hash functions with different output lengths.
macro_rules! sha3 {
    ($name:ident, $n:literal) => {
        /// Computes the SHA-3 hash of the input data.
        ///
        /// # Arguments
        ///
        /// * `input` - A byte slice containing the data to hash.
        ///
        /// # Returns
        ///
        /// A fixed-size array containing the hash output.
        pub fn $name(input: &[u8]) -> [u8; $n / U8BITS] {
            let mut bits = h2b(input, input.len() * U8BITS);
            bits.append(&mut vec![false, true]);
            let result_bits = keccak($n * 2, &bits, $n);
            let result_bytes = b2h(&result_bits);
            result_bytes.try_into().expect("incorrect length")
        }
    };
}

// Define SHA-3 hash functions with different output lengths.
sha3!(sha3_224, 224);
sha3!(sha3_256, 256);
sha3!(sha3_384, 384);
sha3!(sha3_512, 512);
