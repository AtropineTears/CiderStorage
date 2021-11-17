pub const BLAKE2B_DIGEST_SIZE_IN_BYTES: usize = 48usize;
pub const BLAKE2B_DIGEST_SIZE_FILENAME: usize = 8usize;

/// 256 kB (262,144 bytes) | assumes 1kB is equal to 1024 bytes | 262144
pub const BYTES_IN_A_CHUNK: usize = 262144;

//
pub const DIFFICULTY_LOWEST: &str = "0000";
pub const DIFFICULTY_MEDIUM: &str = "000000";
pub const DIFFICULTY_HIGHEST: &str = "00000000";