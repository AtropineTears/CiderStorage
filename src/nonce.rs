pub struct NonceConversion;

impl NonceConversion {
    pub fn to_bytes_u64(input: &[u64]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 * input.len());
    
        for value in input {
            bytes.extend(&value.to_be_bytes());
        }
    
        bytes
    }
    pub fn to_bytes_u128(input: &[u128]) -> Vec<u8> {
        // TODO: Maybe change 8 to 16 depending on what you need
        let mut bytes = Vec::with_capacity(8 * input.len());
    
        for value in input {
            bytes.extend(&value.to_be_bytes());
        }
    
        bytes
    }
}