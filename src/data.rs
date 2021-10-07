use chrono::prelude::*;
use serde::{Serialize,Deserialize};

use crate::enums::MediaType;
use crate::ring_layer::RingLayer;

use std::io;
use std::io::prelude::*;
use std::fs::File;

use std::path::Path;

use std::io::{Error, ErrorKind};

use filebuffer::FileBuffer;

use paranoid_hash::ParanoidHash;
use paranoid_hash::OsAlgorithm;

use crate::constants::BLAKE2B_DIGEST_SIZE_IN_BYTES;

use base32::{encode,decode};

use crate::errors::CiderErrors;

// Ring
    // It is called a ring (layer) which makes up a circle that one can build.

// To Upload File
    // PoW must be done to prevent spam and only allow certain files to upload
#[derive(Debug,Serialize,Deserialize,Clone,PartialEq,PartialOrd,Hash)]
pub struct FileData {
    pub data: Vec<u8>,
    pub nonce: Option<u64>,
    pub cid: String,
}

#[derive(Debug,Serialize,Deserialize,Clone,PartialEq,PartialOrd,Hash)]
pub struct DataPiece {
    // Data
    pub file: FileData,

    // Layer
    pub layer: RingLayer,
    
    // Metadata
    pub media_type: MediaType,
    pub extension: Option<String>, // Up to 4 chars
    pub description: Option<String>, // Up to 512 chars

    // Hashing
    pub sha512_checksum: Option<String>,

    // Tagging (or Labels)
    pub tags: Option<Vec<String>>,

    // Time
    pub unverified_timestamp: Option<DateTime<Utc>>,
    pub unverified_author: Option<String>,
    pub unverified_author_pk: Option<String>,
    pub unverified_signature: Option<String>,
}

impl FileData {
    /// # New
    /// 
    /// Generates a CID for a new FileData struct encoded in Base32. It contains the data in bytes, an empty nonce, and the CID (48 byte hash encoded in Base32)
    /// 
    /// Note: Base32 uses RFC4648 (unpadded)
    /// 
    /// CID Length: 77 bytes (or chars)
    pub fn new<T: AsRef<Path>>(path: T) -> Self {
        let fbuffer = FileBuffer::open(path.as_ref()).expect("[Error 0x0001] Failed To Open/Read File While Generating FileData Struct.");
        let mut bytes = fbuffer.to_vec();

        // Setup context for reading file into hexadecimal and then bytes
        let context = ParanoidHash::new(BLAKE2B_DIGEST_SIZE_IN_BYTES,OsAlgorithm::SHA512);
        let hash_hex = context.read(path.as_ref()).unwrap();
        let hash_bytes = ParanoidHash::as_bytes(&hash_hex.0);

        let cid = base32::encode(base32::Alphabet::RFC4648 { padding: false},&hash_bytes);

        return Self {
            data: bytes,
            nonce: None,
            cid: cid,
        }
    }
    pub fn new_pow<T: AsRef<Path>, S: AsRef<str>>(path: T, cid_pow: S) -> Result<Self,CiderErrors> {
        // Read File
        let fbuffer = FileBuffer::open(path.as_ref()).expect("[Error 0x0002] Failed To Open/Read File While Generating FileData Struct (new_pow).");
        let mut bytes = fbuffer.to_vec();
        
        // Get the beginning CID String You Want
        let x = cid_pow.as_ref().to_ascii_uppercase();
        let cid_length: usize = x.len();

        // Init nonce
        let mut nonce_u64: u64 = 0;
        let mut attempts: usize = 0;

        loop {
            // Increase attempts by 1
            attempts += 1;
            let mut bytes_with_nonce = bytes.clone();

            let mut nonce_u8_vector = FileData::to_bytes(&vec![nonce_u64]);

            // Add nonce vector
            bytes_with_nonce.append(&mut nonce_u8_vector);
            
            // Hash as hexadecimal and then convert from hex to bytes
            let mut context = ParanoidHash::new(BLAKE2B_DIGEST_SIZE_IN_BYTES,OsAlgorithm::SHA512);
            let hash_hex = context.read_bytes(&bytes_with_nonce);
            let hash_bytes = ParanoidHash::as_bytes(&hash_hex.0);

            let cid = base32::encode(base32::Alphabet::RFC4648 { padding: false},&hash_bytes);

            if cid.starts_with(&x) {
                println!("[X] Found CID that matches input with nonce: {} after {} attempts",nonce_u64,attempts);
                println!("CID: {}",cid);

                return Ok(Self {
                    data: bytes,
                    nonce: Some(nonce_u64),
                    cid: cid,
                })
            }
            else {
                nonce_u64 += 1u64;
            }

        }
    }
    pub fn verify(&self) -> bool {
        if self.nonce == None {
            let context = ParanoidHash::new(BLAKE2B_DIGEST_SIZE_IN_BYTES,OsAlgorithm::SHA512);
            let output = context.read_bytes(&self.data);
            let hash_bytes = ParanoidHash::as_bytes(&output.0);

            let cid = base32::encode(base32::Alphabet::RFC4648 { padding: false},&hash_bytes);

            if cid == self.cid {
                return true
            }
            else {
                return false
            }
        }
        else {
            // Init Data Bytes
            let mut bytes = self.data.clone();

            // Convert u64 to vector of u8s
            let mut nonce_u8_vector = FileData::to_bytes(&vec![self.nonce.unwrap()]);

            // Combine data and nonce
            bytes.append(&mut nonce_u8_vector);

            let context = ParanoidHash::new(BLAKE2B_DIGEST_SIZE_IN_BYTES,OsAlgorithm::SHA512);
            let output = context.read_bytes(&bytes);
            let hash_bytes = ParanoidHash::as_bytes(&output.0);
            let cid = base32::encode(base32::Alphabet::RFC4648 { padding: false},&hash_bytes);

            if cid == self.cid {
                return true
            }
            else {
                return false
            }
        }
    }
    fn to_bytes(input: &[u64]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 * input.len());
    
        for value in input {
            bytes.extend(&value.to_be_bytes());
        }
    
        bytes
    }
}

impl DataPiece {
    pub fn new<T: AsRef<Path>>(path: T, layer: RingLayer, media_type: MediaType){
        let fbuffer: FileBuffer = FileBuffer::open(&path).expect("[Error 0x000] Failed To Open File ");
    }
}