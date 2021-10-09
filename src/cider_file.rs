use chrono::prelude::*;
use serde::{Serialize,Deserialize};

use crate::enums::MediaType;
use crate::ring_layer::CiderRingLayer;

use std::io;
use std::io::prelude::*;
use std::fs::File;
use std::fs;

use std::path::{Path,PathBuf};

use std::ffi::{OsStr,OsString};

use std::io::{Error, ErrorKind};

use filebuffer::FileBuffer;

use paranoid_hash::ParanoidHash;
use paranoid_hash::OsAlgorithm;

use dirs::*;

use crate::constants::BLAKE2B_DIGEST_SIZE_IN_BYTES;
use crate::constants::BYTES_IN_A_CHUNK;

use base32::{encode,decode};

use blake3::Hash;

use crate::errors::CiderErrors;

// Ring
    // It is called a ring (layer) which makes up a circle that one can build.

// To Upload File
    // PoW must be done to prevent spam and only allow certain files to upload
#[derive(Debug,Serialize,Deserialize,Clone,PartialEq,PartialOrd,Hash)]
pub struct CiderData {
    // CID
    pub cid: String,

    // Data + Nonce
    pub data: Vec<u8>,
    pub nonce: Option<u64>,

    // Extension
    pub extension: Option<OsString>
}



pub struct FileMetaData {

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

#[derive(Debug,Serialize,Deserialize,Clone,PartialEq,PartialOrd,Hash)]
pub struct DataPiece {
    // Layer
    pub layer: CiderRingLayer,
    
    // Data
    pub file: CiderData,


    

}

pub struct CiderChunks {
    Vec<>
}

pub struct CiderFileChunks {
    number_of_chunks: usize,
    blake3_checksum: Vec<String>,
    chunks: Vec<CiderChunk>,
}

type CiderChunk = Vec<u8>;

impl CiderData {
    /// # New
    /// 
    /// Generates a CID for a new FileData struct encoded in Base32. It contains the data in bytes, an empty nonce, and the CID (48 byte hash encoded in Base32)
    /// 
    /// Note: Base32 uses RFC4648 (unpadded)
    /// 
    /// CID Length: 77 bytes (or chars)
    pub fn new<T: AsRef<Path>>(path: T) -> Self {
        let extension = path.as_ref().extension().expect("[Error 0x0002] Failed To Get File Extension").to_os_string();
        
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
            extension: Some(extension),
        }
    }
    pub fn new_pow<T: AsRef<Path>, S: AsRef<str>>(path: T, cid_pow: S) -> Result<Self,CiderErrors> {
        let extension = path.as_ref().extension().expect("[Error 0x0002] Failed To Get File Extension").to_os_string();

        
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

            let mut nonce_u8_vector = CiderData::to_bytes(&vec![nonce_u64]);

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
                    extension: Some(extension),
                })
            }
            else {
                nonce_u64 += 1u64;
            }

        }
    }
    pub fn return_cid(&self) -> String {
        return self.cid.clone()
    }
    pub fn verify(&self) -> bool {
        // Asserts CID is 77 bytes long
        assert_eq!(self.cid.len(),77usize);

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
            let mut nonce_u8_vector = CiderData::to_bytes(&vec![self.nonce.unwrap()]);

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
    pub fn download<T: AsRef<Path>>(&self, mut path: Option<T>) -> std::io::Result<()> {
        if path.as_ref().is_none(){
            let mut new_path = dirs::download_dir().expect("[Error] Failed To Get Download Directory");
            
            new_path.set_file_name(OsStr::new(&self.cid));
            new_path.set_extension(self.extension.clone().unwrap_or(OsString::new()));
            
            // Write To File in Downloads Directory
            let mut file = File::create(new_path)?;
            file.write_all(&self.data)?;
            return Ok(());
        }
        else if path.as_ref().is_some() {
            let mut new_path: PathBuf = path.as_ref().expect("Failed To Unwrap Path in Download Section").as_ref().to_path_buf();
            // Set File Name and Extension
            new_path.set_file_name(OsStr::new(&self.cid));
            new_path.set_extension(self.extension.clone().unwrap_or(OsString::new()));

            let mut file = File::create(new_path)?;
            file.write_all(&self.data)?;
            return Ok(());
        }
        else {
            panic!("Unreachabled Code was reached in download section");
        }
    }
    pub fn into_chunks(&self) -> CiderFileChunks {
        //let x = fs::metadata(path)?.len();

        
        //let buf: [u8;BYTES_IN_A_CHUNK] = self.data
    }
    fn to_bytes(input: &[u64]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 * input.len());
    
        for value in input {
            bytes.extend(&value.to_be_bytes());
        }
    
        bytes
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
    /*
impl DataPiece {
    pub fn new<T: AsRef<Path>>(path: T, layer: RingLayer, media_type: MediaType){
        let fbuffer: FileBuffer = FileBuffer::open(&path).expect("[Error 0x000] Failed To Open File ");
    }
}
*/