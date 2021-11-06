use chrono::prelude::*;
use serde::{Serialize,Deserialize};

use crate::enums::MediaType;
//use crate::ring_layer::CiderRingLayer;

use std::io;
use std::io::prelude::*;
use std::fs::File;
use std::fs;

use std::path::{Path,PathBuf};
use std::io::prelude::*;


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

use log::{info,warn,error,debug};


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

    // CiderDataPieces
    pub cdp: CiderDataPieces,

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

/// # CiderDataPieces (CDP)
/// 
/// Made up of the blake3 checksums of pieces of a file. The files are split into 256kb.
/// 
/// 
#[derive(Debug,Clone,Hash,Serialize,Deserialize,PartialEq,PartialOrd)]
pub struct CiderDataPieces {
    cdp_hash: String,
    
        number_of_pieces: usize,
    
        blake3_checksum_of_pieces: Vec<String>,
        pieces: Vec<CiderPieces>,

        //want_list: Vec<String>,
        //have_list: Vec<String>,
}

/// A vector of bytes which is a single data piece
type CiderPieces = Vec<u8>;

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

        let cdp = CiderData::into_pieces(&bytes);

        return Self {
            data: bytes,
            nonce: None,
            cid: cid,
            cdp: cdp,
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

                let cdp = CiderData::into_pieces(&bytes);

                return Ok(Self {
                    cdp: cdp,

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
    pub fn into_pieces<T: AsRef<[u8]>>(data: T) -> CiderDataPieces {
        let mut pieces: Vec<CiderPieces> = vec![];
        let mut blake3_hashes: Vec<String> = vec![];
        
        // Get Number of Bytes of Data
        let num_of_bytes: usize = data.as_ref().len();



        // Perform Math. Will always floor division so add 1 if not 0
        let mut num_of_pieces: usize = num_of_bytes / BYTES_IN_A_CHUNK;
        let modulus = num_of_bytes % BYTES_IN_A_CHUNK;

        // If modulus is not equal to 0, add one
        if modulus != 0usize {
            num_of_pieces += 1usize;
        }

        //println!("Number of Bytes In File: {}",num_of_bytes);
        //println!("Number of Pieces: {}",&num_of_pieces);
        //println!("Last Piece Size: {}",&modulus);

        // Init i
        //let mut i: usize = 0;

        for x in 0..num_of_pieces {
            let position: usize = x * BYTES_IN_A_CHUNK;
            let mut position_end: usize = (x + 1) * BYTES_IN_A_CHUNK;

            println!("i: {}",x);
            

            if x == (num_of_pieces-1usize) {
                position_end = num_of_bytes;
            }

            let mut buf: CiderPieces = data.as_ref()[position..position_end].to_vec();
            let hash = blake3::hash(&buf);
            pieces.push(buf);
            blake3_hashes.push(hex::encode_upper(hash.as_bytes()));
        }
        let mut b3_checksum = blake3::Hasher::new();

        // Keep in hexadecimal format when hashing
        for x in blake3_hashes.clone() {
            b3_checksum.update(x.as_bytes());
        }
        let cdp_hash = hex::encode_upper(b3_checksum.finalize().as_bytes());

        return CiderDataPieces {
            cdp_hash: cdp_hash,

            number_of_pieces: num_of_pieces,
            blake3_checksum_of_pieces: blake3_hashes,
            pieces: pieces,
        }
        //println!("{:?}",pieces)
    }

    fn to_cid<T: AsRef<[u8]>>(data: T) -> String {
        let context = ParanoidHash::new(BLAKE2B_DIGEST_SIZE_IN_BYTES,OsAlgorithm::SHA512);
        let hash_hex = context.read_bytes(&data.as_ref());
        let hash_bytes = ParanoidHash::as_bytes(&hash_hex.0);
        let cid = base32::encode(base32::Alphabet::RFC4648 { padding: false},&hash_bytes);

        return cid
    }
        //let buf: [u8;BYTES_IN_A_CHUNK] = self.data
    fn to_bytes(input: &[u64]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 * input.len());
    
        for value in input {
            bytes.extend(&value.to_be_bytes());
        }
    
        bytes
    }
}

impl CiderDataPieces {
    pub fn download(&self){

    }
    /// ### Developer Notes
    /// 
    /// Step 1. Check **CDP Hash** matches BLAKE3 Checksums of Pieces. Keep encoded in hexadecimal when hashing.
    /// 
    /// Step 2. Check pieces are equal in length
    /// 
    /// Step 3. Verify Each Piece
    pub fn verify(&self,cid: String) -> Result<(),CiderErrors> {
        self.verify_cdp()?;
        self.verify_lengths_initial()?;
        let cid_output = self.verify_pieces()?;

        if cid != cid_output {
            return Err(CiderErrors::CidIsInvalid)
        }
        else {
            return Ok(())
        }
    }
    fn get_cdp_hash(&self) -> String {
        // Get Blake3 Hash
        let mut cdp_hash = blake3::Hasher::new();

        // Get CDP Hash from Blake3 hashes of pieces
        for x in &self.blake3_checksum_of_pieces {
            cdp_hash.update(x.as_bytes());
        }

        let output = hex::encode_upper(cdp_hash.finalize().as_bytes());

        return output
    }
    /// # Verify Pieces (and returns CID)
    /// 
    /// This function will verify pieces and return the data's CID
    fn verify_pieces(&self) -> Result<String,CiderErrors> {
        // Data used to get the CID
        let mut data: Vec<u8> = vec![];
        
        for x in 0..self.number_of_pieces {
            // Setup Blake3 Hasher
            let mut b3_checksum = blake3::Hasher::new();
            
            // Get Piece Data and Hash
            let hash = &self.blake3_checksum_of_pieces[x];
            let mut piece = self.pieces[x].clone();

            // Hash Piece
            b3_checksum.update(&piece);
            let hash_output = &hex::encode_upper(b3_checksum.finalize().as_bytes());

            

            if hash_output != hash {
                return Err(CiderErrors::BadBlake3Checksum)
            }
            else {
                data.append(&mut piece);
            }
        }
        let cid = CiderData::to_cid(data);

        return Ok(cid)
    }
    fn verify_lengths_initial(&self) -> Result<(),CiderErrors> {
        if self.blake3_checksum_of_pieces.len() == self.number_of_pieces {
            log::debug!("[Debug] Blake3 Checksums of Pieces and Pieces Length Are The Same");
            return Ok(())
        }
        else {
            log::debug!("[Debug] Length Error");
            return Err(CiderErrors::CdpPiecesLengthIsWrong)
        }
    }
    fn verify_cdp(&self) -> Result<(),CiderErrors> {
        let cdp = self.get_cdp_hash();

        if cdp != self.cdp_hash {
            return Err(CiderErrors::BadBlake3Checksum)
        }
        else {
            Ok(())
        }
    }
}