use crate::constants::BLAKE2B_DIGEST_SIZE_FILENAME;
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

use std::collections::HashMap;

use crate::constants::*;

/*
pub struct DownloadedPiecesCache {
    cdp: String,
    
    pieces: HashMap<String,CiderPieces>, // Hashmap
                                            // Used To Easily Get Pieces That Are Requested
    blake3_hashes: Vec<String>,

    expected_num_of_pieces: usize,
    current_num_of_pieces: usize,
}

impl DownloadedPiecesCache {
    pub fn new<T: AsRef<str>>(cdp: T) -> Self {

    }
    pub fn add_to_pieces(){

    }

    fn hash_piece(piece: &[u8]) -> String {
        let hash1 = hex::encode_upper(blake3::hash(piece).as_bytes());
        return hash1
    }
}
*/

// Ring
    // It is called a ring (layer) which makes up a circle that one can build.

// To Upload File
    // PoW must be done to prevent spam and only allow certain files to upload
#[derive(Debug,Serialize,Deserialize,Clone,PartialEq,PartialOrd,Hash)]
pub struct CiderData {
    // CID
    cid: String,

    // Blake2b 6-bytes
    filename: String,

    // Data + Nonce
    data: Option<Vec<u8>>,
    nonce: Option<u64>,

    // PoW
    pow_nonce: Option<u64>,

    // Hashes of Original Data
    blake2: String,
    sha512: String,

    // CiderDataPieces
    cdp: CiderDataPieces,

    // Extension
    extension: Option<OsString>
}

/// # CiderDataPieces (CDP)
/// 
/// Made up of the blake3 checksums of pieces of a file. The files are split into 256kb.
/// 
/// 
#[derive(Debug,Clone,Hash,Serialize,Deserialize,PartialEq,PartialOrd)]
pub struct CiderDataPieces {
    cdp_hash: String, // Hash of all blake3 checksums combined
    
        number_of_pieces: usize,
    
        blake3_checksum_of_pieces: Vec<String>,
        pieces: Vec<CiderPieces>,

        has_all_pieces: bool,

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
        
        let hash_b2 = hash_hex.0;
        let hash_sha512 = hash_hex.1;

        let cid = base32::encode(base32::Alphabet::RFC4648 { padding: false},&hash_bytes);

        let filename = Self::to_filename(&bytes);

        let cdp = CiderData::into_pieces(&bytes);

        let pow_nonce = Self::get_pow_nonce(cid.clone(), DIFFICULTY_LOWEST);

        return Self {
            filename: filename,

            data: Some(bytes),

            pow_nonce: Some(pow_nonce),

            blake2: hash_b2,
            sha512: hash_sha512,

            nonce: None,
            cid: cid,
            cdp: cdp,
            extension: Some(extension),
        }
    }
    pub fn new_with_nonce<T: AsRef<Path>, S: AsRef<str>>(path: T, cid_pow: S) -> Result<Self,CiderErrors> {
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

            let hash_b2 = hash_hex.0;
            let hash_sha512 = hash_hex.1;

            let cid = base32::encode(base32::Alphabet::RFC4648 { padding: false},&hash_bytes);

            if cid.starts_with(&x) {
                println!("[X] Found CID that matches input with nonce: {} after {} attempts",nonce_u64,attempts);
                println!("CID: {}",cid);

                let cdp = CiderData::into_pieces(&bytes);

                let filename = Self::to_filename(&bytes);

                let pow_nonce = Self::get_pow_nonce(cid.clone(), DIFFICULTY_LOWEST);

                return Ok(Self {
                    filename: filename,

                    pow_nonce: Some(pow_nonce),
                    
                    cdp: cdp,

                    blake2: hash_b2,
                    sha512: hash_sha512,

                    data: Some(bytes),
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

        if self.nonce == None && self.data.is_some() {
            let context = ParanoidHash::new(BLAKE2B_DIGEST_SIZE_IN_BYTES,OsAlgorithm::SHA512);
            let output = context.read_bytes(&self.data.as_ref().unwrap());
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
            let mut bytes = self.data.as_ref().unwrap().clone();

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
    /// ## Developer Notes
    /// 
    /// Do not remove the joining filename of `DO_NOT_REMOVE`. This is in place so the path is done right.
    pub fn download(&self, mut path: Option<PathBuf>) -> std::io::Result<()> {
        if path.is_none(){
            let mut new_path: PathBuf = dirs::download_dir().expect("[Error] Failed To Get Download Directory").join("DO_NOT_REMOVE");

            //new_path.join("test.txt");
            println!("Path: {:?}",new_path);

            //println!("Data {:?}",self.data.as_ref().expect("Failed To Get Data"));
            //println!("CID: {}",self.cid);

            
            new_path.set_file_name(OsStr::new(&self.filename));
            new_path.set_extension(self.extension.clone().unwrap_or(OsString::new()));
            
            // Write To File in Downloads Directory
            let mut file = File::create(new_path)?;
            file.write_all(&self.data.as_ref().expect("[Error] No Data Provided"))?;
            return Ok(());
        }
        else if path.is_some() {
            
            let mut new_path: PathBuf = path.expect("[Error] Failed To Get Path").join("DO_NOT_REMOVE");
            println!("Path: {:?}",new_path);

            
            // Set File Name and Extension
            new_path.set_file_name(OsStr::new(&self.filename));
            new_path.set_extension(self.extension.clone().unwrap_or(OsString::new()));

            println!("Path: {:?}",new_path);


            let mut file = File::create(new_path)?;
            file.write_all(&self.data.as_ref().expect("[Error] No Data Provided In CiderDataPiece"))?;
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

            has_all_pieces: true,
        }
        //println!("{:?}",pieces)
    }
    fn to_cid<T: AsRef<[u8]>>(data: T) -> String {
        let context = ParanoidHash::new(BLAKE2B_DIGEST_SIZE_IN_BYTES,OsAlgorithm::SHA512);
        let hash_hex = context.read_bytes(&data.as_ref());
        let hash_bytes = ParanoidHash::as_bytes(&hash_hex.0);
        let cid = base32::encode(base32::Alphabet::RFC4648 { padding: false},&hash_bytes);
        
        let cid_undercase = cid.to_ascii_lowercase();

        return cid_undercase
    }
        //let buf: [u8;BYTES_IN_A_CHUNK] = self.data
    fn to_bytes(input: &[u64]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 * input.len());
    
        for value in input {
            bytes.extend(&value.to_be_bytes());
        }
    
        bytes
    }
    fn to_filename<T: AsRef<[u8]>>(data: T) -> String {
        let context = ParanoidHash::new(BLAKE2B_DIGEST_SIZE_FILENAME,OsAlgorithm::SHA512);
        let hash_hex = context.read_bytes(data.as_ref());
        let hash_bytes = ParanoidHash::as_bytes(&hash_hex.0);
        let filename = base32::encode(base32::Alphabet::RFC4648 { padding: false},&hash_bytes);

        let filename_undercase = filename.to_ascii_lowercase();

        return filename_undercase
    }
    /// # Get PoW Nonce
    /// 
    /// ## Description
    /// 
    /// This function will return the nonce for your given CID.
    /// 
    /// ## Definition
    /// 
    /// `Blake3_Hash(CID + PoW Nonce)`
    /// 
    /// ## Difficulties
    /// 
    /// There are three difficulties:
    /// 
    /// 1. Lowest (`0000`)
    /// 2. Medium (`000000`)
    /// 3. Highest (`00000000`)
    /// 
    /// The higher you set your file to, the more likely it is to stay up on the network as nodes prefer files with a higher nonce.
    fn get_pow_nonce(cid: String, difficulty: &str) -> u64 {
        println!("Getting Proof of Work Nonce");
        
        let mut pow_nonce: u64 = 0u64;
        let cid_pow_vector: Vec<u8> = cid.as_bytes().to_vec();


        loop {
            // Initialize CID
            let mut cid_pow: Vec<u8> = cid_pow_vector.clone();

            // Convert u64 -> u8 bytes
            let mut pow_bytes = Self::to_bytes(&vec![pow_nonce]);

            // Append u8 bytes to CID
            cid_pow.append(&mut pow_bytes);

            // Hash Output
            let b3_pow = blake3::hash(&cid_pow);

            // Encode Hash as Hexadecimal
            let verify_hash = hex::encode_upper(b3_pow.as_bytes());

            if verify_hash.starts_with(difficulty){
                println!("Got PoW Nonce");
                return pow_nonce
            }
            else {
                pow_nonce += 1;
            }
        }
    }
}

impl CiderDataPieces {
    /// # Has All Pieces
    /// 
    /// Checks whether the user has all the pieces. If it does, they become a seeder
    pub fn has_all_pieces(&self) -> bool {
        let output = self.verify_pieces();

        match output {
            Ok(v) => return true,
            Err(_) => return false
        }
    }
    pub fn construct<T: AsRef<str>>(&self,cid: &str, nonce: Option<u64>, extension: Option<OsString>) -> CiderData {
        let (b2,sha512,data,cid) = self.verify(cid,nonce).expect("[Error] Failed To Verify");
        
        let cdp: CiderDataPieces = CiderDataPieces {
            cdp_hash: self.cdp_hash.clone(),
            blake3_checksum_of_pieces: self.blake3_checksum_of_pieces.clone(),
            number_of_pieces: self.number_of_pieces,
            pieces: self.pieces.clone(),

            has_all_pieces: true,
        };

        let filename = CiderData::to_filename(&data);

        let pow_nonce = CiderData::get_pow_nonce(cid.clone(), DIFFICULTY_LOWEST);

        return CiderData {
            cid: cid,
            data: Some(data),
            nonce: nonce,

            filename: filename,
            pow_nonce: Some(pow_nonce),

            blake2: b2,
            sha512: sha512,
            cdp: cdp,

            extension: extension,
        }
    }
    /// ### Developer Notes
    /// 
    /// Step 1. Check **CDP Hash** matches BLAKE3 Checksums of Pieces. Keep encoded in hexadecimal when hashing.
    /// 
    /// Step 2. Check pieces are equal in length
    /// 
    /// Step 3. Verify Each Piece and return data
    /// 
    /// Step 4. Return CID from data (also checks for nonce to add to data)
    /// 
    /// Step 5. 
    /// 
    /// ## Warning
    /// 
    /// Nonces are unimplemented as of now
    /// 
    /// ## TODO:
    /// 
    /// * Remove as many clones as possible
    pub fn verify(&self,cid: &str, nonce: Option<u64>) -> Result<(String,String,Vec<u8>,String),CiderErrors> {
        self.verify_cdp()?;
        self.verify_lengths_initial()?;
        let data: Vec<u8> = self.verify_pieces()?;
        let (b2,sha512) = self.return_hash_of_data(&data);
        
        let cid_output = self.return_cid(data.clone(), nonce);
        let cid_is_valid = self.verify_cid(&cid_output, &cid.to_string());

        if cid_is_valid {
            return Ok((b2,sha512,data,cid_output))
        }
        else {
            return Err(CiderErrors::CidIsInvalid)
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
    /// # Verify Pieces (and returns Data as a whole)
    /// 
    /// This function will verify pieces and return the data
    fn verify_pieces(&self) -> Result<Vec<u8>,CiderErrors> {
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

                // Add nonce vector
                data.append(&mut piece);
            }
        }
        return Ok(data)

        /*
        if nonce.is_none() {
            let cid = CiderData::to_cid(data);
            return Ok(cid)
        }
        else {
            let mut nonce_u8_vector = CiderData::to_bytes(&vec![nonce.expect("[Error] Unrecoverable Error: 0x7777")]);
            data.append(&mut nonce_u8_vector);
            let cid = CiderData::to_cid(data);
            return Ok(cid)
        }
        */
    }
    fn return_cid(&self, mut data: Vec<u8>, nonce: Option<u64>) -> String {
        if nonce.is_none() {
            let cid = CiderData::to_cid(data);
            return cid
        }
        else {
            let mut nonce_u8_vector = CiderData::to_bytes(&vec![nonce.expect("[Error] Unrecoverable Error: 0x7777")]);
            data.append(&mut nonce_u8_vector);
            let cid = CiderData::to_cid(data);
            return cid
        }
    }
    fn verify_cid<T: AsRef<str>>(&self, cid: T, expected_cid: T) -> bool {
        if cid.as_ref().to_ascii_lowercase() == expected_cid.as_ref().to_ascii_lowercase() {
            return true
        }
        else {
            return false
        }
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
    fn return_hash_of_data<T: AsRef<[u8]>>(&self,data: T) -> (String, String) {
        let hasher = ParanoidHash::new(BLAKE2B_DIGEST_SIZE_IN_BYTES, OsAlgorithm::SHA512);
        let (b2,sha512) = hasher.read_bytes(&data.as_ref());

        return (b2,sha512)
    }
}