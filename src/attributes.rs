use serde::{Serialize,Deserialize};


pub struct CiderFileAttributes {
    // The CID of the file
    cid: String,

    // 12-byte
    attribute_hash: String,

        author: Option<String>,
        author_timestamp: Option<i64>,
        
        // Uploader Metadata
        uploader: Option<String>,
        upload_timestamp: Option<i64>,

        // Tags to organize data
        tags: Option<Vec<String>>,

        // Media Type
        mediatype: Option<MediaType>,

        list_of_signers: Option<Vec<String>>,

        description: Option<String>,
}


#[derive(Debug,Serialize,Deserialize,PartialEq,PartialOrd,Hash,Clone)]
pub enum MediaType {
    Video,
    Image,
    Audio,
    
    Text,
    Pdf,
    Doc,

    Keys, // Cryptography
    Crypto, // Cryptocurrency

    Database,
    Website,
}