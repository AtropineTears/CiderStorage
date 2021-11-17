/// # Media Information
/// 
/// Used to list all media information
pub struct MediaInformation {
    
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