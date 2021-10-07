use serde::{Serialize,Deserialize};


#[derive(Debug,Serialize,Deserialize,PartialEq,PartialOrd,Hash,Clone)]
pub enum CiderRingLayer {
    // Essentials
    Kernel,

    CoreDevelopers, // Essential For Developers
    CoreCrypto, // Stores Core Cryptography Keys
    CoreCollections, // A Collection Is A List Of CIDs (Hashes) under one CID (hash)
    
    // Essentials For Different Communities; Allows you to pick each one.
    CoreCommunity, // Store Core Community Items
    CoreOrganization, // Stores Core Components For Different Organizations
    CoreOpenDomain, // Define core componenets for an open domain
    
    SecurePayments, // Upload your cryptocurrency addresses
    Crypto, // All Cryptography That Is Not Core
    Community, // Allows you to choose who you want to host. Must host all content.
    Organization,
    Collections,

    OpenDomain {
        domain: String,
    }, // [Example] A Domain System That Allows Different Branches Of

    
    Private,
    Unlabeled, // Unknown or not labeled yet
}

pub struct CiderRingLayer {

}