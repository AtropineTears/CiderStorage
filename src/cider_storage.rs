pub struct CiderHome {

}

pub struct CiderFile {
    // CID + CDP Hash
    cid: String,
    cdp_hash: String, // Hash of all Blake3 Checksums
}

pub struct CiderPieces

pub struct CiderFileSignatures {
    author_signature: Option<String>,
    author_pk: Option<String>,

    uploader_signature: Option<String>,
    uploader_pk: Option<String>,
    
    node_pk: Option<String>,
    node_signature: Option<String>,
}