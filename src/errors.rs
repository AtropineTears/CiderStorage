use std::io::{Error, ErrorKind};
use serde::{Serialize,Deserialize};

#[derive(Debug,Clone,Serialize,Deserialize,Hash,PartialEq,PartialOrd)]
pub enum CiderErrors {
    FileNotFound,

    CiderSwapDataIsNotComplete, // Means you do not have all the pieces to construct the CiderPiecesSwap

    //
    BadBlake3Checksum, // CDP is wrong
    BadBlake3ChecksumAgainstExpected,
    CdpPiecesLengthIsWrong,

    CidIsInvalid,
}