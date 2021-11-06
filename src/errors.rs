use std::io::{Error, ErrorKind};
use serde::{Serialize,Deserialize};

#[derive(Debug,Clone,Serialize,Deserialize,Hash,PartialEq,PartialOrd)]
pub enum CiderErrors {
    FileNotFound,

    //
    BadBlake3Checksum,
    CdpPiecesLengthIsWrong,

    CidIsInvalid,
}