use CiderStorage::data::{FileData};
use std::path::{Path,PathBuf};

#[test]
fn test_file_hash(){
    let mut path = PathBuf::new();
    path.push("C:\\Users\\Amelie\\Desktop\\test.txt");

    let file = FileData::new(path);


    println!("CID: {}",file.cid);
    println!("CID Length: {}",file.cid.len())
}

#[test]
fn test_file_hash_pow(){
    let mut path = PathBuf::new();
    path.push("C:\\Users\\Amelie\\Desktop\\test.txt");

    let mut file = FileData::new_pow(path,"CID").unwrap();

    let is_valid: bool = file.verify();

    assert!(is_valid);
}