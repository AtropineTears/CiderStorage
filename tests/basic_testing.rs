use CiderStorage::cider_file::{FileData};
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

    let mut path2 = PathBuf::new();
    path2.push("C:\\Users\\Amelie\\Desktop");

    let mut file = FileData::new_pow(path.clone(),"C").unwrap();

    let x = file.download(Some(path.clone()));

    let is_valid: bool = file.verify();

    assert!(is_valid);
}