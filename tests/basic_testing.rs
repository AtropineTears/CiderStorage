use CiderStorage::cider_file::CiderData;
use std::path::{Path,PathBuf};

#[test]
fn test_file_hash(){
    let mut path = PathBuf::new();
    path.push("C:\\Users\\Amelie\\Desktop\\test.txt");

    let file = CiderData::new(path);

}

#[test]

#[test]
fn test_pieces(){
    let mut path = PathBuf::new();
    path.push("/Users/0xSilene/test.txt");

    let mut file = CiderData::new(path.clone());
}

#[test]
fn test_pow(){
    let mut path = PathBuf::new();
    path.push("/Users/0xSilene/test.txt");

    let mut file = CiderData::new(path.clone());
}