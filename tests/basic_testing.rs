use CiderStorage::cider_file::CiderData;
use std::path::{Path,PathBuf};
use env_logger::*;

fn create_logs(){
    Builder::new()
        .target(Target::Stdout)
        .init();
}

fn init() {
    let _ = env_logger::builder()
    .is_test(true)
    .target(Target::Stdout)
    .try_init();
}

#[test]
fn test_pieces(){
    init();
    let mut path = PathBuf::new();
    path.push("/Users/0xSilene/test.txt");

    let mut file = CiderData::new(path.clone());
    file.verify();
    file.download(None);
}

#[test]
fn test_pow(){
    let mut path = PathBuf::new();
    path.push("/Users/0xSilene/Downloads/Hanna.mp4");

    let mut file = CiderData::new(path.clone());
    file.verify();
    let cid = file.return_cid();
    println!("{}",cid);
    //file.download(None);
}

#[test]
fn test_pow_2(){
    let mut path = PathBuf::new();
    path.push("/Users/0xSilene/Downloads/Hanna.mp4");

    let mut file = CiderData::new_with_nonce(path.clone(),"CID").expect("[Error]");
    let cid = file.return_cid();
    println!("{}",cid);
    //file.download(None);
}