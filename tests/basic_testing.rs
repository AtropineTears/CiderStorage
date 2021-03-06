use CiderStorage::cider::CiderData;
use CiderStorage::cider::*;
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

    let mut file = CiderData::new(path.clone());
    let b3sums = file.cdp.return_all_b3sums();
    let hashmaps = file.cdp.into_cps(file.return_cid(),file.return_nonce()).expect("Failed");

    
    //println!("{}",x.have_pieces);
    

    let cid = file.return_cid();
    println!("{}",cid);
    //file.download(None);
}

#[test]
fn basics(){
    let mut path = PathBuf::from("/Users/0xSilene/Downloads/Inkscape-1.1.1.dmg");

    let mut file: CiderData = CiderData::new(path.clone());

    let is_valid = file.verify();

    file.download(None);

    println!("{:?}",is_valid);

}