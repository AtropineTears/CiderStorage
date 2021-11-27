use CiderStorage::cider_file::CiderData;
use CiderStorage::cider_file::*;
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


    for x in b3sums {
        println!("{:?}",hashmaps.have_pieces[&x]);
    }

    
    //println!("{}",x.have_pieces);
    

    let cid = file.return_cid();
    println!("{}",cid);
    //file.download(None);
}