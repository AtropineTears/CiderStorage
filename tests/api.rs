use CiderStorage::cider::*;
use std::path::PathBuf;

#[test]
fn basic_test(){

    let mut path3: PathBuf = PathBuf::new();
    path3.push("/Users/0xSilene/test.txt");

    let mut path2: PathBuf = PathBuf::new();
    path2.push("/Users/0xSilene/Downloads/Test123/");

    let x = CiderData::new(path3);
    x.download(None);
}