use CiderStorage::prelude::*;
use std::path::PathBuf;

fn main(){
    let mut path: PathBuf = PathBuf::new();
    path.push("/Users/0xSilene/Desktop/CiderStorage/examples/test.txt");
    let x = CiderData::new(path);
    x.download(None);
    x.verify();
}