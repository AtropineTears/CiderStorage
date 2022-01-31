//! # CiderStorage
//! 
//! CiderStorage is an updatable file system that allows users to post a wide variety of different content to the internet which is secured by its cryptographic hash (known as the CID).

pub mod errors;
pub mod constants;

pub mod cider;
pub mod prelude;
//pub mod ring_layer;


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
