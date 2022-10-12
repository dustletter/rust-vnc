//use octavo::digest::prelude::{Digest, Md5};
use md5;

pub fn md5(data: &[u8]) -> [u8; 16] {
    md5::compute(data)
}
