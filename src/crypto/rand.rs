use std::libc::c_int;
use std::vec;

use ffi;

pub fn rand_bytes(len: uint) -> ~[u8] {
    unsafe {
        let mut out = vec::with_capacity(len);

        let r = ffi::RAND_bytes(out.as_mut_ptr(), len as c_int);
        if r != 1 as c_int { fail!() }

        out.set_len(len);

        out
    }
}

#[cfg(test)]
mod tests {
    use super::rand_bytes;

    #[test]
    fn test_rand_bytes() {
        let bytes = rand_bytes(32u);
        println!("{:?}", bytes);
    }
}
