/*
 * Copyright 2013 Jack Lloyd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::libc::{c_int, c_uint};
use std::ptr;
use std::vec;

use hash;
use ffi;

pub struct HMAC {
    priv ctx: ffi::HMAC_CTX,
    priv len: uint,
}

pub fn HMAC(ht: hash::HashType, key: ~[u8]) -> HMAC {
    unsafe {
        let (evp, mdlen) = ffi::evpmd(ht);

        let mut ctx = ffi::HMAC_CTX {
            md: ptr::null(),
            md_ctx: ptr::null(),
            i_ctx: ptr::null(),
            o_ctx: ptr::null(),
            key_length: 0,
            key: [0u8, .. 128]
        };

        ffi::HMAC_CTX_init(&mut ctx,
                           key.as_ptr(),
                           key.len() as c_int,
                           evp);

        HMAC { ctx: ctx, len: mdlen }
    }
}

impl HMAC {
    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            ffi::HMAC_Update(&mut self.ctx, data.as_ptr(), data.len() as c_uint)
        }
    }

    pub fn final(&mut self) -> ~[u8] {
        unsafe {
            let mut res = vec::from_elem(self.len, 0u8);
            let mut outlen = 0;
            ffi::HMAC_Final(&mut self.ctx, res.as_mut_ptr(), &mut outlen);
            assert!(self.len == outlen as uint)
            res
        }
    }
}
