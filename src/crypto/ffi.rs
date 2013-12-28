#[allow(non_camel_case_types)];

use std::libc::{c_char, c_uchar, c_int, c_uint, c_void};

use hash;
use symm;

pub type EVP_CIPHER_CTX = *c_void;
pub type EVP_CIPHER = *c_void;

pub type EVP_MD_CTX = *c_void;
pub type EVP_MD = *c_void;

pub type EVP_PKEY = *c_void;

pub struct HMAC_CTX {
    md: EVP_MD,
    md_ctx: EVP_MD_CTX,
    i_ctx: EVP_MD_CTX,
    o_ctx: EVP_MD_CTX,
    key_length: c_uint,
    key: [c_uchar, ..128]
}

pub type RSA = *c_void;

pub fn evpc(t: symm::Type) -> (EVP_CIPHER, uint, uint) {
    unsafe {
        match t {
            symm::AES_128_ECB => (EVP_aes_128_ecb(), 16u, 16u),
            symm::AES_128_CBC => (EVP_aes_128_cbc(), 16u, 16u),
            // symm::AES_128_CTR => (EVP_aes_128_ctr(), 16u, 0u),
            // symm::AES_128_GCM => (EVP_aes_128_gcm(), 16u, 16u),

            symm::AES_256_ECB => (EVP_aes_256_ecb(), 32u, 16u),
            symm::AES_256_CBC => (EVP_aes_256_cbc(), 32u, 16u),
            // symm::AES_256_CTR => (EVP_aes_256_ctr(), 32u, 0u),
            // symm::AES_256_GCM => (EVP_aes_256_gcm(), 32u, 16u),

            symm::RC4_128 => (EVP_rc4(), 16u, 0u),
        }
    }
}

pub fn evpmd(t: hash::HashType) -> (EVP_MD, uint) {
    unsafe {
        match t {
            hash::MD5 => (EVP_md5(), 16u),
            hash::SHA1 => (EVP_sha1(), 20u),
            hash::SHA224 => (EVP_sha224(), 28u),
            hash::SHA256 => (EVP_sha256(), 32u),
            hash::SHA384 => (EVP_sha384(), 48u),
            hash::SHA512 => (EVP_sha512(), 64u),
        }
    }
}

#[link(name = "crypto")]
extern "C" {
    pub fn EVP_md5() -> EVP_MD;
    pub fn EVP_sha1() -> EVP_MD;
    pub fn EVP_sha224() -> EVP_MD;
    pub fn EVP_sha256() -> EVP_MD;
    pub fn EVP_sha384() -> EVP_MD;
    pub fn EVP_sha512() -> EVP_MD;

    pub fn EVP_CIPHER_CTX_new() -> EVP_CIPHER_CTX;
    pub fn EVP_CIPHER_CTX_set_padding(ctx: EVP_CIPHER_CTX, padding: c_int);
    pub fn EVP_CIPHER_CTX_free(ctx: EVP_CIPHER_CTX);

    pub fn EVP_aes_128_ecb() -> EVP_CIPHER;
    pub fn EVP_aes_128_cbc() -> EVP_CIPHER;
    // fn EVP_aes_128_ctr() -> EVP_CIPHER;
    // fn EVP_aes_128_gcm() -> EVP_CIPHER;
    pub fn EVP_aes_256_ecb() -> EVP_CIPHER;
    pub fn EVP_aes_256_cbc() -> EVP_CIPHER;
    // fn EVP_aes_256_ctr() -> EVP_CIPHER;
    // fn EVP_aes_256_gcm() -> EVP_CIPHER;
    pub fn EVP_rc4() -> EVP_CIPHER;

    pub fn EVP_CipherInit(ctx: EVP_CIPHER_CTX, evp: EVP_CIPHER,
                      key: *u8, iv: *u8, mode: c_int);
    pub fn EVP_CipherUpdate(ctx: EVP_CIPHER_CTX, outbuf: *mut u8,
                        outlen: &mut c_uint, inbuf: *u8, inlen: c_int);
    pub fn EVP_CipherFinal(ctx: EVP_CIPHER_CTX, res: *mut u8, len: &mut c_int);

    pub fn EVP_DigestInit(ctx: EVP_MD_CTX, typ: EVP_MD);
    pub fn EVP_DigestUpdate(ctx: EVP_MD_CTX, data: *u8, n: c_uint);
    pub fn EVP_DigestFinal(ctx: EVP_MD_CTX, res: *mut u8, n: *u32);

    pub fn EVP_MD_CTX_create() -> EVP_MD_CTX;
    pub fn EVP_MD_CTX_destroy(ctx: EVP_MD_CTX);

    pub fn EVP_PKEY_new() -> *EVP_PKEY;
    pub fn EVP_PKEY_free(k: *EVP_PKEY);
    pub fn EVP_PKEY_assign(pkey: *EVP_PKEY, typ: c_int, key: *c_char) -> c_int;
    pub fn EVP_PKEY_get1_RSA(k: *EVP_PKEY) -> *RSA;

    pub fn i2d_PublicKey(k: *EVP_PKEY, buf: **mut u8) -> c_int;
    pub fn d2i_PublicKey(t: c_int, k: **EVP_PKEY, buf: **u8, len: c_uint) -> *EVP_PKEY;
    pub fn i2d_PrivateKey(k: *EVP_PKEY, buf: **mut u8) -> c_int;
    pub fn d2i_PrivateKey(t: c_int, k: **EVP_PKEY, buf: **u8, len: c_uint) -> *EVP_PKEY;

    pub fn RSA_generate_key(modsz: c_uint, e: c_uint, cb: *u8, cbarg: *u8) -> *RSA;
    pub fn RSA_size(k: *RSA) -> c_uint;

    pub fn RSA_public_encrypt(flen: c_uint, from: *u8, to: *mut u8, k: *RSA,
                          pad: c_int) -> c_int;
    pub fn RSA_private_decrypt(flen: c_uint, from: *u8, to: *mut u8, k: *RSA,
                           pad: c_int) -> c_int;
    pub fn RSA_sign(t: c_int, m: *u8, mlen: c_uint, sig: *mut u8, siglen: *mut c_uint,
                k: *RSA) -> c_int;
    pub fn RSA_verify(t: c_int, m: *u8, mlen: c_uint, sig: *u8, siglen: c_uint,
                  k: *RSA) -> c_int;

    pub fn RAND_bytes(buf: *mut u8, num: c_int) -> c_int;

    pub fn HMAC_CTX_init(ctx: *mut HMAC_CTX, key: *u8, keylen: c_int, md: EVP_MD);
    pub fn HMAC_Update(ctx: *mut HMAC_CTX, input: *u8, len: c_uint);
    pub fn HMAC_Final(ctx: *mut HMAC_CTX, output: *mut u8, len: *mut c_uint);

    pub fn PKCS5_PBKDF2_HMAC_SHA1(pass: *u8, passlen: c_int,
                              salt: *u8, saltlen: c_int,
                              iter: c_int, keylen: c_int,
                              out: *mut u8) -> c_int;
}
