use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

pub fn aes_128_cbc_encrypt<T: AsRef<[u8]>>(data: T, key: &str, iv: &str) -> Vec<u8> {
    Aes128CbcEnc::new_from_slices(key.as_bytes(), iv.as_bytes())
        .unwrap()
        .encrypt_padded_vec_mut::<Pkcs7>(data.as_ref())
}

pub fn aes_128_cbc_decrypt<T: AsRef<[u8]>>(data: T, key: &str, iv: &str) -> Vec<u8> {
    Aes128CbcDec::new_from_slices(key.as_bytes(), iv.as_bytes())
        .unwrap()
        .decrypt_padded_vec_mut::<Pkcs7>(data.as_ref())
        .unwrap()
}
