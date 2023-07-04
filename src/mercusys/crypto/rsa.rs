// The router happen to be using the same source code but minified:
//   see: http://www-cs-students.stanford.edu/~tjw/jsbn/rsa.js
// This is a more-or-less "close enough" re-implementation of it.

use num::bigint::ParseBigIntError;
use num::BigUint;
use num::Num;

#[derive(Debug, Clone)]
pub struct RSAPadError;

fn non_zero_rand(buf: &mut [u8]) {
    if cfg!(any(test, feature = "no_rand")) {
        for v in buf.iter_mut() {
            *v = 0xcc_u8;
        }
    } else {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        for v in buf.iter_mut() {
            *v = rng.gen_range(0x01u8..=0xff_u8);
        }
    }
}

/// PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
pub fn pkcs1pad2<D: AsMut<[u8]>, S: AsRef<[u8]>>(input: S, buf: &mut D) -> Result<(), RSAPadError> {
    let buf = buf.as_mut();
    let input = input.as_ref();

    let buf_len = buf.len();
    let input_len = input.len();
    if buf_len < input_len + 11 {
        return Err(RSAPadError);
    }

    let input_start_pos = buf_len - input_len;
    buf[input_start_pos..].copy_from_slice(input);
    buf[input_start_pos - 1] = 0;
    non_zero_rand(&mut buf[2..input_start_pos - 1]);
    buf[0] = 0;
    buf[1] = 2;

    Ok(())
}

pub struct RSAKey {
    n: BigUint,
    e: BigUint,
}

impl RSAKey {
    pub fn new(n: &str, e: &str) -> Result<RSAKey, ParseBigIntError> {
        let n = BigUint::from_str_radix(n, 16)?;
        let e = BigUint::from_str_radix(e, 16)?;
        Ok(RSAKey { n, e })
    }

    pub fn encrypt(&self, text: &str) -> Result<String, RSAPadError> {
        // (bits + 7) >> 3
        let message_len = (self.n.bits() as usize).wrapping_add(7).wrapping_shr(3);
        let mut message = vec![0u8; message_len];
        pkcs1pad2(text.as_bytes(), &mut message)?;
        let message = BigUint::from_bytes_be(&message);
        let encrypted = message.modpow(&self.e, &self.n);
        Ok(encrypted.to_str_radix(16))
    }
}

pub fn rsa_encrypt(message: &str, encrypt_key_n: &str, encrypt_key_e: &str) -> String {
    let rsa_key = RSAKey::new(encrypt_key_n, encrypt_key_e).unwrap();
    rsa_key.encrypt(message).unwrap()
}

#[test]
fn pkcs1pad2_test() {
    let input = "test".as_bytes();
    let mut buf = [0xcc_u8; 20];
    assert!(pkcs1pad2(input, &mut buf).is_ok());

    let expected: [u8; 20] = [
        0, 2, // header
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // padding
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, //
        0, b't', b'e', b's', b't', // data
    ];
    assert_eq!(&expected[..], &buf[..]);
}

#[test]
fn rsa_key_encrypt_test() {
    let expected = "a13de2f14b3cc1161dc16cf9958b49d72cbf8edf36a6d7b29b89c3502971bdc5c2b247d50ded977a3e2d978398576a698871e476c7eed423b9cb6fb4ce4c4711a073b7b88a854cddd3342553a26fed08c0ea007215ae57a905ebf78abc0b7a35073d91fa29f541d3b136ca53a76cae9a41a62a36758fdbe64cf057015e255e7a";
    let actual = rsa_encrypt("12345", "A5261939975948BB7A58DFFE5FF54E65F0498F9175F5A09288810B8975871E99AF3B5DD94057B0FC07535F5F97444504FA35169D461D0D30CF0192E307727C065168C788771C561A9400FB49175E9E6AA4E23FE11AF69E9412DD23B0CB6684C4C2429BCE139E848AB26D0829073351F4ACD36074EAFD036A5EB83359D2A698D3", "10001");
    assert_eq!(actual, expected);
}
