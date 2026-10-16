//! Published SMB 3 examples run through the server's key derivation,
//! signing, and encryption.
//!
//! "SMB 3.1.1 Encryption in Windows 10", appendix A (Microsoft Open
//! Specifications blog):
//! https://learn.microsoft.com/en-us/archive/blogs/openspecification/smb-3-1-1-encryption-in-windows-10
//! "SMB 3.1.1 Pre-authentication integrity in Windows 10", appendix B:
//! https://learn.microsoft.com/en-us/archive/blogs/openspecification/smb-3-1-1-pre-authentication-integrity-in-windows-10
//! "SMB 2 and SMB 3 security in Windows 10: the anatomy of signing and
//! cryptographic keys", SMB 3.0 example:
//! https://learn.microsoft.com/en-us/archive/blogs/openspecification/smb-2-and-smb-3-security-in-windows-10-the-anatomy-of-signing-and-cryptographic-keys
//!
//! The examples name keys from the client's side: the client's
//! EncryptionKey is the server's decryption key and the reverse.

extern crate std;

use std::vec::Vec;

use super::Cipher;
use super::EncryptionKeys;
use super::Nonce;
use super::PreauthHash;
use super::SigningAlgorithm;
use super::TRANSFORM_HEADER;
use super::decrypt;
use super::derive_keys;
use super::encrypt;
use super::signature;
use super::verify;
use crate::auth::SessionKey;
use crate::crypto::tests::decode_hex;
use crate::server::tables::SessionId;
use crate::server::wire::Dialect;

/// Session identifier of the AES-GCM example.
const GCM_SESSION: u64 = 0x0000_1000_0000_0025;
/// Session identifier of the AES-CCM example.
const CCM_SESSION: u64 = 0x0000_1000_0000_0021;

const GCM_NEGOTIATE_REQUEST: &str = concat!(
    "fe534d4240000100000000000000010000000000000000000000000000000000",
    "fffe000000000000000000000000000000000000000000000000000000000000",
    "2400050001000000660000004f0d7fa009f5b246b2ef62551d7d7c0970000000",
    "020000000202100200030203110300000100260000000000010020000100d170",
    "9d7196e1bd0b6ebf95213d76553435763514392649fd6f216ed8bf269cd80000",
    "0200060000000000020002000100",
);

const GCM_HASH_AFTER_NEGOTIATE_REQUEST: &str = concat!(
    "550442daf311412870ad9e58e602b0312d61328d6b1ac28f22af46d6ea581f23",
    "a9bfabe0cc0411976bf3f9da23d3433352cb48cf00b8659bc1a3695e1b1a52a8",
);

const GCM_NEGOTIATE_RESPONSE: &str = concat!(
    "fe534d4240000100000000000000010001000000000000000000000000000000",
    "fffe000000000000000000000000000000000000000000000000000000000000",
    "410001001103020039cbcaf329714942bdce5d60f09ab3fb2700000000008000",
    "0000800000008000d1168e69cdaed00109094ab095aed00180004001c0010000",
    "6082013c06062b0601050502a08201303082012ca01a3018060a2b0601040182",
    "3702021e060a2b06010401823702020aa282010c048201084e45474f45585453",
    "01000000000000006000000070000000807cc0fd06d6362d02dde1cf343bfe29",
    "c16aa4ea4741fb0ef645dc5c5d3c3e6a8de5d0baef7a06dc070076174356eda0",
    "0000000000000000600000000100000000000000000000005c33530deaf90d4d",
    "b2ec4ae3786ec3084e45474f4558545303000000010000004000000098000000",
    "807cc0fd06d6362d02dde1cf343bfe295c33530deaf90d4db2ec4ae3786ec308",
    "40000000580000003056a05430523027802530233121301f0603550403131854",
    "6f6b656e205369676e696e67205075626c6963204b6579302780253023312130",
    "1f06035504031318546f6b656e205369676e696e67205075626c6963204b6579",
    "0100260000000000010020000100b51c002c28941192737a08344b05ce90786e",
    "ec146d99cdb60ae44e5a86127d270000020004000000000001000200",
);

const GCM_HASH_AFTER_NEGOTIATE: &str = concat!(
    "abe4da6e875f6fb05033af04dcc38c92888b4e13d1eab7aa05cade142064974c",
    "b3eab0782600549ba27207aa213b0d190b9950fa36d45be32a888bfee8389b74",
);

const GCM_SETUP_REQUEST_1: &str = concat!(
    "fe534d4240000100000000000100800000000000000000000100000000000000",
    "fffe000000000000000000000000000000000000000000000000000000000000",
    "19000001010000000000000058004a000000000000000000604806062b060105",
    "0502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d5353",
    "500001000000978208e200000000000000000000000000000000060380250000",
    "000f",
);

const GCM_HASH_AFTER_SETUP_REQUEST_1: &str = concat!(
    "a5e8ab87e2adb8fa5f4545d20f1fd2019d66ccd0f4dfd1f762f1dfc8dcb15b98",
    "d0bd1f1450f6a0afc70f80b353c2d959217681949cf22df35f31257a281c6a80",
);

const GCM_SETUP_RESPONSE_1: &str = concat!(
    "fe534d4240000100160000c00100010001000000000000000100000000000000",
    "fffe000000000000250000000010000000000000000000000000000000000000",
    "090000004800b300a181b03081ada0030a0101a10c060a2b0601040182370202",
    "0aa281970481944e544c4d53535000020000000c000c003800000015828ae25f",
    "c0cb7f886e93d6000000000000000050005000440000000a0092270000000f53",
    "005500540033003100310002000c0053005500540033003100310001000c0053",
    "005500540033003100310004000c0053005500540033003100310003000c0053",
    "005500540033003100310007000800248d5c6ccdaed00100000000",
);

const GCM_HASH_AFTER_SETUP_RESPONSE_1: &str = concat!(
    "9a095455244172898902b0fbdf5fefafd8435bb66a47eb55cb7542732a423f58",
    "b12b3ed698bef3878d8a346fd9f5cc882da37aaf2a939290e98b935fc72b3944",
);

const GCM_SETUP_REQUEST_2: &str = concat!(
    "fe534d4240000100000000000100800000000000000000000200000000000000",
    "fffe000000000000250000000010000000000000000000000000000000000000",
    "1900000101000000000000005800cf010000000000000000a18201cb308201c7",
    "a0030a0101a28201aa048201a64e544c4d535350000300000018001800900000",
    "00ee00ee00a80000000c000c00580000001a001a0064000000120012007e0000",
    "001000100096010000158288e2060380250000000fa5e34268ef143be5816251",
    "d02c564e9b530055005400330031003100610064006d0069006e006900730074",
    "007200610074006f007200440052004900560045005200330031003100000000",
    "0000000000000000000000000000000000000000002c263da5c2d54785e8eda0",
    "552472d3a30101000000000000248d5c6ccdaed001bea7a53e2dc098eb000000",
    "0002000c0053005500540033003100310001000c005300550054003300310031",
    "0004000c0053005500540033003100310003000c005300550054003300310031",
    "0007000800248d5c6ccdaed00106000400020000000800300030000000000000",
    "000000000000300000b61fefcaa857ea57bf1edcebf8974b8e0eba5a6dfd9d07",
    "a31d11b548f8c9d0cc0a00100000000000000000000000000000000000090016",
    "0063006900660073002f00530055005400330031003100000000000000000000",
    "000000133fa6ea154880bb44576c6e2490bde7a31204100100000067890bd408",
    "f5680d00000000",
);

const GCM_SESSION_HASH: &str = concat!(
    "b23f3cbfd69487d9832b79b1594a367cdd950909b774c3a4c412b4fcea9edddb",
    "a7db256ba2ea30e977f11f9b113247578e0e915c6d2a513b8f2fca5707dc8770",
);

const GCM_SETUP_RESPONSE_2: &str = concat!(
    "fe534d4240000100000000000100800009000000000000000200000000000000",
    "fffe00000000000025000000001000006b85a4519a0f3eea35ba946dd3afe6b8",
    "0900000048001d00a11b3019a0030a0100a3120410010000003932a87523ab66",
    "0100000000",
);

const GCM_WRITE_REQUEST: &str = concat!(
    "fe534d4240000100000000000900010008000000000000000500000000000000",
    "fffe000001000000250000000010000000000000000000000000000000000000",
    "3100700017000000000000000000000006000000040000000100000004000000",
    "00000000000000007000000000000000536d623320656e6372797074696f6e20",
    "74657374696e67",
);

const GCM_WRITE_REQUEST_TRANSFORMED: &str = concat!(
    "fd534d42bd73d97d2bc9001bcafac0fdff5feebcc7d6822d269caf48904c664c",
    "00000000870000000000010025000000001000006ecdd2a7afc7b47763057a04",
    "1b8fd4daffe990b70c9e09d36c084e02d14ef247f8bde38acf6256f8b1d3b56f",
    "77fbdeb312fea5e92cbcc1ed8fb2ebbfaa75e49a4a394bb44576545567c24d4c",
    "014d47c9fbdfdafd2c4f9b72f8d256452620a299f48e29e53d6b61d1c13a19e9",
    "1af013f00d17e3abc2fc3d36c8c1b6b93973253852dbd442e46ee8",
);

const GCM_WRITE_RESPONSE_TRANSFORMED: &str = concat!(
    "fd534d42acbe1cb7ed343adf1725ef144d90d4b0e06831dd2e8eb7b400000000",
    "000000005000000000000100250000000010000026bbbf949983a6c1c796559d",
    "0f2c510cb651d1f7b6ac8ded32a2a0b8f2d793a815c6f6b848d69767a215841a",
    "42d400ae6ddb5f0b44173a014973321fdd7950da6179159b82e03c9e18a050ff",
    "0ea1c967",
);

const GCM_WRITE_RESPONSE: &str = concat!(
    "fe534d4240000100000000000900010001000000000000000500000000000000",
    "fffe000001000000250000000010000000000000000000000000000000000000",
    "11000000170000000000000000000000",
);

const GCM_READ_REQUEST: &str = concat!(
    "fe534d4240000100000000000800010008000000000000000600000000000000",
    "fffe000001000000250000000010000000000000000000000000000000000000",
    "3100000017000000000000000000000006000000040000000100000004000000",
    "0000000000000000000000000000000000",
);

const GCM_READ_REQUEST_TRANSFORMED: &str = concat!(
    "fd534d426dac0b6fd85a3ed42bb917da38fe0386d7aa8c6d36859243b715e0a6",
    "000000007100000000000100250000000010000088a47bf09ca3c3141cdd7306",
    "be9d9475ab24fccb833d77461c041f8fb983d0c188f0729272b31d9d3d0dc6b6",
    "87c069eee0cc8eaca2c536d019acc9e185d1eb630e0fcb793eeeceb06d82a1d7",
    "7706e700dbebfb4feb54d7ad2d97e7288804f90757fe4d08d6a84a3ff433e745",
    "1e768e4699",
);

const GCM_READ_RESPONSE_TRANSFORMED: &str = concat!(
    "fd534d427f714b3b9d8fa1198584e71c2baa1cb6e16831dd2e8eb7b400000000",
    "0000000067000000000001002500000000100000fecedf4d03bb11a6cc5d8a53",
    "be33d6d8701986342b4197d306e16f9cbb218e92f7f8281f51ce68bb85a20d87",
    "de90ebbf80538066d1c37513c0a58d70936d537b624f5500202a612b6cd30d44",
    "8a82791a0b2e049ed512afaefb06e98ab3d6f931d7d50db2dbd36a",
);

const GCM_READ_RESPONSE: &str = concat!(
    "fe534d4240000100000000000800010001000000000000000600000000000000",
    "fffe000001000000250000000010000000000000000000000000000000000000",
    "11005000170000000000000000000000536d623320656e6372797074696f6e20",
    "74657374696e67",
);

const CCM_SESSION_HASH: &str = concat!(
    "decf98a420718718f22090d3580fcc5e484bd310fa1268210c6e86335a8891e7",
    "67f5bcd99fa5a7859d665ad07a73ea94e1bcdb7cfa69a6962a28a244138340b1",
);

const CCM_SETUP_RESPONSE_2: &str = concat!(
    "fe534d4240000100000000000100800009000000000000000200000000000000",
    "fffe00000000000021000000001000003676196aee8ca17e5d50a53642ef2be4",
    "0900000048001d00a11b3019a0030a0100a3120410010000000f57444342a271",
    "7e00000000",
);

const CCM_WRITE_REQUEST: &str = concat!(
    "fe534d4240000100000000000900010008000000000000000500000000000000",
    "fffe000001000000210000000010000000000000000000000000000000000000",
    "3100700017000000000000000000000005000000040000000100000004000000",
    "00000000000000007000000000000000536d623320656e6372797074696f6e20",
    "74657374696e67",
);

const CCM_WRITE_REQUEST_TRANSFORMED: &str = concat!(
    "fd534d42e89551d666dab8993488f5a97103116c9f6f1eaad7e9f24aacd38f00",
    "000000008700000000000100210000000010000056a74778199a9d2b6e9c3a37",
    "6fd88d27680694fed253a313beb07381ae8689f973acdb8d716e4477803bce53",
    "a92e1b81fa3e965ad9af2c89c08ce66a344664453b8fc88118edc9814cf58e92",
    "aa465e6efb09958a9fdad96fbd55b36a710c30d5e7c64ad7b9449f9f17edd024",
    "fe8ba79154f340a82740d1d5180c69b0a2de6a4ba893bd55d3210e",
);

const CCM_WRITE_RESPONSE_TRANSFORMED: &str = concat!(
    "fd534d42dd33ec41a927dd51476fe887c2d3c136d96831dd2e8eb7b400000000",
    "0000000050000000000001002100000000100000f783157e0f6f1c055d746753",
    "ca16d20c21088e2a67564e056c2f68a7f14f226c3bd809b7a2d52e5fe4ecf498",
    "21bc6001733430cf174e2764b3ccb213aad8bb9fbaf6c15e13d9120965390e00",
    "4a96a3f7",
);

const CCM_WRITE_RESPONSE: &str = concat!(
    "fe534d4240000100000000000900010001000000000000000500000000000000",
    "fffe000001000000210000000010000000000000000000000000000000000000",
    "11000000170000000000000000000000",
);

const CCM_READ_REQUEST: &str = concat!(
    "fe534d4240000100000000000800010008000000000000000600000000000000",
    "fffe000001000000210000000010000000000000000000000000000000000000",
    "3100000017000000000000000000000005000000040000000100000004000000",
    "0000000000000000000000000000000000",
);

const CCM_READ_REQUEST_TRANSFORMED: &str = concat!(
    "fd534d4235bf9600c841f0cda9bd1bc3727b7e36a0f92e964edc3049b86e1900",
    "0000000071000000000001002100000000100000c4ccd3eb483a0638e69c99e3",
    "91e7f64bcc10d6bee46feea258c4bcaf792cb5a6e69283924081806dab64827e",
    "9d14a5345d5221ab6dafcb0e89fc2606b63d92163f4f6c93d1213d86abf123b9",
    "3ead3aef9a3471efd68a423a00a6e0064d9ae3c842efffad236a3bf25d37f4cd",
    "054c97de18",
);

const CCM_READ_RESPONSE_TRANSFORMED: &str = concat!(
    "fd534d42e241a13c7e1ee42ecf1fd69f3b8668c6da6831dd2e8eb7b400000000",
    "000000006700000000000100210000000010000015d67234fc8358d7ba1bf037",
    "abc8efd41a0a8f9bb04b16deb1e85606bd8c2770823fe6239a286cb3e3d5762a",
    "bbd53fd8de11ed491fe905e146a8ffce09414ab741103d637e28b19c6ba759b3",
    "99dcc21fae24cf2a455a13b215fc2857abb513927f9f271d1c208b",
);

const CCM_READ_RESPONSE: &str = concat!(
    "fe534d4240000100000000000800010001000000000000000600000000000000",
    "fffe000001000000210000000010000000000000000000000000000000000000",
    "11005000170000000000000000000000536d623320656e6372797074696f6e20",
    "74657374696e67",
);

const PREAUTH_SESSION_HASH: &str = concat!(
    "cb3320852ed35231f1087e6a4828c129384f7041005ff76543b46b1590574300",
    "b376771109c29903d0a5e6eb124a3bca8dd9cf0fbf2ef60f2fed746a70ce0533",
);

const PREAUTH_SETUP_RESPONSE: &str = concat!(
    "fe534d4240000100000000000100800009000000000000000300000000000000",
    "fffe0000000000000d000000001c0000bce812303d9bcd5d3295ef0572553aeb",
    "0900000048001d00a11b3019a0030a0100a31204100100000017dd19d27e10a5",
    "5d00000000",
);

fn bytes(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn hash(text: &str) -> PreauthHash {
    PreauthHash(decode_hex(text))
}

fn gcm_keys() -> EncryptionKeys {
    EncryptionKeys {
        cipher: Cipher::Aes128Gcm,
        encryption: decode_hex("748c50868c90f302962a5c35f5f9a8bf"),
        decryption: decode_hex("a2f5e80e5d59103034f32e52f698e5ec"),
    }
}

fn ccm_keys() -> EncryptionKeys {
    EncryptionKeys {
        cipher: Cipher::Aes128Ccm,
        encryption: decode_hex("95c544aef6072680da1ce49a68a97fa6"),
        decryption: decode_hex("dfaaa31aae40a2485d47ac4df09fda1d"),
    }
}

#[test]
fn preauth_hash_follows_the_negotiate_and_session_setup_exchange() {
    let after_request = PreauthHash::ZERO.update(&bytes(GCM_NEGOTIATE_REQUEST));
    assert_eq!(after_request, hash(GCM_HASH_AFTER_NEGOTIATE_REQUEST));
    let connection = after_request.update(&bytes(GCM_NEGOTIATE_RESPONSE));
    assert_eq!(connection, hash(GCM_HASH_AFTER_NEGOTIATE));
    let session = connection.update(&bytes(GCM_SETUP_REQUEST_1));
    assert_eq!(session, hash(GCM_HASH_AFTER_SETUP_REQUEST_1));
    let session = session.update(&bytes(GCM_SETUP_RESPONSE_1));
    assert_eq!(session, hash(GCM_HASH_AFTER_SETUP_RESPONSE_1));
    let session = session.update(&bytes(GCM_SETUP_REQUEST_2));
    assert_eq!(session, hash(GCM_SESSION_HASH));
}

#[test]
fn smb_3_1_1_keys_of_the_examples() {
    for (session_key, preauth, cipher, signing, keys) in [
        (
            "419fddf34c1e001909d362ae7fb6af79",
            GCM_SESSION_HASH,
            Cipher::Aes128Gcm,
            "8765949dfeaee105ce9118b45be988f0",
            gcm_keys(),
        ),
        (
            "07b7f69c1e2581662df6987e88f9e891",
            CCM_SESSION_HASH,
            Cipher::Aes128Ccm,
            "3dcc82c5795ae27f383242761078c59b",
            ccm_keys(),
        ),
    ] {
        let (signing_key, encryption) = derive_keys(
            Dialect::SMB_3_1_1,
            &SessionKey(decode_hex(session_key)),
            &hash(preauth),
            SigningAlgorithm::AesCmac,
            Some(cipher),
        );
        assert_eq!(signing_key.key, decode_hex::<16>(signing));
        assert_eq!(signing_key.algorithm, SigningAlgorithm::AesCmac);
        assert_eq!(encryption, Some(keys));
    }
    let (signing_key, encryption) = derive_keys(
        Dialect::SMB_3_1_1,
        &SessionKey(decode_hex("a8b3fcb8c96884ba9126132ae5b076af")),
        &hash(PREAUTH_SESSION_HASH),
        SigningAlgorithm::AesCmac,
        None,
    );
    assert_eq!(
        signing_key.key,
        decode_hex::<16>("5756ac382298721282d4d9f61cf1195f")
    );
    assert_eq!(encryption, None);
}

#[test]
fn smb_3_0_keys_of_the_example() {
    let (signing_key, encryption) = derive_keys(
        Dialect::SMB_3_0,
        &SessionKey(decode_hex("7cd451825d0450d235424e44ba6e78cc")),
        &PreauthHash::ZERO,
        SigningAlgorithm::AesGmac,
        Some(Cipher::Aes128Ccm),
    );
    assert_eq!(
        signing_key.key,
        decode_hex::<16>("0b7e9c5cac36c0f6ea9ab275298cedce")
    );
    // SMB 3.0 signs with AES-CMAC whatever the connection offered.
    assert_eq!(signing_key.algorithm, SigningAlgorithm::AesCmac);
    assert_eq!(
        encryption,
        Some(EncryptionKeys {
            cipher: Cipher::Aes128Ccm,
            encryption: decode_hex("b0f0427f7ceb416d1d9dcc0cd4f99447"),
            decryption: decode_hex("fad27796665b313ebb578f388632b4f7"),
        })
    );
}

#[test]
fn final_session_setup_responses_carry_the_example_signatures() {
    for (response, key) in [
        (GCM_SETUP_RESPONSE_2, "8765949dfeaee105ce9118b45be988f0"),
        (CCM_SETUP_RESPONSE_2, "3dcc82c5795ae27f383242761078c59b"),
        (PREAUTH_SETUP_RESPONSE, "5756ac382298721282d4d9f61cf1195f"),
    ] {
        let response = bytes(response);
        let key = super::SigningKey {
            key: decode_hex(key),
            algorithm: SigningAlgorithm::AesCmac,
        };
        assert_eq!(signature(&response, &key), response[48..64]);
        assert!(verify(&response, &key));
        let mut altered = response.clone();
        altered[64] ^= 1;
        assert!(!verify(&altered, &key));
    }
}

#[test]
fn decrypts_the_example_requests() {
    for (transformed, plain, keys) in [
        (GCM_WRITE_REQUEST_TRANSFORMED, GCM_WRITE_REQUEST, gcm_keys()),
        (GCM_READ_REQUEST_TRANSFORMED, GCM_READ_REQUEST, gcm_keys()),
        (CCM_WRITE_REQUEST_TRANSFORMED, CCM_WRITE_REQUEST, ccm_keys()),
        (CCM_READ_REQUEST_TRANSFORMED, CCM_READ_REQUEST, ccm_keys()),
    ] {
        let plain = bytes(plain);
        let mut message = bytes(transformed);
        assert_eq!(decrypt(&mut message, &keys), Some(plain.len()));
        assert_eq!(message[TRANSFORM_HEADER..], plain[..]);

        // A changed byte of the ciphertext, the tag, or the authenticated
        // header fails.
        for offset in [TRANSFORM_HEADER + 3, 4, 20, 44] {
            let mut message = bytes(transformed);
            message[offset] ^= 0x01;
            assert_eq!(decrypt(&mut message, &keys), None, "offset {offset}");
        }
    }
}

#[test]
fn encrypts_the_example_responses() {
    for (plain, transformed, keys, session) in [
        (
            GCM_WRITE_RESPONSE,
            GCM_WRITE_RESPONSE_TRANSFORMED,
            gcm_keys(),
            GCM_SESSION,
        ),
        (
            GCM_READ_RESPONSE,
            GCM_READ_RESPONSE_TRANSFORMED,
            gcm_keys(),
            GCM_SESSION,
        ),
        (
            CCM_WRITE_RESPONSE,
            CCM_WRITE_RESPONSE_TRANSFORMED,
            ccm_keys(),
            CCM_SESSION,
        ),
        (
            CCM_READ_RESPONSE,
            CCM_READ_RESPONSE_TRANSFORMED,
            ccm_keys(),
            CCM_SESSION,
        ),
    ] {
        let expected = bytes(transformed);
        // The server's nonces are an 8-byte counter followed by zeros.
        assert!(expected[28..36].iter().all(|&byte| byte == 0));
        let nonce = u64::from_le_bytes(expected[20..28].try_into().unwrap());
        let mut message = [&[0u8; TRANSFORM_HEADER][..], &bytes(plain)].concat();
        assert_eq!(
            encrypt(&mut message, &keys, SessionId(session), Nonce(nonce)),
            Some(())
        );
        assert_eq!(message, expected);
    }
}
