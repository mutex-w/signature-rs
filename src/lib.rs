use base64::encode;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

pub enum Algorithm<'a> {
    HmacSha256(&'a str),
    HmacSha512(&'a str),
    HmacSha256Base64(&'a str),
}

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

impl<'a> Algorithm<'a> {
    pub fn verify(&self, message: &str, digest: &[u8]) -> bool {
        match self {
            Algorithm::HmacSha256(secret) => {
                let mac = HmacSha256::new_varkey(secret.as_bytes()).unwrap();
                hmac_verify(mac, message, digest)
            }
            Algorithm::HmacSha512(secret) => {
                let mac = HmacSha512::new_varkey(secret.as_bytes()).unwrap();
                hmac_verify(mac, message, digest)
            }
            Algorithm::HmacSha256Base64(secret) => {
                let mac = HmacSha256::new_varkey(secret.as_bytes()).unwrap();
                hmac_base64_verify(mac, message, digest)
            }
        }
    }
}

fn hmac_verify(mut mac: impl Mac, message: &str, digest: &[u8]) -> bool {
    mac.input(message.as_bytes());
    if let Ok(_) = mac.verify(digest) {
        true
    } else {
        false
    }
}

fn hmac_base64_verify(mut mac: impl Mac, message: &str, digest: &[u8]) -> bool {
    mac.input(message.as_bytes());
    let code_bytes = mac.result().code();
    encode(&code_bytes).as_bytes() == digest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_sha256_verify() {
        let secret = "my secret key";
        let mac = HmacSha256::new_varkey(secret.as_bytes()).unwrap();
        let algorithm = Algorithm::HmacSha256(secret);
        hmac_verify(mac, &algorithm);
    }

    #[test]
    fn hmac_sha512_verify() {
        let secret = "my secret key";
        let mac = HmacSha512::new_varkey(secret.as_bytes()).unwrap();
        let algorithm = Algorithm::HmacSha512(secret);
        hmac_verify(mac, &algorithm);
    }

    #[test]
    fn hmac_sha256_base64_verify() {
        let secret = "my secret key";
        let mac = HmacSha256::new_varkey(secret.as_bytes()).unwrap();
        let algorithm = Algorithm::HmacSha256Base64(secret);
        hmac_base64_verify(mac, &algorithm);
    }

    fn hmac_verify(mut mac: impl Mac, algorithm: &Algorithm) {
        let message = "my message";
        mac.input(message.as_bytes());
        let digest = mac.result().code();
        assert!(algorithm.verify(message, &digest))
    }

    fn hmac_base64_verify(mut mac: impl Mac, algorithm: &Algorithm) {
        let message = "my message";
        mac.input(message.as_bytes());
        let digest = mac.result().code();
        assert!(algorithm.verify(message, encode(&digest).as_bytes()))
    }
}
