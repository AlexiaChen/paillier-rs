// Copyright 2022 MathxH Chen.
//
// Code is licensed under MIT License.

//! # Paillier
//!
//! Just an implementation of [Paillier Cryptosystem](https://en.wikipedia.org/wiki/Paillier_cryptosystem) written in Rust.
//!
//! ## Documents
//!
//! See [Github README](https://github.com/AlexiaChen/paillier-rs/blob/master/README.md)

use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num_primes::Generator;
use num_traits::identities::{One, Zero};
use std::clone::Clone;
use std::ops::{Mul, Sub};

/// PubKey -- Publick Key
#[derive(Debug, Clone, Default)]
pub struct PubKey {
    pub g: BigInt,  // g = n + 1
    pub n: BigInt,  // n = p*q
    pub nn: BigInt, // n^2
}

/// PrivKey -- Private Key
pub struct PrivKey {
    pub lambda: BigInt, // lambda = lcm(p - 1, q - 1)
    pub mu: BigInt, // https://en.wikipedia.org/wiki/Mu_(letter)  mu = （L(g^lambda mod n^2)）^-1 mod n
    pub pk: PubKey,
}

/// KeyPair -- includes public key and privatekey
pub struct KeyPair(PrivKey);

/// make_key_pair -- Generate pk and sk
pub fn make_key_pair(bitlen: usize) -> Option<KeyPair> {
    let p = Generator::new_prime(bitlen).to_bigint().unwrap();
    let q = Generator::new_prime(bitlen).to_bigint().unwrap();
    let n = &p * &q;
    let nn = &n * &n;

    // Select random integer g where g ∈ Z_(n^2)*
    // but If using p,q of equivalent length,
    // a simpler variant of the above key generation steps would be to set
    // g = n + 1, lambda = phi(n), mu = phi(n)^-1 mod n,  phi(n) = (p - 1)*(q - 1)
    // The simpler variant is recommended for implementational purposes,
    // because in the general form the calculation time of mu
    // can be very high with sufficiently large primes p,q.
    // https://crypto.stackexchange.com/questions/8276/what-does-mathbbz-n2-mean
    let g = &n + BigInt::one();

    // lambda = phi(n)
    let lambda = phi(&p, &q);

    // mu = phi(n)^-1 mod n = lambda^-1 mod n = inverse lambda mod n
    let mu = mod_inverse(&lambda, &n).unwrap();

    let pk = PubKey { g, n, nn };

    Some(KeyPair(PrivKey { lambda, mu, pk }))
}

//////////////////// Enrypt & Decrypt /////////////////////////////////////

impl PubKey {
    /// encrypt message to ciphertext
    pub fn encrypt_message(&self, msg: &str) -> Option<BigInt> {
        let msg_int = BigUint::from_bytes_be(msg.as_bytes()).to_bigint().unwrap();
        self.encrypt(&msg_int)
    }

    /// ecrypt integer message to ciphertext
    /// Encrypt: additive group A -> additive group B
    pub fn encrypt(&self, m: &BigInt) -> Option<BigInt> {
        // Let m be a message to be encrypted where 0 <= m < n
        if m >= &BigInt::zero() && m < &self.n {
            // select random r where 0 < r < n
            let mut rng = rand::thread_rng();
            let r = rng.gen_bigint_range(&BigInt::one(), &self.n);

            // compute ciphertext c = g^m * r^n (mod n^2)
            let g_m = self.g.modpow(m, &self.nn);
            let r_n = r.modpow(&self.n, &self.nn);
            let c = (g_m * r_n) % &self.nn;
            Some(c)
        } else {
            None
        }
    }
}

impl PrivKey {
    /// decrypt ciphertext to plain text
    pub fn decrypt_message(&self, ciphertext: &BigInt) -> Option<String> {
        let plain_text_int = self.decrypt(ciphertext).unwrap();
        Some(String::from_utf8(plain_text_int.to_biguint().unwrap().to_bytes_be()).unwrap())
    }

    /// decrypt cipertext to integer message
    /// additive group B -> additive group A
    pub fn decrypt(&self, ciphertext: &BigInt) -> Option<BigInt> {
        if is_cipher_valid(ciphertext, &self.pk.nn) {
            // Compute the plaintext message as m = L(c^lambda mod n^2) * mu mod n
            let c_lambda = ciphertext.modpow(&self.lambda, &self.pk.nn);
            let l_ = l(&c_lambda, &self.pk.n);
            let m = (l_ * &self.mu) % &self.pk.n;
            Some(m)
        } else {
            None
        }
    }
}

//////////////////////// Homomorphic properties ////////////////////////////////

impl PubKey {
    /// D(E(m1) * E(m2) mod n^2) = m1 + m2 mod n    this formula not efficient, cause operation E has more OP steps
    /// => D(E(m1) * g^m2 mod n^2) = m1 + m2 mod n     That is efficient, Simplified steps
    /// D(add_plain_text(E(m1), m2)) = m1 + m2 mod n
    /// returns added msg encrypted result
    /// add_plain_text(&self, ciphertext: &BigInt, msg: &str) -> Option<BigInt>
    pub fn add_plain_text(&self, ciphertext: &BigInt, msg: &BigInt) -> Option<BigInt> {
        if is_cipher_valid(ciphertext, &self.nn) {
            // ciphertext * g^m2 mod N^2
            // => ciphertext(E(m1)) * ciphertext2(E(m2)) mod N^2
            let ciphertext2 = self.g.modpow(msg, &self.nn);
            Some(ciphertext.mul(ciphertext2) % &self.nn)
        } else {
            None
        }
    }

    /// D(add(E(m1), E(m2))) = m1 + m2 mod n
    /// returns added sum of two encrypted data
    pub fn add(&self, ciphertext1: &BigInt, ciphertext2: &BigInt) -> Option<BigInt> {
        if !is_cipher_valid(ciphertext1, &self.nn) || !is_cipher_valid(ciphertext2, &self.nn) {
            return None;
        }

        // D(E(m1) * E(m2) mod n^2) = m1 + m2 mod n
        Some(ciphertext1.mul(ciphertext2) % &self.nn)
    }

    /// D(sub(E(m1), E(m2))) = E(m1) - E(m2) mod n if m1 > m2
    /// returns sub result of two encrypted data
    pub fn sub(&self, ciphertext1: &BigInt, ciphertext2: &BigInt) -> Option<BigInt> {
        if !is_cipher_valid(ciphertext1, &self.nn) || !is_cipher_valid(ciphertext2, &self.nn) {
            return None;
        }
        let neg_m2 = mod_inverse(ciphertext2, &self.nn).unwrap();
        Some(ciphertext1.mul(neg_m2) % &self.nn)
    }

    /// D(E(m1)^m2 mod n^2) = m1*m2 mod n
    /// => D(E(m2)^m1 mod n^2) = m1*m2 mod n = m2*m1 mod n
    /// => D(E(m)^k mod n^2) = k*m mod n
    /// Dec(mult_plain_text(E(m1), m2)) = m1 * m2 mod n.
    /// returns result of multiplication of two ciphertexts
    /// D(E(m)^k mod n^2) = k*m mod n
    /// Dec(mult_k(E(m1), m2)) = m1 * m2 mod n.
    pub fn mult_plain_text(&self, ciphertext: &BigInt, plain_k: &BigInt) -> Option<BigInt> {
        if !is_cipher_valid(ciphertext, &self.nn) {
            return None;
        }
        Some(ciphertext.modpow(plain_k, &self.nn))
    }

    /// D(E(m)^-k mod n^2) = D(E(m)^(inverse k) mod n^2) = m / k mod n
    /// Dec(div_plain_text(E(m1), m2)) = m1 / m2 mod n.
    /// returns result division  of two ciphertext
    pub fn div_plain_text(&self, ciphertext: &BigInt, plain_k: &BigInt) -> Option<BigInt> {
        if !is_cipher_valid(ciphertext, &self.nn) {
            return None;
        }
        let inverse_k = mod_inverse(plain_k, &self.nn).unwrap();
        self.mult_plain_text(ciphertext, &inverse_k)
    }
}

// L(x) = (x - 1) / n
fn l(x: &BigInt, n: &BigInt) -> BigInt {
    let x1 = x - BigInt::one();
    x1 / n
}

fn phi(p: &BigInt, q: &BigInt) -> BigInt {
    let p1 = p.sub(BigInt::one());
    let q1 = q.sub(BigInt::one());
    p1 * q1
}

fn extend_gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if a == &BigInt::zero() {
        (b.clone(), BigInt::zero(), BigInt::one())
    } else {
        let (g, x, y) = extend_gcd(&(b % a), a);
        (g, y - (b / a) * &x, x)
    }
}

fn mod_inverse(a: &BigInt, modular: &BigInt) -> Option<BigInt> {
    let (g, x, _) = extend_gcd(a, modular);
    if g != BigInt::one() {
        None
    } else {
        let result = (&x % modular + modular) % modular;
        Some(result)
    }
}

// Let c be the ciphertext to decrypt, where c ∈ Z_(n^2)*    0 < c <= n^2 - 1
fn is_cipher_valid(c: &BigInt, nn: &BigInt) -> bool {
    c > &BigInt::zero() && c <= &(nn - BigInt::one())
}

#[cfg(test)]
mod tests {
    use num_traits::{FromPrimitive, ToPrimitive};

    use super::*;

    #[test]
    fn test_text_encrypt_decrypt() {
        const MSG: &str = "secret message";
        let keypair = make_key_pair(1024).unwrap();
        let cipher_text = keypair.0.pk.encrypt_message(MSG).unwrap();
        let plain_text = keypair.0.decrypt_message(&cipher_text).unwrap();
        assert_eq!(MSG, plain_text);
    }

    #[test]
    fn test_int_encrypt_decrypt() {
        {
            const MSG: usize = 2022;
            let keypair = make_key_pair(1024).unwrap();
            let cipher_text = keypair
                .0
                .pk
                .encrypt(&BigInt::from_usize(MSG).unwrap())
                .unwrap();
            let plain_text = keypair.0.decrypt(&cipher_text).unwrap();
            assert_eq!(MSG, plain_text.to_usize().unwrap());
        }

        {
            const MSG: i32 = -1;
            let keypair = make_key_pair(1024).unwrap();
            let cipher_text = keypair.0.pk.encrypt(&BigInt::from_i32(MSG).unwrap());
            assert_eq!(cipher_text.is_none(), true);
        }
    }

    #[test]
    fn test_homo_add_plaintext() {
        let keypair = make_key_pair(1024).unwrap();
        // D(E(6) + E(9)) = 6 + 9
        // D(E(50) + E(50)) = 6 + 9
        let tests = [(6, 9), (50, 50)];
        for test in tests {
            let m1 = BigInt::from_i32(test.0).unwrap();
            let m2 = BigInt::from_i32(test.1).unwrap();
            let sum = &m1 + &m2;

            let encrypted_m1 = keypair.0.pk.encrypt(&m1).unwrap();
            let encrypted_sum = keypair.0.pk.add_plain_text(&encrypted_m1, &m2).unwrap();

            let got = keypair.0.decrypt(&encrypted_sum).unwrap();
            assert_eq!(got, sum);
        }
    }

    #[test]
    fn test_homo_add() {
        let keypair = make_key_pair(1024).unwrap();

        let tests = [(12, 100), (17, 13)];
        for test in tests {
            let m1 = BigInt::from_i32(test.0).unwrap();
            let m2 = BigInt::from_i32(test.1).unwrap();
            let sum = &m1 + &m2;

            let encrypted_m1 = keypair.0.pk.encrypt(&m1).unwrap();
            let encrypted_m2 = keypair.0.pk.encrypt(&m2).unwrap();
            let encrypted_sum = keypair.0.pk.add(&encrypted_m1, &encrypted_m2).unwrap();

            let got = keypair.0.decrypt(&encrypted_sum).unwrap();
            assert_eq!(got, sum);
        }
    }

    #[test]
    fn test_homo_sub() {
        let keypair = make_key_pair(1024).unwrap();

        {
            let tests = [(100, 12), (17, 13)];
            for test in tests {
                let m1 = BigInt::from_i32(test.0).unwrap();
                let m2 = BigInt::from_i32(test.1).unwrap();
                let sum = &m1 - &m2;

                let encrypted_m1 = keypair.0.pk.encrypt(&m1).unwrap();
                let encrypted_m2 = keypair.0.pk.encrypt(&m2).unwrap();
                let encrypted_sum = keypair.0.pk.sub(&encrypted_m1, &encrypted_m2).unwrap();

                let got = keypair.0.decrypt(&encrypted_sum).unwrap();
                assert_eq!(got, sum);
            }
        }

        // must m1 > m2
        {
            let tests = [(12, 100), (13, 17)];
            for test in tests {
                let m1 = BigInt::from_i32(test.0).unwrap();
                let m2 = BigInt::from_i32(test.1).unwrap();
                let sum = &m1 - &m2;

                let encrypted_m1 = keypair.0.pk.encrypt(&m1).unwrap();
                let encrypted_m2 = keypair.0.pk.encrypt(&m2).unwrap();
                let encrypted_sum = keypair.0.pk.sub(&encrypted_m1, &encrypted_m2).unwrap();

                let got = keypair.0.decrypt(&encrypted_sum).unwrap();
                assert_ne!(got, sum);
            }
        }
    }

    #[test]
    fn test_homo_mult_plaintext() {
        let keypair = make_key_pair(1024).unwrap();

        let tests = [(2, 2), (10, 13), (0, 0)];
        for test in tests {
            let m1 = BigInt::from_i32(test.0).unwrap();
            let m2 = BigInt::from_i32(test.1).unwrap();
            let product = &m1 * &m2;

            let encrypted_m1 = keypair.0.pk.encrypt(&m1).unwrap();
            let encrypted_product = keypair.0.pk.mult_plain_text(&encrypted_m1, &m2).unwrap();
            let got = keypair.0.decrypt(&encrypted_product).unwrap();

            assert_eq!(got, product);
        }
    }

    #[test]
    fn test_homo_div_plaintext() {
        let keypair = make_key_pair(1024).unwrap();

        let tests = [(10, 2), (36, 12), (0, 1)];
        for test in tests {
            let m1 = BigInt::from_i32(test.0).unwrap();
            let m2 = BigInt::from_i32(test.1).unwrap();
            let div_res = &m1 / &m2;

            let encrypted_m1 = keypair.0.pk.encrypt(&m1).unwrap();
            let encrypted_div_res = keypair.0.pk.div_plain_text(&encrypted_m1, &m2).unwrap();
            let got = keypair.0.decrypt(&encrypted_div_res).unwrap();

            assert_eq!(got, div_res);
        }
    }

    #[test]
    fn test_homo_all() {
        let keypair = make_key_pair(1024).unwrap();

        {
            const F: i32 = ((7 - 5) * 13 + 4) / 2;
            let target_res = BigInt::from_i32(F).unwrap();

            let encrypted_7 = keypair.0.pk.encrypt(&BigInt::from_i32(7).unwrap()).unwrap();
            let encrypted_5 = keypair.0.pk.encrypt(&BigInt::from_i32(5).unwrap()).unwrap();
            let got_crypted_res = keypair.0.pk.sub(&encrypted_7, &encrypted_5).unwrap();
            let got_crypted_res = keypair
                .0
                .pk
                .mult_plain_text(&got_crypted_res, &BigInt::from_i32(13).unwrap())
                .unwrap();
            let got_crypted_res = keypair
                .0
                .pk
                .add_plain_text(&got_crypted_res, &BigInt::from_i32(4).unwrap())
                .unwrap();
            let got_crypted_res = keypair
                .0
                .pk
                .div_plain_text(&got_crypted_res, &BigInt::from_i32(2).unwrap())
                .unwrap();
            let got = keypair.0.decrypt(&got_crypted_res).unwrap();

            assert_eq!(got, target_res);
        }

        {
            const F: i32 = ((7 - 5) * 13 + 4) / 2;
            let target_res = BigInt::from_i32(F).unwrap();

            let encrypted_7 = keypair.0.pk.encrypt(&BigInt::from_i32(7).unwrap()).unwrap();
            let encrypted_5 = keypair.0.pk.encrypt(&BigInt::from_i32(5).unwrap()).unwrap();
            let got_crypted_res = keypair.0.pk.sub(&encrypted_7, &encrypted_5).unwrap();
            let got_crypted_res = keypair
                .0
                .pk
                .mult_plain_text(&got_crypted_res, &BigInt::from_i32(13).unwrap())
                .unwrap();
            let encrypted_4 = keypair.0.pk.encrypt(&BigInt::from_i32(4).unwrap()).unwrap();
            let got_crypted_res = keypair.0.pk.add(&got_crypted_res, &encrypted_4).unwrap();
            let got_crypted_res = keypair
                .0
                .pk
                .div_plain_text(&got_crypted_res, &BigInt::from_i32(2).unwrap())
                .unwrap();
            let got = keypair.0.decrypt(&got_crypted_res).unwrap();

            assert_eq!(got, target_res);
        }
    }
}
