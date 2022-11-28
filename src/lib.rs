use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num_primes::Generator;
use num_traits::identities::{One, Zero};
use std::clone::Clone;
use std::ops::Sub;

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

pub struct KeyPair(PrivKey);

pub fn make_key_pair(bitlen: usize) -> Option<KeyPair> {
    let p = Generator::new_prime(bitlen).to_bigint().unwrap();
    let q = Generator::new_prime(bitlen).to_bigint().unwrap();
    let n = p.clone() * q.clone();
    let nn = n.clone() * n.clone();

    // Select random integer g where g ∈ Z_(n^2)*
    // but If using p,q of equivalent length,
    // a simpler variant of the above key generation steps would be to set
    // g = n + 1, lambda = phi(n), mu = phi(n)^-1 mod n,  phi(n) = (p - 1)*(q - 1)
    // The simpler variant is recommended for implementational purposes,
    // because in the general form the calculation time of mu
    // can be very high with sufficiently large primes p,q.
    // https://crypto.stackexchange.com/questions/8276/what-does-mathbbz-n2-mean
    let g = n.clone() + BigInt::one();

    // lambda = phi(n)
    let lambda = phi(&p, &q);

    // mu = phi(n)^-1 mod n = lambda^-1 mod n = inverse lambda mod n
    let mu = mod_inverse(&lambda, &n).unwrap();

    let pk = PubKey { g, n, nn };

    return Some(KeyPair(PrivKey { lambda, mu, pk }));
}

//////////////////// Enrypt & Decrypt /////////////////////////////////////

impl PubKey {
    /// encrypt message to ciphertext
    pub fn encrypt_message(&self, msg: &str) -> Option<BigInt> {
        let msg_int = BigUint::from_bytes_be(msg.as_bytes()).to_bigint().unwrap();
        self.encrypt(&msg_int)
    }

    /// ecrypt integer message to ciphertext
    pub fn encrypt(&self, m: &BigInt) -> Option<BigInt> {
        // Let m be a message to be encrypted where 0 <= m < n
        if m >= &BigInt::zero() && m < &self.n {
            // select random r where 0 < r < n
            let mut rng = rand::thread_rng();
            let r = rng.gen_bigint_range(&BigInt::one(), &self.n);

            // compute ciphertext c = g^m * r^n (mod n^2)
            let g_m = self.g.modpow(m, &self.nn);
            let r_n = r.modpow(&self.n, &self.nn);
            let c = (g_m * r_n) % self.nn.clone();
            Some(c)
        } else {
            None
        }
    }
}

impl PrivKey {
    pub fn decrypt_message(&self, ciphertext: &BigInt) -> Option<String> {
        let plain_text_int = self.decrypt(ciphertext).unwrap();
        Some(String::from_utf8(plain_text_int.to_biguint().unwrap().to_bytes_be()).unwrap())
    }

    pub fn decrypt(&self, ciphertext: &BigInt) -> Option<BigInt> {
        // Let c be the ciphertext to decrypt, where c ∈ Z_(n^2)*    0 < c <= n^2 - 1
        if ciphertext == &BigInt::zero() {
            None
        } else {
            // Compute the plaintext message as m = L(c^lambda mod n^2) * mu mod n
            let c_lambda = ciphertext.modpow(&self.lambda, &self.pk.nn);
            let l_ = l(&c_lambda, &self.pk.n);
            let m = (l_ * self.mu.clone()) % self.pk.n.clone();
            Some(m)
        }
    }
}

//////////////////////// Homomorphic properties ////////////////////////////////

impl PubKey {}

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

fn extend_gcd(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
    if a == BigInt::zero() {
        (b.clone(), BigInt::zero(), BigInt::one())
    } else {
        let (g, x, y) = extend_gcd(b.clone() % a.clone(), a.clone());
        (g, y - (b.clone() / a.clone()) * x.clone(), x.clone())
    }
}

fn mod_inverse(a: &BigInt, modular: &BigInt) -> Option<BigInt> {
    let (g, x, _) = extend_gcd(a.clone(), modular.clone());
    if g != BigInt::one() {
        None
    } else {
        let result = (x.clone() % modular.clone() + modular.clone()) % modular.clone();
        Some(result)
    }
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
                .encrypt(&BigInt::from_usize(MSG as usize).unwrap())
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
}
