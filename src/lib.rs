

use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num_integer::Integer;
use num_primes::Generator;
use num_traits::identities::{One, Zero};
use std::{clone::Clone};
use std::ops::Sub;



/// PubKey -- Publick Key
#[derive(Debug, Clone, Default)]
pub struct PubKey {
    pub g: BigInt, // g = n + 1
    pub n: BigInt, // n = p*q
    pub nn: BigInt // n^2
}

/// PrivKey -- Private Key
pub struct PrivKey {
    pub lambda: BigInt, // lambda = lcm(p - 1, q - 1)
    pub mu: BigInt, // https://en.wikipedia.org/wiki/Mu_(letter)  mu = （L(g^lambda mod n^2)）^-1 mod n
    pub pk: PubKey,
}

pub struct KeyPair(PrivKey);

pub fn make_key_pair(bitlen: usize) -> Option<KeyPair> {
    let p = Generator::safe_prime(bitlen).to_bigint().unwrap();
    let q = Generator::safe_prime(bitlen).to_bigint().unwrap();
    let n = p.clone() * q.clone();
    let nn = n.clone() * n.clone();

    // Select random integer g where g ∈ Z_(n^2)*
    // but If using p,q of equivalent length, 
    // a simpler variant of the above key generation steps would be to set
    // g = n + 1, lambda = phi(n), mu = phi(n)^-1 mod n,  phi(n) = (p - 1)*(q - 1)
    // https://crypto.stackexchange.com/questions/8276/what-does-mathbbz-n2-mean
    let g = n.clone() + BigInt::one();

    // lambda = phi(n)
    let lambda = phi(&p, &q);
    
    // mu = phi(n)^-1 = lambda^-1
    let mu = mod_inverse(&lambda, &n).unwrap();

    let pk = PubKey {
        g,
        n,
        nn
    };
    
    return Some(KeyPair(
        PrivKey { lambda, mu, pk }
    ));
}

fn l(x: &BigInt, n: &BigInt) -> BigInt {
    let x1 = x - BigInt::one();
    x1 / n
}

fn phi(p: &BigInt, q: &BigInt) -> BigInt {
    let p1 = p.sub(BigInt::one());
    let q1 = q.sub(BigInt::one());
    p1 * q1
}

fn g_lambda(g:&BigInt, lambda: &BigInt, nn: &BigInt) -> BigInt {
    g.modpow(lambda, nn)
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
        let result = (x.clone() % modular.clone() + modular.clone())
            % modular.clone();
        Some(result)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
      
    }
}
