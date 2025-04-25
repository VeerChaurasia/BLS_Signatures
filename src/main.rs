use blst::min_sig::{PublicKey, SecretKey, Signature};
use rand::{rng, RngCore};
use rand::rngs::OsRng;


fn key_generation() -> (SecretKey, PublicKey) {
    let mut ikm = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut ikm);
    let sk = SecretKey::key_gen(&ikm, &[]).expect("Failed to generate secret key");
    let pk = sk.sk_to_pk();
    (sk, pk)
}

fn main() {
    let (secret_key, public_key) = key_generation();
    println!("Key pair generated successfully:{:?},{:?}",secret_key,public_key);
}


