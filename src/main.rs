use blst::min_sig::{AggregateSignature, PublicKey, SecretKey, Signature};
use blst::Pairing;
use rand::{rng, RngCore};
use rand::rngs::OsRng;

const DST: &[u8; 43]=b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
fn key_generation() -> (SecretKey, PublicKey) {
    let mut ikm = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut ikm);
    let sk = SecretKey::key_gen(&ikm, &[]).expect("Failed to generate secret key");
    let pk = sk.sk_to_pk();
    (sk, pk)
}
fn signing(sk:&SecretKey,message:&[u8])->Signature{
    // let DST = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    let signedmessage = sk.sign(message, DST, &[]);
    signedmessage
    
}
fn agg_signatures(signatures:&[Signature])->Signature{
    let sig_refs: Vec<&Signature> = signatures.iter().collect();
    AggregateSignature::aggregate(&sig_refs, true)
        .expect("Failed to aggregate signatures")
        .to_signature()
}
fn verify_agg_signatures(agg_signatures:&Signature,ps:&[PublicKey],message:&[u8]){
    let refs: Vec<&PublicKey> = pks.iter().collect();
    let messages=vec![message; ps.len()];
    let result=agg_signatures.aggregate_verify(true, &messages, DST, &refs, true);
}




fn main() {
    let (secret_key, public_key) = key_generation();
    println!("Key pair generated successfully:{:?},{:?}",secret_key,public_key);
}


