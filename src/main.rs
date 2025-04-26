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
fn verify_agg_signatures(agg_signatures:&Signature,ps:&[PublicKey],message:&[u8])->bool{
    let refs: Vec<&PublicKey> = ps.iter().collect();
    let messages=vec![message; ps.len()];
    let verified=agg_signatures.aggregate_verify(true, &messages, DST, &refs, true);
    verified == blst::BLST_ERROR::BLST_SUCCESS
}

fn main() {
    let message=b"Hail Ethereum";
    let mut secret_keys = Vec::new();
    let mut public_keys = Vec::new();
    let mut signatures = Vec::new();
    for _ in 0..10{
        let(sk,p)=key_generation();
        let sig=signing(&sk, message);
        secret_keys.push(sk);

        public_keys.push(p);
        
        signatures.push(sig);
    }
    // public_keys[0] = key_generation().1; This will make the signatur invalid
    let agg_sigs=agg_signatures(&signatures);
    let result=verify_agg_signatures(&agg_sigs, &public_keys, message);
    if result{
        println!("Valid Signature");
    }
    else{
        println!("Signature is not valid");
    }
}


