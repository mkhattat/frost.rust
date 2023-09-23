use std::collections::HashMap;

extern crate libc;

use frost::keys::{
    PublicKeyPackage, SecretShare, SigningShare, VerifiableSecretSharingCommitment, VerifyingShare,
};
use frost::round1::SigningCommitments;
use frost::round2::SignatureShare;
use frost::{Identifier, VerifyingKey};
use frost_ed25519 as frost;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::sleep;
/// Benchmarking for 2 of n signing
use std::time::Duration;
use std::{env, slice};

extern crate getopts;

use std::fs::File;

struct CommandArgs {
    index: usize,
    n: usize,
    thres: usize,
    sendvec: Vec<Option<std::net::TcpStream>>,
    recvvec: Vec<Option<std::net::TcpStream>>,
}

impl CommandArgs {
    fn send_bytes(&mut self, buf: &[u8], index: usize) {
        self.sendvec[index]
            .as_mut()
            .unwrap()
            .write(buf)
            .expect(&format!("Party {} failed to send signal.", index));
    }

    fn send(&mut self, buf: &Vec<u8>, index: usize) {
        let size: u32 = buf.len() as u32;
        self.send_bytes(&size.to_ne_bytes(), index);
        self.send_bytes(&buf[..], index);
    }

    fn resv_bytes(&mut self, buf: &mut [u8], index: usize) {
        self.recvvec[index]
            .as_mut()
            .unwrap()
            .read_exact(buf)
            .expect(&format!("Party {} failed to read signal.", index));
    }

    fn listen(&mut self, index: usize) -> Vec<u8> {
        let mut msg_size = [0u8; 4];
        self.resv_bytes(&mut msg_size, index);
        let msg_size = u32::from_ne_bytes(msg_size);
        let mut buf_enc: Vec<u8> = vec![0; msg_size as usize];
        self.resv_bytes(&mut buf_enc[..], index);
        buf_enc
    }

    fn broadcast(&mut self, buf: &[u8]) {
        let size: u32 = buf.len() as u32;
        for i in 0..self.n {
            if i == self.index {
                continue;
            }
            self.send_bytes(&size.to_ne_bytes(), i);
            self.send_bytes(buf, i);
        }
    }

    fn listen_all_devices(&mut self) -> Vec<Vec<u8>> {
        let mut queue: Vec<Vec<u8>> = Vec::with_capacity(self.n);
        for ii in 0..self.n {
            if ii == self.index {
                continue;
            }
            let mut size_og = [0u8; 4];
            self.resv_bytes(&mut size_og, ii);
            let size_og = u32::from_ne_bytes(size_og);

            let mut buf: Vec<u8> = vec![0; size_og as usize];
            self.resv_bytes(&mut buf[..], ii);
            queue.push(buf);
        }
        queue
    }

    fn broadcast_and_listen(&mut self, buf: &[u8]) -> Vec<Vec<u8>> {
        self.broadcast(buf);
        self.listen_all_devices()
    }
}

fn init_devices(n: usize, thres: usize, index: usize, addrs: String, port: usize) -> CommandArgs {
    let mut sendvec: Vec<Option<std::net::TcpStream>> = Vec::with_capacity(n);
    let mut recvvec: Vec<Option<std::net::TcpStream>> = Vec::with_capacity(n);

    // ports should be separated by commas
    let addrs: Vec<&str> = addrs.split(",").collect();
    let min_ports = n;
    let mut ports = Vec::with_capacity(min_ports);
    for ii in port..(port + min_ports) {
        ports.push(format!("{}", ii));
    }

    for jj in 0..n {
        if jj < index {
            let port_index = jj;
            let port = format!("0.0.0.0:{}", &ports[port_index]);
            println!("{} waiting for {} to connect on {}", index, jj, port);
            let listener = TcpListener::bind(port).unwrap_or_else(|e| panic!("{}", e));
            let (recv, _) = listener.accept().unwrap_or_else(|e| panic!("{}", e));
            let send = recv.try_clone().unwrap();
            recv.set_nodelay(true).expect("Could not set nodelay");
            send.set_nodelay(true).expect("Could not set nodelay");
            sendvec.push(Some(send));
            recvvec.push(Some(recv));
        } else if jj > index {
            let port_index = index;
            let port = format!("{}:{}", addrs[jj], &ports[port_index]);
            println!("{} connecting to {} server {:?}...", index, jj, port);
            let mut send = TcpStream::connect(&port);
            let connection_wait_time = 2 * 60;
            let poll_interval = 100;
            for _ in 0..(connection_wait_time * 1000 / poll_interval) {
                if send.is_err() {
                    sleep(Duration::from_millis(poll_interval));
                    send = TcpStream::connect(&port);
                }
            }
            let send = send.unwrap();
            let recv = send.try_clone().unwrap();
            recv.set_nodelay(true).expect("Could not set nodelay");
            send.set_nodelay(true).expect("Could not set nodelay");
            sendvec.push(Some(send));
            recvvec.push(Some(recv));
        } else {
            // pause here so the lower numbers can start their listeners?
            //sleep(Duration::from_millis(500));
            sendvec.push(None);
            recvvec.push(None);
        }
    }

    if index == n - 1 {
        for ii in 0..n - 1 {
            sendvec[ii]
                .as_mut()
                .unwrap()
                .write(&[0])
                .expect(&format!("Party {} failed to send ready signal.", index));
            sendvec[ii]
                .as_mut()
                .unwrap()
                .flush()
                .expect(&format!("Party {} failed to flush.", index));
        }
    } else {
        let mut sigread = [1u8; 1];
        recvvec[n - 1]
            .as_mut()
            .unwrap()
            .read_exact(&mut sigread)
            .expect(&format!("Party {} failed to read ready signal.", index));
    }

    CommandArgs {
        index,
        thres,
        n,
        sendvec,
        recvvec,
    }
}

pub struct FrostData {
    pub sig: [u8; 64],
    pub pk: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FrostSecret {
    pub identifier: [u8; 32],
    pub verifying_share: [u8; 32], //needed for validating signature_share
    pub secret: [u8; 32],          //part of secret_share
    pub commitment: Vec<[u8; 32]>, //part of secret_share
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MyCommitments {
    pub hiding: [u8; 32],
    pub binding: [u8; 32],
    pub id: [u8; 32],
    pub verifying_share: [u8; 32], //needed for validating signature_share
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MySignatureShare {
    pub identifier: [u8; 32],
    pub secret_share: [u8; 32],
}

pub fn run_frost(
    n: usize,
    thres: usize,
    index: usize,
    addrs: String,
    port: usize,
    message: &[u8],
) -> Result<FrostData, frost_ed25519::Error> {
    let mut device = init_devices(n, thres, index, addrs, port);
    let index = device.index + 1;
    let participant_index = index as u16;
    let n = device.n;
    let thres = device.thres;
    println!("n {}, index {}, thres {}", n, index, thres);

    let mut rng = thread_rng();
    let mut signer_pubkeys: HashMap<Identifier, VerifyingShare> = HashMap::new();

    let path = env::current_dir().unwrap();
    println!("The current directory is {}", path.display());

    let file = File::open(format!("./key-{}", participant_index)).unwrap();
    let reader = BufReader::new(file);
    let mykey: FrostSecret = serde_json::from_reader(reader).unwrap();

    let id = Identifier::deserialize(&mykey.identifier).unwrap();
    let vshare = VerifyingShare::deserialize(mykey.verifying_share).unwrap();
    let commitment = VerifiableSecretSharingCommitment::deserialize(mykey.commitment).unwrap();
    let sk = SigningShare::deserialize(mykey.secret).unwrap();
    let secret_share = SecretShare::new(id, sk, commitment);

    signer_pubkeys.insert(id, vshare);

    let file = File::open("./key.pub").unwrap();
    let reader = BufReader::new(file);
    let pk_encoded = serde_json::from_reader(reader).unwrap();
    let pk = VerifyingKey::deserialize(pk_encoded).unwrap();

    // Verifies the secret shares from the dealer and store them in a HashMap.
    // In practice, the KeyPackages must be sent to its respective participants
    // through a confidential and authenticated channel.

    let key_package = frost::keys::KeyPackage::try_from(secret_share)?;
    let participant_identifier: Identifier =
        participant_index.try_into().expect("should be nonzero");

    let mut commitments_map = BTreeMap::new();

    ////////////////////////////////////////////////////////////////////////////
    // Round 1: generating nonces and signing commitments for each participant
    ////////////////////////////////////////////////////////////////////////////

    // In practice, each iteration of this loop will be executed by its respective participant.
    // Generate one (1) nonce and one SigningCommitments instance for each
    // participant, up to _threshold_.
    let (nonces, commitments) = frost::round1::commit(key_package.secret_share(), &mut rng);
    commitments_map.insert(participant_identifier, commitments);

    //**********************communicate the commitments and verifying_shares**********************************
    let sb = commitments.binding().serialize();
    let sh = commitments.hiding().serialize();
    let si = participant_identifier.serialize();
    let mc = MyCommitments {
        hiding: sh,
        binding: sb,
        id: si,
        verifying_share: mykey.verifying_share,
    };
    let mc_encoded = serde_json::to_vec(&mc).unwrap();

    let other_commitments = device.broadcast_and_listen(&mc_encoded[..]);
    for p in &other_commitments {
        let mc_decoded: MyCommitments = serde_json::from_slice(&p).unwrap();
        let b = frost_ed25519::round1::NonceCommitment::deserialize(mc_decoded.binding)?;
        let h = frost_ed25519::round1::NonceCommitment::deserialize(mc_decoded.hiding)?;
        let i = Identifier::deserialize(&mc_decoded.id)?;
        let other_c = SigningCommitments::new(h, b);
        commitments_map.insert(i, other_c);
        let vs = VerifyingShare::deserialize(mc_decoded.verifying_share).unwrap();
        signer_pubkeys.insert(i, vs);
    }
    //**********************communicate the commitments**********************************

    // In practice, the nonces must be kept by the participant to use in the
    // next round, while the commitment must be sent to the coordinator
    // (or to every other participant if there is no coordinator) using
    // an authenticated channel.
    let pubkey_package = PublicKeyPackage::new(signer_pubkeys, pk);

    // This is what the signature aggregator / coordinator needs to do:
    // - decide what message to sign
    // - take one (unused) commitment per signing participant
    let mut signature_shares = HashMap::new();
    let signing_package = frost::SigningPackage::new(commitments_map, message);

    ////////////////////////////////////////////////////////////////////////////
    // Round 2: each participant generates their signature share
    ////////////////////////////////////////////////////////////////////////////

    // In practice, each iteration of this loop will be executed by its respective participant.

    // Each participant generates their signature share.
    let signature_share = frost::round2::sign(&signing_package, &nonces, &key_package)?;
    signature_shares.insert(participant_identifier, signature_share);

    // *********************communicate the signature_share*************************************
    // In practice, the signature share must be sent to the Coordinator
    // using an authenticated channel.
    let serialized_secret_share = signature_share.serialize();
    let mss = MySignatureShare {
        identifier: si,
        secret_share: serialized_secret_share,
    };
    let my_signature_share_encoded = serde_json::to_vec(&mss).unwrap();
    let other_secret_shares = device.broadcast_and_listen(&my_signature_share_encoded);
    for oss in &other_secret_shares {
        let mss_decoded: MySignatureShare = serde_json::from_slice(&oss).unwrap();
        let other_id = Identifier::deserialize(&mss_decoded.identifier)?;
        let other_secret_share = SignatureShare::deserialize(mss_decoded.secret_share)?;
        signature_shares.insert(other_id, other_secret_share);
    }
    // *********************communicate the signature_share*************************************

    ////////////////////////////////////////////////////////////////////////////
    // Aggregation: collects the signing shares from all participants,
    // generates the final signature.
    ////////////////////////////////////////////////////////////////////////////

    // Aggregate (also verifies the signature shares)
    let group_signature = frost::aggregate(&signing_package, &signature_shares, &pubkey_package)?;
    let pk_bytes = pubkey_package.group_public().serialize();
    let _pub_key = VerifyingKey::deserialize(pk_bytes)?;
    let sig_bytes = group_signature.serialize();
    println!("sig_bytes {:?}", sig_bytes);

    // Check that the threshold signature can be verified by the group public
    // key (the verification key).

    let is_signature_valid = pubkey_package
        .group_public()
        .verify(message, &group_signature)
        .is_ok();
    assert!(is_signature_valid);

    println!("DONE.");

    let x = FrostData {
        sig: sig_bytes,
        pk: pk_bytes,
    };

    println!(">>>pk {:?}", pk_bytes);
    println!(">>>sig {:?}", sig_bytes);

    Ok(x)
}

#[no_mangle]
pub extern "C" fn callme(slice: *const libc::c_uchar, len: libc::size_t) -> *const libc::c_uchar {
    let data = unsafe { slice::from_raw_parts(slice, len as usize) };
    println!(">>>>hello from rust {:?}", data);

    let n = 5;
    let thres = 2;
    let index = 0;
    let port = 8877;
    let addrs = "192.168.0.138,192.168.0.146,192.168.0.153,192.168.0.154,192.168.0.190";

    let frost_data = run_frost(n, thres, index, addrs.to_string(), port, data).unwrap();
    let pk = frost_data.pk;
    let sig = frost_data.sig;
    let mut bytes: [u8; 96] = [0; 96];
    bytes[..32].copy_from_slice(&pk);
    bytes[32..].copy_from_slice(&sig);

    let x = bytes.as_ptr();
    println!(">>>> rust bytes {:?}", bytes);
    x
}
