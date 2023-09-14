use std::collections::HashMap;

extern crate libc;

use frost::keys::{
    PublicKeyPackage, SecretShare, SigningShare, VerifiableSecretSharingCommitment, VerifyingShare,
};
use frost::round1::SigningCommitments;
use frost::{Identifier, SigningKey, VerifyingKey};
use frost_ed25519 as frost;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};

use bincode::{config, Decode, Encode};
use std::env;
use std::error::Error;
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::thread::sleep;
/// Benchmarking for 2 of n signing
use std::time::Duration;

extern crate getopts;
use self::getopts::{Matches, Options};

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
    pub secret: [u8; 32],
    pub verifying_share: [u8; 32],
    pub commitment: Vec<[u8; 32]>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MyCommitments {
    pub hiding: [u8; 32],
    pub binding: [u8; 32],
    pub id: [u8; 32],
}

pub fn run_frost(
    n: usize,
    thres: usize,
    index: usize,
    addrs: String,
    port: usize,
    message: &[u8],
) -> Result<FrostData, frost_ed25519::Error> {
    // let mut device = init_devices(n, thres, index, addrs, port);
    // let index = device.index + 1;
    // let n = device.n;
    // let thres = device.thres;
    // println!("n {}, index {}, thres {}", n, index, thres);

    let mut rng = thread_rng();
    let max_signers = n as u16;
    let min_signers = thres as u16;

    // let mut signer_pubkeys: HashMap<Identifier, VerifyingShare> = HashMap::new();
    // let mut shares: HashMap<Identifier, SecretShare> = HashMap::new();
    // for participant_index in 1..(max_signers as u16 + 1) {
    //     let file = File::open(format!("key-{}", participant_index)).unwrap();
    //     let reader = BufReader::new(file);
    //     let secrets: FrostSecret = serde_json::from_reader(reader).unwrap();
    //     let id = Identifier::deserialize(&secrets.identifier).unwrap();
    //     let vshare = VerifyingShare::deserialize(secrets.verifying_share).unwrap();
    //     let commitments =
    //         VerifiableSecretSharingCommitment::deserialize(secrets.commitment).unwrap();
    //     let sec = SigningShare::deserialize(secrets.secret).unwrap();
    //     signer_pubkeys.insert(id, vshare);
    //
    //     let secret_shares = SecretShare::new(id, sec, commitments);
    //     shares.insert(id, secret_shares);
    // }
    // let file = File::open("key.pub").unwrap();
    // let reader = BufReader::new(file);
    // let pk_encoded = serde_json::from_reader(reader).unwrap();
    // let pk = VerifyingKey::deserialize(pk_encoded).unwrap();
    // let pubkey_package = PublicKeyPackage::new(signer_pubkeys, pk);

    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )?;

    // let file = File::create("key.pub").unwrap();
    // let mut writer = BufWriter::new(file);
    // serde_json::to_writer(&mut writer, &pubkey_package.group_public().serialize()).unwrap();
    // writer.flush().unwrap();
    // let serialized = serde_json::to_string(&pubkey_package.group_public().serialize()).unwrap();
    // println!(">>>serialized {}", serialized);

    // Verifies the secret shares from the dealer and store them in a HashMap.
    // In practice, the KeyPackages must be sent to its respective participants
    // through a confidential and authenticated channel.
    let mut key_packages: HashMap<_, _> = HashMap::new();

    let mut i = 0;
    for (identifier, secret_share) in shares {
        i += 1;
        // let file = File::create(format!("{}-{}", "key", i)).unwrap();
        // let mut writer = BufWriter::new(file);
        // let id = identifier.serialize();
        // let sec = secret_share.secret().serialize();
        // let vshare = pubkey_package.signer_pubkeys()[&identifier].serialize();
        // let cmm = secret_share.commitment().serialize();
        // let frost_secret = FrostSecret {
        //     identifier: id,
        //     secret: sec,
        //     verifying_share: vshare,
        //     commitment: cmm,
        // };
        // serde_json::to_writer(&mut writer, &frost_secret).unwrap();
        // writer.flush().unwrap();

        let key_package = frost::keys::KeyPackage::try_from(secret_share)?;
        key_packages.insert(identifier, key_package);
    }

    let mut nonces_map = HashMap::new();
    let mut commitments_map = BTreeMap::new();

    ////////////////////////////////////////////////////////////////////////////
    // Round 1: generating nonces and signing commitments for each participant
    ////////////////////////////////////////////////////////////////////////////

    // In practice, each iteration of this loop will be executed by its respective participant.
    for participant_index in 1..(min_signers as u16 + 1) {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        let key_package = &key_packages[&participant_identifier];
        // Generate one (1) nonce and one SigningCommitments instance for each
        // participant, up to _threshold_.
        let (nonces, commitments) = frost::round1::commit(
            key_packages[&participant_identifier].secret_share(),
            &mut rng,
        );

        let sb = commitments.binding().serialize();
        let sh = commitments.hiding().serialize();
        let si = participant_identifier.serialize();
        let mc = MyCommitments {
            hiding: sh,
            binding: sb,
            id: si,
        };
        let mc_encoded = serde_json::to_vec(&mc).unwrap();

        // let other_commitments = device.broadcast_and_listen(&mc_encoded[..]);
        // for p in &other_commitments {
        //     let mc_decoded: MyCommitments = serde_json::from_slice(&p).unwrap();
        //     let b = frost_ed25519::round1::NonceCommitment::deserialize(mc_decoded.binding)?;
        //     let h = frost_ed25519::round1::NonceCommitment::deserialize(mc_decoded.hiding)?;
        //     let i = Identifier::deserialize(&mc_decoded.id)?;
        //     let other_c = SigningCommitments::new(h, b);
        //     commitments_map.insert(i, other_c);
        // }

        // In practice, the nonces must be kept by the participant to use in the
        // next round, while the commitment must be sent to the coordinator
        // (or to every other participant if there is no coordinator) using
        // an authenticated channel.
        nonces_map.insert(participant_identifier, nonces);
        commitments_map.insert(participant_identifier, commitments);
    }

    // This is what the signature aggregator / coordinator needs to do:
    // - decide what message to sign
    // - take one (unused) commitment per signing participant
    let mut signature_shares = HashMap::new();
    let signing_package = frost::SigningPackage::new(commitments_map, message);

    ////////////////////////////////////////////////////////////////////////////
    // Round 2: each participant generates their signature share
    ////////////////////////////////////////////////////////////////////////////

    // In practice, each iteration of this loop will be executed by its respective participant.
    for participant_identifier in nonces_map.keys() {
        let key_package = &key_packages[participant_identifier];

        let nonces = &nonces_map[participant_identifier];

        // Each participant generates their signature share.
        let signature_share = frost::round2::sign(&signing_package, nonces, key_package)?;

        // In practice, the signature share must be sent to the Coordinator
        // using an authenticated channel.
        signature_shares.insert(*participant_identifier, signature_share);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Aggregation: collects the signing shares from all participants,
    // generates the final signature.
    ////////////////////////////////////////////////////////////////////////////

    // Aggregate (also verifies the signature shares)
    let group_signature = frost::aggregate(&signing_package, &signature_shares, &pubkey_package)?;
    let pk_bytes = pubkey_package.group_public().serialize();
    let _pub_key = VerifyingKey::deserialize(pk_bytes)?;
    let sig_bytes = group_signature.serialize();
    println!(">>>>>pbk {:?} {}", pk_bytes, pk_bytes.len());
    println!(">>>>>sig {:?} {}", sig_bytes, sig_bytes.len());

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

    Ok(x)
}

#[no_mangle]
pub extern "C" fn rustdemo(name: *const libc::c_char) -> *const libc::c_char {
    let cstr_name = unsafe { CStr::from_ptr(name) };
    let msg = cstr_name.to_bytes();
    println!(">>>>hello from rust! {:?}", cstr_name);

    let n = 4;
    let thres = 3;
    let index = 1;
    let port = 8878;
    let addrs = "192.168.0.146";

    let frost_data = run_frost(n, thres, index, addrs.to_string(), port, msg).unwrap();
    let pk = frost_data.pk;
    let sig = frost_data.sig;
    let mut bytes: [u8; 96] = [0; 96];
    bytes[..32].copy_from_slice(&pk);
    bytes[32..].copy_from_slice(&sig);

    CString::new(bytes).unwrap().into_raw()
}
