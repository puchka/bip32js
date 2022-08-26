import pkgcryptojs from 'crypto-js';
const { algo, enc } = pkgcryptojs;
import pkgelliptic from 'elliptic';
const { ec: EC } = pkgelliptic;
import * as bs58check from 'bs58check';

const ec = new EC("secp256k1");

const TEST_VECTOR_1_SEED = "000102030405060708090a0b0c0d0e0f";
const MASTER_KEY_DERIVATION_KEY = "Bitcoin seed";
const mainnetVersionBytesPriv = "0488ADE4";
const mainnetVersionBytesPub = "0488B21E";
const childDepth = "00"; // master node
const parentFingerPrint = "00000000"; // Calculated from http://bip32.org/ - First 32 bits of the public key identifier i.e. HASH160(publicKey)
const childNumber = "00000000";

const key = Buffer.from(MASTER_KEY_DERIVATION_KEY).toString("hex");
const hasher = algo.HMAC.create(algo.SHA512, enc.Hex.parse(key));
hasher.update(enc.Hex.parse(TEST_VECTOR_1_SEED));
const res = hasher.finalize().toString();
console.log(res);

const left256Bits = res.substring(0, 64);
const right256Bits = res.substring(64, 128);
const keypair = ec.keyFromPrivate(Buffer.from(left256Bits, "hex"));
const masterPub = keypair.getPublic("hex");
const compressedMasterPub = `${(Buffer.from(masterPub, "hex")[64] % 2 === 0) ? "02" : "03"}${masterPub.substring(2, 66)}`;

const extendedPrivateKey = `${mainnetVersionBytesPriv}${childDepth}${parentFingerPrint}${childNumber}${right256Bits}00${left256Bits}`;
const extendedPublicKey = `${mainnetVersionBytesPub}${childDepth}${parentFingerPrint}${childNumber}${right256Bits}${compressedMasterPub}`;
console.log(extendedPrivateKey);
console.log(extendedPublicKey);
// const xprv = bs58check.encode(Buffer.from(extendedPrivateKey, "hex"));
// const xpub = bs58check.encode(Buffer.from(extendedPublicKey, "hex"));
// console.log(`Extended Private Key: ${xprv}`);
// console.log(`Extended Public Key: ${xpub}`);
