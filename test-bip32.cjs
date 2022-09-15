
const ecc = require('tiny-secp256k1')
const { BIP32Factory } = require('bip32')
// You must wrap a tiny-secp256k1 compatible implementation
const bip32 = BIP32Factory(ecc)
const createHmac = require('create-hmac');

const node = bip32.fromBase58('xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U')

const neuteredNode = node.neutered()
const derivedFromNeutered = neuteredNode.derive(0)
console.log('Public Key', node.publicKey)
console.log('Chain Code', node.chainCode)
console.log('Derived from Neutered Public Key', derivedFromNeutered.publicKey)
console.log('Derived from Neutered Chain Chode', derivedFromNeutered.chainCode)

const child = node.deriveHardened(0);

console.log('parent private key:', node.privateKey)
const HIGHEST_BIT = 0x80000000;
const data = Buffer.allocUnsafe(37);
data[0] = 0x00;
node.privateKey.copy(data, 1);
data.writeUInt32BE(HIGHEST_BIT, 33);
I = createHmac('sha512', node.chainCode)
    .update(data)
    .digest();
    //"e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
//console.log(I);
console.log('IL:', I.slice(0, 32));
console.log('IR:', I.slice(32));
console.log('node private key: ', node.privateKey);
console.log('private key + IL mod n:', Buffer.from(ecc.privateAdd(node.privateKey, I.slice(0, 32))));
console.log('child private key:', child.privateKey);
console.log('child chain code:', child.chainCode);
console.log('parent public key:', node.publicKey);
console.log('child fingerprint:', child.fingerprint);

const nodepub = bip32.fromBase58('xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB')
const childp = nodepub.derive(0)

const datap = Buffer.allocUnsafe(37);

nodepub.publicKey.copy(datap, 0);
datap.writeUInt32BE(0, 33);

Ip = createHmac('sha512', nodepub.chainCode)
    .update(datap)
    .digest();

console.log('Public Key:', nodepub.publicKey)

const Ki = Buffer.from(ecc.pointAddScalar(nodepub.publicKey, Ip.slice(0, 32)), true);

console.log('IRp:', Ip.slice(32));
console.log('child public chain code:', childp.chainCode)
console.log('Ki:', Ki)
console.log('child public public key:', childp.publicKey)
