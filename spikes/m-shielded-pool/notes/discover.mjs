// ADR 0014 M6d — encrypted note discovery.
//
// A shielded note hides (amount, nk, rho). For a recipient to SPEND a note later, they must learn its opening.
// Like Zcash, each transfer attaches a note ciphertext: the sender encrypts the opening to the RECIPIENT's
// X25519 public key (the recipient publishes it once, as moimoi already does for §F sealed listings). The
// recipient scans the on-chain ciphertexts, trial-decrypts with their key, and recovers any notes addressed to
// them. Eavesdroppers learn nothing; the commitment + nullifier stay unlinkable on-chain.
//
// This demo uses Node's built-in crypto (X25519 ECDH + AES-256-GCM = ECIES) — no external deps. The same
// scheme drops into the moimoi client (which already manages X25519 enc keypairs).
import {
  generateKeyPair,
  createPublicKey,
  diffieHellman,
  createPrivateKey,
  randomBytes,
  createCipheriv,
  createDecipheriv,
  createHash,
} from 'node:crypto';
import { promisify } from 'node:util';

const genKP = promisify(generateKeyPair);

// derive an AES key from an X25519 shared secret (+ the ephemeral pub, for domain binding)
const kdf = (shared, ephPubRaw) => createHash('sha256').update(Buffer.concat([shared, ephPubRaw])).digest();
const rawPub = keyObj => keyObj.export({ type: 'spki', format: 'der' });

// sender: encrypt a note opening to the recipient's X25519 public key
const sealNote = (recipientPubDer, note) => {
  const recipientPub = createPublicKey({ key: recipientPubDer, format: 'der', type: 'spki' });
  const eph = generateKeyPairSync('x25519');
  const shared = diffieHellman({ privateKey: eph.privateKey, publicKey: recipientPub });
  const key = kdf(shared, rawPub(eph.publicKey));
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(JSON.stringify(note), 'utf8'), c.final()]);
  return {
    eph: rawPub(eph.publicKey).toString('base64'),
    iv: iv.toString('base64'),
    ct: ct.toString('base64'),
    tag: c.getAuthTag().toString('base64'),
  };
};

// recipient: trial-decrypt a ciphertext with their X25519 private key; null if not theirs
const openNote = (recipientPriv, blob) => {
  try {
    const ephPub = createPublicKey({ key: Buffer.from(blob.eph, 'base64'), format: 'der', type: 'spki' });
    const shared = diffieHellman({ privateKey: recipientPriv, publicKey: ephPub });
    const key = kdf(shared, Buffer.from(blob.eph, 'base64'));
    const d = createDecipheriv('aes-256-gcm', key, Buffer.from(blob.iv, 'base64'));
    d.setAuthTag(Buffer.from(blob.tag, 'base64'));
    const pt = Buffer.concat([d.update(Buffer.from(blob.ct, 'base64')), d.final()]);
    return JSON.parse(pt.toString('utf8'));
  } catch {
    return null; // not addressed to this key (auth tag fails)
  }
};

// node:crypto sync keygen
import { generateKeyPairSync } from 'node:crypto';

const main = async () => {
  // two recipients each publish an X25519 enc pubkey
  const alice = await genKP('x25519');
  const bob = await genKP('x25519');
  const alicePubDer = rawPub(alice.publicKey);
  const bobPubDer = rawPub(bob.publicKey);

  // a transfer sends note0 to Alice and note1 to Bob (openings the senders know)
  const note0 = { amount: '600', nk: 'alice-nk', rho: '222222' };
  const note1 = { amount: '397', nk: 'bob-nk', rho: '333333' };
  const onChain = [sealNote(alicePubDer, note0), sealNote(bobPubDer, note1)];
  console.log(`published ${onChain.length} note ciphertexts on-chain (opaque to everyone else)`);

  // Alice scans ALL ciphertexts; only hers decrypts
  const aliceFound = onChain.map(b => openNote(alice.privateKey, b)).filter(Boolean);
  const bobFound = onChain.map(b => openNote(bob.privateKey, b)).filter(Boolean);

  console.log('Alice recovered:', JSON.stringify(aliceFound));
  console.log('Bob recovered:  ', JSON.stringify(bobFound));

  // assertions
  const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  if (!(aliceFound.length === 1 && eq(aliceFound[0], note0))) throw Error('Alice should recover exactly note0');
  if (!(bobFound.length === 1 && eq(bobFound[0], note1))) throw Error('Bob should recover exactly note1');

  // an eavesdropper (third key) recovers nothing
  const eve = await genKP('x25519');
  const eveFound = onChain.map(b => openNote(eve.privateKey, b)).filter(Boolean);
  if (eveFound.length !== 0) throw Error('Eve must recover nothing');

  console.log('M6d OK — each recipient finds exactly their own note; eavesdropper recovers nothing.');
};

main().catch(e => {
  console.error('FAIL:', e.message);
  process.exit(1);
});
