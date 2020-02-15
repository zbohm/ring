const Hasher = require('./hasher.js');
const PrivateKey = require('./private-key.js');
const PublicKey = require('./public-key.js');
const Prng = require('./prng.js');
const Signature = require('./signature.js');

const prng = new Prng.Prng();
//console.log(prng);
const hasher = new Hasher.Hasher();
//console.log(hasher)
const key = new PrivateKey.PrivateKey(prng.random,hasher);

//console.log(key);

const foreign_keys = [new PrivateKey.PrivateKey(prng.random,hasher).public_key,
                      new PrivateKey.PrivateKey(prng.random,hasher).public_key,
                      new PrivateKey.PrivateKey(prng.random,hasher).public_key];


const foreign_keys2 = [new PrivateKey.PrivateKey(prng.random,hasher).public_key,
                      new PrivateKey.PrivateKey(prng.random,hasher).public_key,
                      new PrivateKey.PrivateKey(prng.random,hasher).public_key];

const msg = 'one ring to rule them all';
//console.log(msg)
const signature = key.sign(msg,foreign_keys);
const public_keys = signature.public_keys;

console.log(signature.verify(msg,public_keys));
console.log(signature.verify(msg,foreign_keys2));
