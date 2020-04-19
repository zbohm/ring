const Hasher = require('./hasher.js');
const PrivateKey = require('./private-key.js');
const Prng = require('./prng.js');

const prng = new Prng.Prng();
//console.log(prng);
const hasher = new Hasher.Hasher();
//console.log(hasher)
const key = new PrivateKey.PrivateKey(prng.random,hasher);


const make_unique_id = (key) => [key.point.x.toString(16), key.point.y.toString(16), key.point.z.toString(16)].join('')

const sort_by_unique_id = (key1, key2) => {
    if (make_unique_id(key1) < make_unique_id(key2)) {
        return -1
    }
    return 1
}


const foreign_keys = [new PrivateKey.PrivateKey(prng.random,hasher).public_key,
                      new PrivateKey.PrivateKey(prng.random,hasher).public_key,
                      new PrivateKey.PrivateKey(prng.random,hasher).public_key,
                      key.public_key
                    ];

// Sort public keys into always same order.
foreign_keys.sort(sort_by_unique_id)

const foreign_keys2 = [new PrivateKey.PrivateKey(prng.random,hasher).public_key,
                      new PrivateKey.PrivateKey(prng.random,hasher).public_key,
                      new PrivateKey.PrivateKey(prng.random,hasher).public_key,
                      key.public_key
                    ];
foreign_keys2.sort(sort_by_unique_id)

const msg = 'one ring to rule them all';

let signatures_tags = []

const check_signature = (signature, name) => {
    console.log(`Verify signature ${name} by foreign_keys:`)
    console.log(signature.verify(msg, foreign_keys))
    console.log(`Verify signature ${name} by foreign_keys2:`)
    console.log(signature.verify(msg, foreign_keys2))

    if (signatures_tags.includes(signature.key_image)) {
        console.error(`ERROR: A private key in signature ${name} was already used.`)
    } else {
        console.log(`OK. A private key in signature ${name} was not used yet.`)
        signatures_tags.push(signature.key_image)
    }
    console.log("---")
}

const signature1 = key.sign(msg, foreign_keys)
check_signature(signature1, '1')

const signature2 = key.sign(msg, foreign_keys)
check_signature(signature2, '2')
