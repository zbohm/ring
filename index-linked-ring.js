const EdDSA = require('elliptic').ec
const assert = require('assert')
const lring = require('./linked-ring')


const eddsa = new EdDSA('ed25519')

const adam = eddsa.genKeyPair()
const bianca = eddsa.genKeyPair()
const daniel = eddsa.genKeyPair()
const eva = eddsa.genKeyPair()
const frank = eddsa.genKeyPair()

const public_keys = [
    adam.getPublic(),
    bianca.getPublic(),
    daniel.getPublic(),
    eva.getPublic(),
]
const invalid_public_keys = [
    adam.getPublic(),
    bianca.getPublic(),
    daniel.getPublic(),
    frank.getPublic(),
]
const invalid_public_keys_order = [
    bianca.getPublic(),
    adam.getPublic(),
    daniel.getPublic(),
    eva.getPublic(),
]


const ring = new lring.LinkedRing()

const message = "One ring to rule them all."

const adam_sign = ring.sign(message, adam, public_keys)
const is_adam_valid = ring.verify(message, adam_sign, public_keys)
assert(is_adam_valid, "Adam signature is not valid.")
console.log("Adam signature is valid.")

const isnot_adam_valid = ring.verify(message, adam_sign, invalid_public_keys)
assert(!isnot_adam_valid, "Adam signature with invalid_public_keys is valid.")
console.log("Adam signature with invalid_public_keys is not valid.")

const isnot_order_valid = ring.verify(message, adam_sign, invalid_public_keys_order)
assert(!isnot_order_valid, "Adam signature with invalid_public_keys_order is valid.")
console.log("Adam signature with invalid_public_keys_order is not valid.")

const second_adam_sign = ring.sign(message, adam, public_keys)
const is_second_adam_valid = ring.verify(message, second_adam_sign, public_keys)
assert(is_second_adam_valid, "Second Adam signature is not valid.")
console.log("Second Adam signature is valid.")

const adam_key_images_eq = ring.imagesAreEqual(adam_sign[0], second_adam_sign[0])
assert(adam_key_images_eq, "Adam key images are not equal.")
console.log("Adam key images are equal.")

const eva_sign = ring.sign(message, eva, public_keys)
const is_eva_valid = ring.verify(message, eva_sign, public_keys)
assert(is_eva_valid, "Eva signature is not valid.")
console.log("Eva signature is valid.")

const adam_eva_key_images_ne = ring.imagesAreEqual(adam_sign[0], eva_sign[0])
assert(!adam_eva_key_images_ne, "Adam and Eva key images are equal.")
console.log("Adam and Eva key images are not equal.")

console.log("END")
