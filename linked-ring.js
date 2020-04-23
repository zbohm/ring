const EdDSA = require('elliptic').ec
const BN = require('bn.js')
const keccakHash = require('keccak')


/**
 * Linked (one time) Ring signature.
 * @function sign - make signature.
 * @function verify - verify signature.
 */
class LinkedRing {

    constructor() {
        this.eddsa = new EdDSA('ed25519')
    }

    /**
     * @param {String} text - text to hash
     * @returns {String} - hashed text in hex
     */
    hash_string(text) {
        const msgHash = new BN(keccakHash('keccak256').update(text).digest())
        return msgHash.mod(this.eddsa.curve.n).toString(16)
    }

    /**
     * @param {Array<String|BN>} array - array of hashes or BN (Big number)
     * @returns {String} - hash of array in hex
     */
    hash_array(array) {
        let sum = ''
        for (const value of array) {
            sum += value
        }
        return this.hash_string(sum)
    }

    /**
     * @param {BN} value - BN (Big number)
     * @returns {String} - hash of BN in hex
     */
    hash_bn(value) {
        return this.hash_string(value.toString(16))
    }

    /**
     * @param {Array<Point>} all_keys - array of Point (elliptic/curve/edwards.js)
     * @param {String} seed - hash in hex
     * @returns {Array<String>} - array of hashes
     */
    generate_q(all_keys, seed) {
        const prefix = this.hash_string('q')
        const hseed = this.hash_string(seed)
        const q_array = []
        for (let i = 0; i < all_keys.length; i++) {
            q_array.push(this.hash_array([
                prefix,
                hseed,
                this.hash_string(i.toString())
            ]))
        }
        return q_array
    }

    /**
     * @param {Array<Point>} all_keys - array of Point (elliptic/curve/edwards.js)
     * @param {String} seed - hash in hex
     * @param {KeyPair} signatory - a pair of private and public key (elliptic/ec.key.js)
     * @returns {Array<String|BN>} - array of hashes
     */
    generate_w(all_keys, seed, signatory) {
        const prefix = this.hash_string('w')
        const hseed = this.hash_string(seed)
        const w_array = []
        for (let i = 0; i < all_keys.length; i++) {
            if (all_keys[i] === signatory) {
                w_array.push(new BN(0, 16))
            } else {
                w_array.push(this.hash_array([
                    prefix,
                    hseed,
                    this.hash_string(i.toString())
                ]))
            }
        }
        return w_array
    }

    /**
     * @param {Array<Point>} all_keys - array of Point (elliptic/curve/edwards.js)
     * @param {Array<String>} q_array - Q array
     * @param {Array<String|BN>} w_array - W array
     * @param {KeyPair} signatory - a pair of private and public key (elliptic/ec.key.js)
     * @returns {Array<Point>} - array of points
     */
    generate_ll(all_keys, q_array, w_array, signatory) {
        const ll_array = []
        for (let i = 0; i < all_keys.length; i++) {
            ll_array.push(this.eddsa.g.mul(new BN(q_array[i], 16)))
            if (all_keys[i] !== signatory) {
                ll_array[i] = ll_array[i].add(all_keys[i].mul(new BN(w_array[i], 16)))
            }
        }
        return ll_array
    }

    /**
     * @param {Point} key - EC Point
     * @returns {Point} - EDDSA.G * hash(key[x, y])
     */
    hash_point(key) {
        return this.eddsa.g.mul(new BN(this.hash_array([key.x, key.y]), 16))
    }

    /**
     * @param {Array<Point>} all_keys - array of Point (elliptic/curve/edwards.js)
     * @param {Array<String>} q_array - Q array
     * @param {Array<String|BN>} w_array - W array
     * @param {Point} key_image - EC Point with unique key image (tag)
     * @param {KeyPair} signatory - a pair of private and public key (elliptic/ec.key.js)
     * @returns {Array<Point>} - array of points
     */
    generate_rr(all_keys, q_array, w_array, key_image, signatory) {
        const rr_array = []
        for (let i = 0; i < all_keys.length; i++) {
            const pub = all_keys[i] === signatory ? signatory.getPublic() : all_keys[i]
            let rri = this.hash_point(pub).mul(new BN(q_array[i], 16))
            if (all_keys[i] !== signatory) {
                rri = rri.add(key_image.mul(new BN(w_array[i], 16)))
            }
            rr_array.push(rri)
        }
        return rr_array
    }

    /**
     * @param {Array<Point>} all_keys - array of Point (elliptic/curve/edwards.js)
     * @param {Array<String|BN>} w_array - W array
     * @param {String} challenge - hex hash
     * @param {KeyPair} signatory - a pair of private and public key (elliptic/ec.key.js)
     * @returns {Array<BN>} - array of BN
     */
    generate_c(all_keys, w_array, challenge, signatory) {
        const c_array = []
        for (let i = 0; i < all_keys.length; i++) {
            if (all_keys[i] !== signatory) {
                c_array.push(new BN(w_array[i], 16))
            } else {
                const chNum = new BN(challenge, 16)
                const wSum = w_array.reduce((acc, val) => {
                    return acc.add(new BN(val, 16))
                }, new BN(0, 16))
                c_array.push(chNum.sub(wSum).umod(this.eddsa.curve.n))
            }
        }
        return c_array
    }

    /**
     * @param {Array<Point>} all_keys - array of Point (elliptic/curve/edwards.js)
     * @param {Array<String>} q_array - array of hashes
     * @param {Array<BN>} c_array - array of BN
     * @param {KeyPair} signatory - a pair of private and public key (elliptic/ec.key.js)
     * @returns {Array<BN>} - array of BN
     */
    generate_r(all_keys, q_array, c_array, signatory) {
        const priv = signatory.getPrivate()
        const r_array = []
        for (let i = 0; i < all_keys.length; i++) {
            if (all_keys[i] === signatory) {
                const ri = new BN(q_array[i], 16).sub(priv.mul(c_array[i]))
                r_array.push(ri.umod(this.eddsa.curve.n))
            } else {
                r_array.push(new BN(q_array[i], 16))
            }
        }
        return r_array
    }

    /**
     * @param {String} message_digest - hash in hex
     * @param {Array<Point>} ll_array - array of Point (elliptic/curve/edwards.js)
     * @param {Array<Point>} rr_array - array of Point (elliptic/curve/edwards.js)
     * @returns {String} - hash in hex
     */
    make_challenge(message_digest, ll_array, rr_array) {
        const challenge_arr = [message_digest]
        for (const point of ll_array) {
            challenge_arr.push(this.hash_string(point.encode('hex')))
        }
        for (const point of rr_array) {
            challenge_arr.push(this.hash_string(point.encode('hex')))
        }
        return this.hash_array(challenge_arr)
    }

    /**
     * @param {String} message - message to sign
     * @param {KeyPair} signatory - a pair of private and public key (elliptic/ec.key.js)
     * @param {Array<Point>} public_keys - array of Point (elliptic/curve/edwards.js)
     * @returns {Array<[Point, Array<BN>, Array<BN>]>} - signature values
     */
    sign(message, signatory, public_keys) {
        const private_key = signatory.getPrivate()
        const message_digest = this.hash_string(message)
        const seed = this.hash_array([
            this.hash_bn(private_key),
            this.hash_string(message_digest)
        ])
        const public_key = signatory.getPublic()
        const all_keys = []
        for (const pub_key of public_keys) {
            all_keys.push(pub_key === public_key ? signatory : pub_key)
        }
        const q_array = this.generate_q(all_keys, seed)  // hex numbers
        const w_array = this.generate_w(all_keys, seed, signatory)  // hex number + 1 BN
        const ll_array = this.generate_ll(all_keys, q_array, w_array, signatory)
        const key_image = this.hash_point(public_key).mul(private_key)  // I = x * Hp(P)
        const rr_array = this.generate_rr(all_keys, q_array, w_array, key_image, signatory)
        const challenge = this.make_challenge(message_digest, ll_array, rr_array)
        const c_array = this.generate_c(all_keys, w_array, challenge, signatory)
        const r_array = this.generate_r(all_keys, q_array, c_array, signatory)

        return [key_image, c_array, r_array]
    }

    /**
     * @param {Array<Point>} public_keys - array of Point (elliptic/curve/edwards.js)
     * @param {Array<BN>} c_array - array of BN
     * @param {Array<BN>} r_array - array of BN
     * @returns {Array<Point>} - array of points
     */
    verify_generate_ll(public_keys, c_array, r_array) {
        const ll_array = []
        for (let i = 0; i < public_keys.length; i++) {
            const rG = this.eddsa.g.mul(new BN(r_array[i], 16))
            const cP = public_keys[i].mul(new BN(c_array[i], 16))
            ll_array.push(rG.add(cP))  // L' = rG + cP
        }
        return ll_array
    }

    /**
     * @param {Array<Point>} public_keys - array of Point (elliptic/curve/edwards.js)
     * @param {Point} key_image - EC Point with unique key image (tag)
     * @param {Array<BN>} c_array - array of BN
     * @param {Array<BN>} r_array - array of BN
     * @returns {Array<Point>} - array of points
     */
    verify_generate_rr(public_keys, key_image, c_array, r_array) {
        const rr_array = []
        for (let i = 0; i < public_keys.length; i++) {
            const cI = key_image.mul(new BN(c_array[i], 16))
            const HpP = this.hash_point(public_keys[i])
            const rHp = HpP.mul(new BN(r_array[i], 16))
            rr_array.push(cI.add(rHp))
        }
        return rr_array
    }

    /**
     * @param {Array<BN>} c_array - array of BN
     * @returns {BN} - summation of BN
     */
    c_summation(c_array) {
        let summation = new BN(0, 16)
        for (let i = 0; i < c_array.length; i++) {
            summation = summation.add(c_array[i])
        }
        return summation
    }

    /**
     * @param {String} message - message to sign
     * @param {Array<[Point, Array<BN>, Array<BN>]>} signature - signature values
     * @param {Array<Point>} public_keys - array of Point (elliptic/curve/edwards.js)
     * @returns {boolean} - signature is valid or not
     */
    verify(message, signature, public_keys) {
        const ll_array = this.verify_generate_ll(public_keys, signature[1], signature[2])
        const rr_array = this.verify_generate_rr(public_keys, signature[0], signature[1], signature[2])
        const c_sum = this.c_summation(signature[1]).umod(this.eddsa.curve.n).toString('hex')
        const challenge = this.make_challenge(this.hash_string(message), ll_array, rr_array)
        return challenge === c_sum
    }

    /**
     * @param {Point} point - some Point (elliptic/curve/edwards.js)
     * @returns {String} - hash in hex
     */
    pointToHexString(point) {
        return point.x.fromRed().toString(16, 2) +
            point.y.fromRed().toString(16, 2) +
            point.z.fromRed().toString(16, 2)
    }

    /**
     * @param {Point} image1 - some Point (elliptic/curve/edwards.js)
     * @param {Point} image2 - some Point (elliptic/curve/edwards.js)
     * @returns {boolean} - point equals or not
     */
    imagesAreEqual(image1, image2) {
        return this.pointToHexString(image1) === this.pointToHexString(image2)
    }
}

module.exports = {LinkedRing}
