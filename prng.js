const XorShift128Plus = require('xorshift128plus');
const crypto =require('crypto');

var Prng = class Prng{
  constructor(){
    this.seed = crypto.randomBytes(16).toString('hex');
    this.prng = new XorShift128Plus.fromHex(this.seed);
  }

  get random(){
    return crypto.randomBytes(32).toString('hex');
  }
}

module.exports = {
  Prng:Prng
}
