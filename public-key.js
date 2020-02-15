const BN = require('bn.js');

const PublicKey = class PublicKey{
  constructor(point,hasher){
    this.point = point;
    this.hasher = hasher;
  }
}

module.exports = {
  PublicKey:PublicKey
}
