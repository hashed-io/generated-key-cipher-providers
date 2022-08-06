const BaseGeneratedKeyCipher = require('./BaseGeneratedKeyCipher')

class SignatureGeneratedKeyCipher extends BaseGeneratedKeyCipher {
  constructor ({ signFn, address }) {
    super()
    this._signFn = signFn
    this._address = address
  }

  /**
   *
   * @param {Buffer|Uint8Array} payload as bytes
   * @returns {string} base64 encoded ciphered payload
   */
  async cipher ({
    payload,
    type
  }) {
    this._clearPrivateKey()
    const nonce = this._crypto.ownNonce()
    console.log('cipher: ', nonce)
    return this._crypto.cipher({ payload, privateKey: await this._generatePrivateKey(nonce), nonce, type })
  }

  /**
   *
   * @param {String} fullCipheredPayload encoded as base64
   * @returns deciphered payload as Uint8Array of bytes
   */
  async decipher ({
    fullCipheredPayload
  }) {
    const { cipheredPayload, nonce, type } = this._crypto.decodeOwnFullCipheredPayload(fullCipheredPayload)
    console.log('decipher: ', nonce)
    return this._crypto.decipher({ cipheredPayload, nonce, privateKey: await this._generatePrivateKey(nonce), type })
  }

  async _generatePrivateKey (nonce) {
    let password = null
    if (!this._hasPrivateKey()) {
      password = await this._signFn(this._address, nonce)
      console.log('password: ', password)
    }
    return super._generatePrivateKey(password)
  }
}

module.exports = SignatureGeneratedKeyCipher
