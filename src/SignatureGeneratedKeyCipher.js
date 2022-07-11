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
    payload
  }) {
    this._clearPrivateKey()
    const nonce = this._crypto.ownNonce()
    const { fullCipheredPayload } = await this._crypto.cipher({ payload, privateKey: await this._getPrivateKey(nonce), nonce })
    return fullCipheredPayload
  }

  /**
   *
   * @param {Buffer|Uint8Array} fullCipheredPayload encoded as base64
   * @returns deciphered payload as Uint8Array of bytes
   */
  async decipher ({
    fullCipheredPayload
  }) {
    const { cipheredPayload, nonce } = this._crypto.decodeOwnFullCipheredPayload(fullCipheredPayload)
    return this._crypto.decipher({ cipheredPayload, nonce, privateKey: await this._getPrivateKey(nonce) })
  }

  async _getPrivateKey (nonce) {
    let password = null
    if (!this._hasPrivateKey()) {
      password = await this._signFn(this._address, nonce)
    }
    return super._getPrivateKey(password)
  }
}

module.exports = SignatureGeneratedKeyCipher
