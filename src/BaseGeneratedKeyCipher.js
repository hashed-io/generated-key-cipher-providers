const { Crypto } = require('@smontero/hashed-crypto')

const SALT_PREFIX = 'Key1 Salt'

class BaseGeneratedKeyCipher {
  constructor () {
    this._crypto = new Crypto()
    this._privateKey = null
  }

  /**
   *
   * @param {Buffer|Uint8Array} payload as bytes
   * @returns {string} base64 encoded ciphered payload
   */
  async cipher ({
    payload
  }) {
    throw new Error('Subclass should override this method')
  }

  /**
   *
   * @param {Buffer|Uint8Array} fullCipheredPayload encoded as base64
   * @returns deciphered payload as Uint8Array of bytes
   */
  async decipher ({
    fullCipheredPayload
  }) {
    throw new Error('Subclass should override this method')
  }

  _clearPrivateKey () {
    this._privateKey = null
  }

  _hasPrivateKey () {
    return !!this._privateKey
  }

  assertHasPrivateKey () {
    if (!this._hasPrivateKey()) {
      throw new Error('Private key has not been generated')
    }
  }

  privateKey () {
    this.assertHasPrivateKey()
    return this._privateKey
  }

  async _generatePrivateKey (password) {
    if (!this._privateKey) {
      const secret = await this._crypto.argon2id({ password, salt: this._salt('argon2id') })
      this._privateKey = await this._crypto.deriveKey({ secret, salt: this._salt('Derivation') })
    }
    return this._privateKey
  }

  _salt (suffix) {
    return Buffer.from(`${SALT_PREFIX}${suffix}`)
  }
}

module.exports = BaseGeneratedKeyCipher
