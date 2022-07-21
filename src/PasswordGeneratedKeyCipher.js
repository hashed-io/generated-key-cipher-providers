const BaseGeneratedKeyCipher = require('./BaseGeneratedKeyCipher')
const PASSWORD_REGEX = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9])(?!.*\s).{8,}$/

class PasswordGeneratedKeyCipher extends BaseGeneratedKeyCipher {
  constructor ({ password }) {
    super()
    if (!PASSWORD_REGEX.test(password)) {
      throw Error('The password must be at least 8 characters long, and contain at least one lowercase letter, one uppercase letter, one numeric digit, and one special character')
    }
    this._password = password
  }

  /**
   *
   * @param {Buffer|Uint8Array} payload as bytes
   * @returns {string} base64 encoded ciphered payload
   */
  async cipher ({
    payload
  }) {
    return this._crypto.cipher({ payload, privateKey: await this._getPrivateKey() })
  }

  /**
   *
   * @param {Buffer|Uint8Array} fullCipheredPayload encoded as base64
   * @returns deciphered payload as Uint8Array of bytes
   */
  async decipher ({
    fullCipheredPayload
  }) {
    return this._crypto.decipher({ fullCipheredPayload, privateKey: await this._getPrivateKey() })
  }

  async _getPrivateKey () {
    return super._getPrivateKey(this._password)
  }
}

module.exports = PasswordGeneratedKeyCipher
