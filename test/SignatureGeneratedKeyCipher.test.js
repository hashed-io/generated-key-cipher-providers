/* eslint-disable no-new */
global.File = class {}
const { Keyring } = require('@polkadot/keyring')
const { mnemonicGenerate } = require('@polkadot/util-crypto')
const { SignatureGeneratedKeyCipher } = require('../src')

let keyring = null
let keyPair1 = null
let keyPair2 = null
let signatureCipher = null
beforeAll(async () => {
  keyring = new Keyring()
  keyPair1 = createKeyPair(mnemonicGenerate())
  keyPair2 = createKeyPair(mnemonicGenerate())
  signatureCipher = newSignatureGeneratedKeyCipherInstance(keyPair1.address)
})

describe('SignatureGeneratedKeyCipher', () => {
  test('cipher/decipher', async () => {
    const payload = Buffer.from(JSON.stringify({ p1: 'hola', p2: 2 }), 'utf8')
    const fullCipheredPayload = await signatureCipher.cipher({ payload })
    // console.log('encrypted: ', fullCipheredPayload)
    let decipheredPayload = await signatureCipher.decipher({ fullCipheredPayload })
    // console.log('decipheredPayload: ', decipheredPayload)
    expect(Buffer.from(decipheredPayload)).toEqual(payload)
    // A new instance for the same address should be able to decipher
    const signatureCipher2 = newSignatureGeneratedKeyCipherInstance(keyPair1.address)
    decipheredPayload = await signatureCipher2.decipher({ fullCipheredPayload })
    // console.log('decipheredPayload: ', decipheredPayload)
    expect(Buffer.from(decipheredPayload)).toEqual(payload)
  })

  test('Should fail for trying to decipher payload using instance with different address', async () => {
    const payload = Buffer.from(JSON.stringify({ p1: 'hola', p2: 2 }), 'utf8')
    const fullCipheredPayload = await signatureCipher.cipher({ payload })
    // console.log('encrypted: ', fullCipheredPayload)
    const signatureCipher2 = newSignatureGeneratedKeyCipherInstance(keyPair2.address)
    try {
      await signatureCipher2.decipher({ fullCipheredPayload })
    } catch (error) {
      expect(error.message).toContain('Could not decrypt message')
    }
  })
})

function newSignatureGeneratedKeyCipherInstance (address) {
  return new SignatureGeneratedKeyCipher({
    address: keyPair1.address,
    signFn: (address, message) => {
      const keyPair = keyring.getPair(address)
      return keyPair.sign(message)
    }
  })
}

function createKeyPair (mnemonic) {
  return keyring.addFromUri(mnemonic, {}, 'ed25519')
}
