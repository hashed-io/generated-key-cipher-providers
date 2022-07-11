/* eslint-disable no-new */
global.File = class {}
const { PasswordGeneratedKeyCipher } = require('../src')

describe('PasswordGeneratedKeyCipher', () => {
  test('should throw error for easy passwords', async () => {
    try {
      new PasswordGeneratedKeyCipher({
        password: 'A1b$asd'
      })
    } catch (error) {
      expect(error.message).toContain('The password must be at least 8 characters long, and contain at least one lowercase letter, one uppercase letter, one numeric digit, and one special character')
    }
    try {
      new PasswordGeneratedKeyCipher({
        password: 'A1basdac'
      })
    } catch (error) {
      expect(error.message).toContain('The password must be at least 8 characters long, and contain at least one lowercase letter, one uppercase letter, one numeric digit, and one special character')
    }

    try {
      new PasswordGeneratedKeyCipher({
        password: 'A$basdac'
      })
    } catch (error) {
      expect(error.message).toContain('The password must be at least 8 characters long, and contain at least one lowercase letter, one uppercase letter, one numeric digit, and one special character')
    }

    try {
      new PasswordGeneratedKeyCipher({
        password: '1$basdac'
      })
    } catch (error) {
      expect(error.message).toContain('The password must be at least 8 characters long, and contain at least one lowercase letter, one uppercase letter, one numeric digit, and one special character')
    }
  })
  test('cipher/decipher', async () => {
    const password = 'Abfek$%lak232'
    const passwordCipher1 = new PasswordGeneratedKeyCipher({
      password
    })
    const payload = Buffer.from(JSON.stringify({ p1: 'hola', p2: 2 }), 'utf8')
    const fullCipheredPayload = await passwordCipher1.cipher({ payload })
    // console.log('encrypted: ', fullCipheredPayload)
    let decipheredPayload = await passwordCipher1.decipher({ fullCipheredPayload })
    // console.log('decipheredPayload: ', decipheredPayload)
    expect(Buffer.from(decipheredPayload)).toEqual(payload)

    // A new instance with the same password should be able to decipher
    const passwordCipher2 = new PasswordGeneratedKeyCipher({
      password
    })

    decipheredPayload = await passwordCipher2.decipher({ fullCipheredPayload })
    // console.log('decipheredPayload: ', decipheredPayload)
    expect(Buffer.from(decipheredPayload)).toEqual(payload)
  })

  test('Should fail when trying to decipher a payload encrypted with another password', async () => {
    expect.assertions(1)
    const passwordCipher1 = new PasswordGeneratedKeyCipher({
      password: 'Abfek$%lak232'
    })
    const payload = Buffer.from(JSON.stringify({ p1: 'hola', p2: 2 }), 'utf8')
    const fullCipheredPayload = await passwordCipher1.cipher({ payload })
    // console.log('encrypted: ', fullCipheredPayload)
    const passwordCipher2 = new PasswordGeneratedKeyCipher({
      password: 'otherAbfek$%lak232'
    })
    try {
      await passwordCipher2.decipher({ fullCipheredPayload })
    } catch (error) {
      expect(error.message).toContain('Could not decrypt message')
    }
    // console.log('decipheredPayload: ', decipheredPayload)
  })
})
