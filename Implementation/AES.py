from botan3 import *

rng = RandomNumberGenerator()


def encrypt_message(message, secret, hmac_key):
    aes: SymmetricCipher = SymmetricCipher("AES-256/CBC", encrypt=True)
    aes.set_key(secret)
    iv = rng.get(aes.default_nonce_length())
    aes.start(iv)
    message_bytes = message.encode()
    ciphertext = aes.finish(message_bytes)
    ivWithCiphertext = iv + ciphertext

    hmac: MsgAuthCode = MsgAuthCode("HMAC(SHA-256)")
    hmac.set_key(hmac_key)
    hmac.update(ivWithCiphertext)
    tag = hmac.final()

    return ivWithCiphertext + tag


def decrypt_message(ciphertext, secret, hmac_key):
    hmac: MsgAuthCode = MsgAuthCode("HMAC(SHA-256)")
    hmac.set_key(hmac_key)
    hmac.update(ciphertext[:-hmac.output_length()])
    tag = hmac.final()
    ciphertextTag = ciphertext[-hmac.output_length():]
    if not ciphertextTag == tag:
        return "Message authentication failed - tag mismatch"

    aes: SymmetricCipher = SymmetricCipher("AES-256/CBC", encrypt=False)
    aes.set_key(secret)
    iv = ciphertext[:aes.default_nonce_length()]
    aes.start(iv)
    plaintext = aes.finish(ciphertext[aes.default_nonce_length():-hmac.output_length()])
    return plaintext.decode()
