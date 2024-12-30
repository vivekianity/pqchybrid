from botan3 import *

rng = RandomNumberGenerator()
no_salt = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # 16 bytes of 0

# Client Keys for Key Exchange global variables
client_private_ecdh = None
client_keyAgreement = None

client_private_mlkem = None
client_public_mlkem = None

# Client Keys for Signature
client_private_ecdsa: PrivateKey = PrivateKey.create("Ed25519", "", rng)
client_public_ecdsa: PublicKey = client_private_ecdsa.get_public_key()

client_private_mldsa: PrivateKey = PrivateKey.create("ML-DSA", "ML-DSA-6x5", rng)
client_public_mldsa: PublicKey = client_private_mldsa.get_public_key()

# CA Keys
with open("ca_private_ecdsa.pem", "r") as file:
    ca_private_ecdsa: PrivateKey = PrivateKey.load(file.read())
with open("ca_public_ecdsa.pem", "r") as file:
    ca_public_ecdsa: PublicKey = PublicKey.load(file.read())

with open("ca_private_mldsa.pem", "r") as file:
    ca_private_mldsa: PrivateKey = PrivateKey.load(file.read())
with open("ca_public_mldsa.pem", "r") as file:
    ca_public_mldsa: PublicKey = PublicKey.load(file.read())

# Sign the client public keys
server_public_keys_concat = client_public_ecdsa.to_pem() + client_public_mldsa.to_pem()
ecdsa_signer = PKSign(ca_private_ecdsa, "")
ecdsa_signer.update(server_public_keys_concat)
ecdsa_signature = ecdsa_signer.finish(rng)

mldsa_signer = PKSign(ca_private_mldsa, "")
mldsa_signer.update(server_public_keys_concat)
mldsa_signature = mldsa_signer.finish(rng)


def getMLDSAPublicKey():
    return client_public_mldsa.to_pem()


def getECDSAPublicKey():
    return client_public_ecdsa.to_pem()


def getECDSASignatureCA():
    return ecdsa_signature


def getMLDSASignatureCA():
    return mldsa_signature


def verifyServerCASignature(server_public_keys_concat, server_ecdsa_signature, server_mldsa_signature):
    ecdsa_verifier = PKVerify(ca_public_ecdsa, "")
    ecdsa_verifier.update(server_public_keys_concat)
    ecdsa_verified = ecdsa_verifier.check_signature(server_ecdsa_signature)

    mldsa_verifier = PKVerify(ca_public_mldsa, "")
    mldsa_verifier.update(server_public_keys_concat)
    mldsa_verified = mldsa_verifier.check_signature(server_mldsa_signature)

    return ecdsa_verified and mldsa_verified


def signECDSASignature(data: str):
    client_ecdsa_signer = PKSign(client_private_ecdsa, "")
    client_ecdsa_signer.update(data)
    return client_ecdsa_signer.finish(rng)


def signMLDSASignature(data: str):
    client_mldsa_signer = PKSign(client_private_mldsa, "")
    client_mldsa_signer.update(data)
    return client_mldsa_signer.finish(rng)


def verifySignature(data: str, signature, public_key: str):
    public_key = PublicKey.load(public_key)
    verifier = PKVerify(public_key, "")
    verifier.update(data)
    return verifier.check_signature(signature)


def generateClientNonce():
    return rng.get(32)


def generateKeyExchangeValue():
    # Generate Client Key Exchange Value ephemerally
    global client_private_ecdh, client_keyAgreement, client_private_mlkem, client_public_mlkem
    client_private_ecdh = PrivateKey.create("ECDH", "x25519", rng)
    client_keyAgreement = PKKeyAgreement(client_private_ecdh, "KDF2(SHA-256)")

    client_private_mlkem = PrivateKey.create("Kyber", "ML-KEM-768", rng)
    client_public_mlkem = client_private_mlkem.get_public_key()

    client_keyAgreement_pub = client_keyAgreement.public_value()
    keyExchangeValue = client_keyAgreement_pub + client_public_mlkem.to_raw()
    print("Client ECDH Public Key: ", client_keyAgreement_pub)
    print("Client ML-KEM Public Key: ", client_public_mlkem.to_raw())
    return keyExchangeValue


def processKeyExchangeResponse(keyExchangeResponse):
    server_keyAgreement_pub = keyExchangeResponse[:32]
    encap_key = keyExchangeResponse[32:]
    kem_dec: KemDecrypt = KemDecrypt(client_private_mlkem, "KDF2(SHA-256)")

    client_mlkem_shared_key = kem_dec.decrypt_shared_key(no_salt, 32, encap_key)
    client_ecdh_shared_key = client_keyAgreement.agree(server_keyAgreement_pub, 32, no_salt)

    client_shared_secret = client_ecdh_shared_key + client_mlkem_shared_key
    return client_shared_secret


def deriveKeys(masterSecret, clientNonce, serverNonce):
    clientServerNonce = clientNonce + serverNonce
    key_block = kdf("HKDF(SHA-256)", masterSecret, 128, clientServerNonce, b'key material')
    clientSessionKey = key_block[:32]
    serverSessionKey = key_block[32:64]
    clientHmacKey = key_block[64:96]
    serverHmacKey = key_block[96:]
    return clientSessionKey, serverSessionKey, clientHmacKey, serverHmacKey
