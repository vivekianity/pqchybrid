from botan3 import *

rng = RandomNumberGenerator()
no_salt = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # 16 bytes of 0

# Server Keys for Key Exchange global variables
server_private_ecdh = None
server_keyAgreement = None

# Server Keys for Signature
server_private_ecdsa: PrivateKey = PrivateKey.create("Ed25519", "", rng)
server_public_ecdsa: PublicKey = server_private_ecdsa.get_public_key()

server_private_mldsa: PrivateKey = PrivateKey.create("ML-DSA", "ML-DSA-6x5", rng)
server_public_mldsa: PublicKey = server_private_mldsa.get_public_key()

# CA Keys
with open("ca_private_ecdsa.pem", "r") as file:
    ca_private_ecdsa: PrivateKey = PrivateKey.load(file.read())
with open("ca_public_ecdsa.pem", "r") as file:
    ca_public_ecdsa: PublicKey = PublicKey.load(file.read())

with open("ca_private_mldsa.pem", "r") as file:
    ca_private_mldsa: PrivateKey = PrivateKey.load(file.read())
with open("ca_public_mldsa.pem", "r") as file:
    ca_public_mldsa: PublicKey = PublicKey.load(file.read())

# Sign the server public keys
server_public_keys_concat = server_public_ecdsa.to_pem() + server_public_mldsa.to_pem()
ecdsa_signer = PKSign(ca_private_ecdsa, "")
ecdsa_signer.update(server_public_keys_concat)
ecdsa_signature = ecdsa_signer.finish(rng)

mldsa_signer = PKSign(ca_private_mldsa, "")
mldsa_signer.update(server_public_keys_concat)
mldsa_signature = mldsa_signer.finish(rng)


def getMLDSAPublicKey():
    return server_public_mldsa.to_pem()


def getECDSAPublicKey():
    return server_public_ecdsa.to_pem()


def getECDSASignatureCA():
    return ecdsa_signature


def getMLDSASignatureCA():
    return mldsa_signature


def verifyClientCASignature(client_public_keys_concat, client_ecdsa_signature, client_mldsa_signature):
    ecdsa_verifier = PKVerify(ca_public_ecdsa, "")
    ecdsa_verifier.update(client_public_keys_concat)
    ecdsa_verified = ecdsa_verifier.check_signature(client_ecdsa_signature)

    mldsa_verifier = PKVerify(ca_public_mldsa, "")
    mldsa_verifier.update(client_public_keys_concat)
    mldsa_verified = mldsa_verifier.check_signature(client_mldsa_signature)

    return ecdsa_verified and mldsa_verified


def signECDSASignature(data: str):
    server_ecdsa_signer = PKSign(server_private_ecdsa, "")
    server_ecdsa_signer.update(data)
    return server_ecdsa_signer.finish(rng)


def signMLDSASignature(data: str):
    server_mldsa_signer = PKSign(server_private_mldsa, "")
    server_mldsa_signer.update(data)
    return server_mldsa_signer.finish(rng)


def verifySignature(data: str, signature, public_key: str):
    public_key = PublicKey.load(public_key)
    verifier = PKVerify(public_key, "")
    verifier.update(data)
    return verifier.check_signature(signature)


def generateServerNonce():
    return rng.get(32)


def processKeyExchangeValue(keyExchangeValue):
    # Ephemerally generate
    global server_keyAgreement, server_private_ecdh
    server_private_ecdh = PrivateKey.create("ECDH", "x25519", rng)
    server_keyAgreement = PKKeyAgreement(server_private_ecdh, "KDF2(SHA-256)")

    client_keyAgreement_pub = keyExchangeValue[:32]
    client_public_mlkem_bytes = keyExchangeValue[32:]
    client_public_mlkem = PublicKey.load_ml_kem("ML-KEM-768", client_public_mlkem_bytes)

    kem_enc: KemEncrypt = KemEncrypt(client_public_mlkem, "KDF2(SHA-256)")
    server_mlkem_shared_key, encap_key = kem_enc.create_shared_key(rng, no_salt, 32)

    server_keyAgreement_pub = server_keyAgreement.public_value()
    server_ecdh_shared_key = server_keyAgreement.agree(client_keyAgreement_pub, 32, no_salt)

    server_shared_secret = server_ecdh_shared_key + server_mlkem_shared_key
    keyExchangeResponse = server_keyAgreement_pub + encap_key
    print("Server ECDH Public Key: ", server_keyAgreement_pub)
    print("Server ML-KEM Encap: ", encap_key)
    return keyExchangeResponse, server_shared_secret


def deriveKeys(masterSecret, clientNonce, serverNonce):
    clientServerNonce = clientNonce + serverNonce
    key_block = kdf("HKDF(SHA-256)", masterSecret, 128, clientServerNonce, b'key material')
    clientSessionKey = key_block[:32]
    serverSessionKey = key_block[32:64]
    clientHmacKey = key_block[64:96]
    serverHmacKey = key_block[96:]
    return clientSessionKey, serverSessionKey, clientHmacKey, serverHmacKey
