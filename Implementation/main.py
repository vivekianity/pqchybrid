import json
import socket
import threading
import X25519MLKE768M_Client
import AES
from Implementation import X25519MLKE768M_Server


def listen_for_messages(connection, secret, hmac_key):
    while True:
        try:
            message = receive_message(connection, secret, hmac_key)
            if not message:
                print("Connection closed.")
                break
            print(f"\nOther: {message}")
        except:
            print("Error receiving message.")
            break


def send_messages(connection, secret, hmac_key):
    while True:
        message = input("Me: ")
        ciphertxt = AES.encrypt_message(message, secret, hmac_key)
        connection.send(ciphertxt)


def receive_message(connection, secret, hmac_key):
    data = b''
    while True:
        part = connection.recv(1024)
        data += part
        if len(part) < 1024:
            break
    return AES.decrypt_message(data, secret, hmac_key)



def main():
    print("Select mode:"
          "\n1. Client"
          "\n2. Server"
          "\nAny other key to exit.")
    mode = input("Enter mode: ")
    if mode != '1' and mode != '2':
        exit()
    else:
        host = input("Enter host: ")
        port = int(input("Enter port: "))
        if mode == '1':
            client(host, port)
        else:
            server(host, port)


def client(host, port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    # Client Hello
    clientNonce = X25519MLKE768M_Client.generateClientNonce()
    client_socket.send(clientNonce)
    print("Client Hello sent.")
    print("Client Random: ", clientNonce)
    print("-------------------")

    # Server Hello with server public keys and the signatures for the public keys
    server_response = b''
    while True:
        part = client_socket.recv(1024)
        server_response += part
        if len(part) < 1024:
            break
    server_response = json.loads(server_response)
    serverNonce = bytes.fromhex(server_response["serverNonce"])
    serverECDSAPublicKey = server_response["serverECDSAPublicKey"]
    serverMLDSAPublicKey = server_response["serverMLDSAPublicKey"]
    serverECDSASignature = bytes.fromhex(server_response["serverECDSASignature"])
    serverMLDSASignature = bytes.fromhex(server_response["serverMLDSASignature"])
    print("Server Hello received.")
    print("Server Random: ", serverNonce)
    print("Server Public Keys and signature received.")
    print("Server EdDSA Public Key: ", serverECDSAPublicKey)
    print("Server MLDSA Public Key: ", serverMLDSAPublicKey)
    print("Server EdDSA Signature: ", serverECDSASignature)
    print("Server MLDSA Signature: ", serverMLDSASignature)
    if not X25519MLKE768M_Client.verifyServerCASignature(serverECDSAPublicKey + serverMLDSAPublicKey, serverECDSASignature, serverMLDSASignature):
        print("Server CA signature verification failed.")
        client_socket.close()
        return
    print("Signatures verified.")
    print("-------------------")

    # Client response with client public keys and the signatures for the public keys
    client_response = {
        "clientECDSAPublicKey": X25519MLKE768M_Client.getECDSAPublicKey(),
        "clientMLDSAPublicKey": X25519MLKE768M_Client.getMLDSAPublicKey(),
        "clientECDSASignature": X25519MLKE768M_Client.getECDSASignatureCA().hex(),
        "clientMLDSASignature": X25519MLKE768M_Client.getMLDSASignatureCA().hex()
    }
    client_response_json = json.dumps(client_response).encode()
    client_socket.sendall(client_response_json)
    print("Client public keys and signatures sent.")
    print("Client EdDSA Public Ley: ", client_response["clientECDSAPublicKey"])
    print("Client MLDSA Public Key: ", client_response["clientMLDSAPublicKey"])
    print("Client EdDSA Signature: ", bytes.fromhex(client_response["clientECDSASignature"]))
    print("Client MLDSA Signature: ", bytes.fromhex(client_response["clientMLDSASignature"]))
    print("-------------------")

    # Client now sends the key exchange value and the signatures for the key exchange values
    keyExchangeValue = X25519MLKE768M_Client.generateKeyExchangeValue()
    toSign = clientNonce + serverNonce + keyExchangeValue
    client_key_exchange_values ={
        "keyExchangeValue": keyExchangeValue.hex(),
        "clientECDSAKeyExchangeSignature": X25519MLKE768M_Client.signECDSASignature(toSign.hex()).hex(),
        "clientMLDSAKeyExchangeSignature": X25519MLKE768M_Client.signMLDSASignature(toSign.hex()).hex()
    }
    client_key_exchange_values_json = json.dumps(client_key_exchange_values).encode()
    client_socket.sendall(client_key_exchange_values_json)
    print("Client key exchange values sent with Signatures.")
    print("Client Key Exchange Value: ", bytes.fromhex(client_key_exchange_values["keyExchangeValue"]))
    print("Client EdDSA Key Exchange Signature: ", bytes.fromhex(client_key_exchange_values["clientECDSAKeyExchangeSignature"]))
    print("Client MLDSA Key Exchange Signature: ", bytes.fromhex(client_key_exchange_values["clientMLDSAKeyExchangeSignature"]))
    print("-------------------")

    # Server response with the key exchange value
    server_key_exchange_values = b''
    while True:
        part = client_socket.recv(1024)
        server_key_exchange_values += part
        if len(part) < 1024:
            break
    server_key_exchange_values_dict = json.loads(server_key_exchange_values)
    keyExchangeResponse = bytes.fromhex(server_key_exchange_values_dict["keyExchangeResponse"])
    serverECDSAKeyExchangeSignature = bytes.fromhex(server_key_exchange_values_dict["serverECDSAKeyExchangeSignature"])
    serverMLDSAKeyExchangeSignature = bytes.fromhex(server_key_exchange_values_dict["serverMLDSAKeyExchangeSignature"])
    toVerify = clientNonce + serverNonce + keyExchangeResponse
    print("Server key exchange values received with Signatures.")
    print("Server Key Exchange Value: ", keyExchangeResponse)
    print("Server EdDSA Key Exchange Signature: ", serverECDSAKeyExchangeSignature)
    print("Server MLDSA Key Exchange Signature: ", serverMLDSAKeyExchangeSignature)
    if not X25519MLKE768M_Client.verifySignature(toVerify.hex(), serverECDSAKeyExchangeSignature, serverECDSAPublicKey)\
            and not X25519MLKE768M_Client.verifySignature(toVerify.hex(), serverMLDSAKeyExchangeSignature, serverMLDSAPublicKey):
        print("Server key exchange signature verification failed.")
        client_socket.close()
        return
    print("Signatures verified.")
    print("-------------------")

    masterSecret = X25519MLKE768M_Client.processKeyExchangeResponse(keyExchangeResponse)
    print("Master Secret derived: ", masterSecret)
    print("-------------------")
    clientSessionKey, serverSessionKey, clientHmacKey, serverHmacKey = X25519MLKE768M_Client.deriveKeys(masterSecret, clientNonce, serverNonce)
    print("Client Session Key: ", clientSessionKey)
    print("Server Session Key: ", serverSessionKey)
    print("Client HMAC Key: ", clientHmacKey)
    print("Server HMAC Key: ", serverHmacKey)
    print("-------------------")

    threading.Thread(target=listen_for_messages, args=(client_socket, serverSessionKey, serverHmacKey)).start()
    threading.Thread(target=send_messages, args=(client_socket, clientSessionKey, clientHmacKey)).start()

def server(host, port):

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print("Waiting for a connection...")

    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")

    clientNonce = conn.recv(1024)
    print("Client Hello received.")
    print("Client Random: ", clientNonce)
    print("-------------------")

    serverNonce = X25519MLKE768M_Server.generateServerNonce()
    server_response = {
        "serverNonce": serverNonce.hex(),
        "serverECDSAPublicKey": X25519MLKE768M_Server.getECDSAPublicKey(),
        "serverMLDSAPublicKey": X25519MLKE768M_Server.getMLDSAPublicKey(),
        "serverECDSASignature": X25519MLKE768M_Server.getECDSASignatureCA().hex(),
        "serverMLDSASignature": X25519MLKE768M_Server.getMLDSASignatureCA().hex()
    }
    server_response_json = json.dumps(server_response).encode()
    conn.sendall(server_response_json)
    print("Server Hello sent.")
    print("Server Random: ", serverNonce)
    print("Server Public Keys and signature sent.")
    print("Server EdDSA Public Key: ", server_response["serverECDSAPublicKey"])
    print("Server MLDSA Public Key: ", server_response["serverMLDSAPublicKey"])
    print("Server ECDSA Signature: ", bytes.fromhex(server_response["serverECDSASignature"]))
    print("Server MLDSA Signature: ", bytes.fromhex(server_response["serverMLDSASignature"]))
    print("-------------------")
    # Client response with client public keys and the signatures for the public keys
    client_response = b''
    while True:
        part = conn.recv(1024)
        client_response += part
        if len(part) < 1024:
            break
    client_response_dict = json.loads(client_response)
    clientECDSAPublicKey = client_response_dict["clientECDSAPublicKey"]
    clientMLDSAPublicKey = client_response_dict["clientMLDSAPublicKey"]
    clientECDSASignature = bytes.fromhex(client_response_dict["clientECDSASignature"])
    clientMLDSASignature = bytes.fromhex(client_response_dict["clientMLDSASignature"])
    print("Client public keys and signatures received.")
    print("Client EdDSA Public Key: ", clientECDSAPublicKey)
    print("Client MLDSA Public Key: ", clientMLDSAPublicKey)
    print("Client EdDSA Signature: ", clientECDSASignature)
    print("Client MLDSA Signature: ", clientMLDSASignature)
    if not X25519MLKE768M_Server.verifyClientCASignature(clientECDSAPublicKey + clientMLDSAPublicKey,
                                                         clientECDSASignature, clientMLDSASignature):
        print("Client CA signature verification failed.")
        conn.close()
        return
    print("Signatures verified.")
    print("-------------------")

    # Client now sends the key exchange value and the signatures for the key exchange values
    clientKeyExchangeValues = b''
    while True:
        part = conn.recv(1024)
        clientKeyExchangeValues += part
        if len(part) < 1024:
            break
    clientKeyExchangeValues_dict = json.loads(clientKeyExchangeValues)
    keyExchangeValue = bytes.fromhex(clientKeyExchangeValues_dict["keyExchangeValue"])
    clientECDSAKeyExchangeSignature = bytes.fromhex(clientKeyExchangeValues_dict["clientECDSAKeyExchangeSignature"])
    clientMLDSAKeyExchangeSignature = bytes.fromhex(clientKeyExchangeValues_dict["clientMLDSAKeyExchangeSignature"])
    toVerify = clientNonce + serverNonce + keyExchangeValue
    print("Client key exchange values received with Signatures.")
    print("Client Key Exchange Value: ", keyExchangeValue)
    print("Client EdDSA Key Exchange Signature: ", clientECDSAKeyExchangeSignature)
    print("Client MLDSA Key Exchange Signature: ", clientMLDSAKeyExchangeSignature)
    if not X25519MLKE768M_Server.verifySignature(toVerify.hex(), clientECDSAKeyExchangeSignature, clientECDSAPublicKey)\
            and not X25519MLKE768M_Server.verifySignature(toVerify.hex(), clientMLDSAKeyExchangeSignature, clientMLDSAPublicKey):
        print("Client key exchange signature verification failed.")
        conn.close()
        return
    print("Signatures verified.")
    print("-------------------")

    # Server response with the key exchange value
    keyExchangeResponse, masterSecret = X25519MLKE768M_Server.processKeyExchangeValue(keyExchangeValue)
    print("Master Secret derived: ", masterSecret)
    print("-------------------")
    toSign = clientNonce + serverNonce + keyExchangeResponse
    server_key_exchange_values = {
        "keyExchangeResponse": keyExchangeResponse.hex(),
        "serverECDSAKeyExchangeSignature": X25519MLKE768M_Server.signECDSASignature(toSign.hex()).hex(),
        "serverMLDSAKeyExchangeSignature": X25519MLKE768M_Server.signMLDSASignature(toSign.hex()).hex()
    }
    server_key_exchange_values_json = json.dumps(server_key_exchange_values).encode()
    conn.sendall(server_key_exchange_values_json)
    print("Server key exchange values sent with Signatures.")
    print("Server Key Exchange Value: ", bytes.fromhex(server_key_exchange_values["keyExchangeResponse"]))
    print("Server EdDSA Key Exchange Signature: ", bytes.fromhex(server_key_exchange_values["serverECDSAKeyExchangeSignature"]))
    print("Server MLDSA Key Exchange Signature: ", bytes.fromhex(server_key_exchange_values["serverMLDSAKeyExchangeSignature"]))
    print("-------------------")

    clientSessionKey, serverSessionKey, clientHmacKey, serverHmacKey = X25519MLKE768M_Server.deriveKeys(masterSecret, clientNonce, serverNonce)
    print("Client Session Key: ", clientSessionKey)
    print("Server Session Key: ", serverSessionKey)
    print("Client HMAC Key: ", clientHmacKey)
    print("Server HMAC Key: ", serverHmacKey)

    threading.Thread(target=listen_for_messages, args=(conn, clientSessionKey, clientHmacKey)).start()
    threading.Thread(target=send_messages, args=(conn, serverSessionKey, serverHmacKey)).start()


if __name__ == "__main__":
    main()
