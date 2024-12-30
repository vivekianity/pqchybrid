# Hybrid Encryption Method: pqchybrid

## Overview
This project implements a Hybrid Encryption Method that combines classical cryptographic techniques with post-quantum cryptographic methods to provide secure data transmission in light of potential quantum computing threats.

![Methodolody](image.jpg)

## Features
The algorithms used are EdDSA with Ed25519, ML-DSA-6x5, ML-KEM-768 and ECDH with x25519. 

For key exchange, a hybrid scheme is employed. A classical key exchange protocol, such as ECDH, a post-quantum key exchange protocol, such as ML-KEM, and quantum key distribution are used. The keys are then all concatenated together and passed through a key derivation function to generate the symmetric and HMAC keys. The use of a key derivation function ensures that the symmetric and HMAC keys are not compromised even if the attacker compromises one of the key exchange protocols, as the symmetric and HMAC keys depend on all key exchange protocols to be executed correctly to be generated properly.

For signatures, a double signature scheme is employed. A classical signature scheme, such as EdDSA, and a post quantum signature scheme, such as ML-DSA, will be used in parallel. Both signatures are required to be validated for the authenticity and integrity of the message to be considered verified. In the case where the classical signature scheme is broken due to quantum attacks, the integrity and authenticity of the message is still preserved due to the usage of the post quantum signature scheme. Similarly, in the case where the post quantum signature scheme is broken due to flaws in the scheme, the integrity and authenticity of the message is still preserved through the usage of the classical signature scheme. Overall, the dual signature scheme provides resiliency against classical and quantum based threats.

## Requirements
- Python 3.10 or higher

## Installation
1. Clone this repository: git clone https://github.com//pqchybrid.git

## Set - Up 
1. Identify the IP address and port that your device is running. 
a. If you are running both the server and the client are running on the same device, you should use your loopback ip.
b. If both the server and the cient are running on different device, you should use the ip address that is connected to the network.

3. Navigate to the project directory
4. To set the PQC communication channel, run main.py
