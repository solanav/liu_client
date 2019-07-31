# How to build/compile

1. Install [cmoka](https://cmocka.org/) for the tests.

2. Create a folder called build (at the same level as src and the others) and cd inside:
```
$ mkdir build && cd build
```
3. Create the makefile with cmake
```
$ cmake ..
```

4. Use the generated makefile
```
$ make
```
5. Execute the program
```
$ src/liu_client
```

# Encryption notes

We are going to use RSA + AES to encrypt files of all sizes pretty fast. It would be a good idea not to roll our own protocol but we'll see. Both the public and private key will be uploaded to the server 

For communication Server-Client we shall use RSA + SHA512 to sign the instructions sent to all clients. Client-Client communication will not be signed or encrypted further, the server signature is enough to trust the message.

The public certificate from the Server will be hardcoded inside the client.

# P2P protocol and security issues

## Peer discovery.
To be sure a peer is part of the network, each peer should have the IP of the client signed with the server's private key. Doing this, we can verify the IP is signed by the server and we are sure it is part of the network.

## Peer to peer
1. Ping-Pong: Message to make sure the communication is still working. If the peer does not respond in a set ammount of time, it will be removed from the peer list and communicated to the server. The server may not delete the peer, it may be a turned off computer.
2. Peer discovery: To get more peers we can ask other clients to forward some, following the DHT model. This would happen after verifying that the client is part of the network.

## Server to peer
1. The server can signal the peers to forward the instructions to all known peers for a decentralized message. For this to happen, the client must be sure that the message is from the Server.
2. The server can directly send instructions to peers that will only be executed there.
3. The server can send instructions that will be executed only in the given list of peers. This will use DHT.
