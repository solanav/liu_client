# How to build/compile

1. Be in linux

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

