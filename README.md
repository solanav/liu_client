# How to build/compile

1. Use linux

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

# Packet structure

1. HEADER > 2 bytes
2. NUM    > 2 bytes
3. COOKIE > 4 bytes
4. DATA   > 468 bytes
5. EMPTY  > 36 bytes
