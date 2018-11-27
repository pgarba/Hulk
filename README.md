# Hulk

Hulk is able to bruteforce missing bytes after a DCA attack on AES with his special ability of AES-NI

Hulk makes use of the AES-NI extension to bruteforce up to 6 missing bytes of AES. If you are lucky to own
a Threadripper 1950x, Hulk will use 2 AES-NI engines per core which makes the attack really fast.


# Numbers

Threadripper 1950x (2 AES NI Units per Core)

32 bit - aes ni 32 threads : 1.2s

40 bit - aes ni 32 threads : 5.17m

48 bit - aes ni 32 threads : ~23h

Core i7-6700k @ 4ghz (1 AES NI Unit per Core)

32 bit - aes ni 4 threads : real 0m20.776s

32 bit - aes ni 8 threads : real 0m29.173


# Installation

Compile and test with the given script ./build_and_test.sh or by using clang:

clang++-7 aes.cpp -O3 -march=native -fms-extensions -o hulk -lpthread -g


# Usage

./hulk e|d input output key 10:Optional

e|d         - Attack (e) encryption or (d) decryption

input       - The to input to the AES whitebox

output      - The output of the AES whitebox
	
key         - The partial key retrieved by the DCA attack

              Mark the missing bytes with '??'
								
10:Optional - Handle the key as a round 10 key

              Hulk will calculate the round 0 key and test it against the given test vector 
								


# Example

time ./hulk d 00000000000000000000000000000000 ac589cfe8a7ae5dd875d9786e5832400 462f8e8e6ec0fe2b1d63????9f7f???? 10

AES Key tester v0.1 (pgarba 2018)

[*] AES-NI is supported by this CPU!

[*] Round           : 10

[*] Mode            : Decryption

[*] Key             : 462f8e8e6ec0fe2b1d6300009f7f0000

[*] Input           : 00000000000000000000000000000000

[*] Expected        : ac589cfe8a7ae5dd875d9786e5832400

[!] Bruteforce      : 4 missing bytes

[*] Byte 0 Index 10

[*] Byte 1 Index 11

[*] Byte 2 Index 14

[*] Byte 3 Index 15

[*] AES-NI Units    : 8

[*] Range           : 00000000 - FFFFFFFF

[*] Step            : 1FFFFFFF

[*] T00 Range       : 00000000 - 1FFFFFFF

[*] T01 Range       : 20000000 - 3FFFFFFF

[*] T02 Range       : 40000000 - 5FFFFFFF

[*] T03 Range       : 60000000 - 7FFFFFFF

[*] T04 Range       : 80000000 - 9FFFFFFF

[*] T05 Range       : A0000000 - BFFFFFFF

[*] T06 Range       : C0000000 - DFFFFFFF

[*] T07 Range       : E0000000 - FFFFFFFF

[!] T06 Key found   : 3525ac10bb391d8d5f3914fe94341985

[*] Output          : ac589cfe8a7ae5dd875d9786e5832400

[!] Valid key!



real    0m29.173s

user    3m49.406s

sys     0m0.141s
