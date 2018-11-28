# Hulk

Hulk is able to bruteforce missing bytes after a DCA attack on AES with his special ability of AES-NI

Hulk makes use of the AES-NI extension to bruteforce up to 6 missing bytes of AES. If you are lucky to own  
a Threadripper 1950x, Hulk will use 2 AES-NI engines per core which makes the attack really fast.


# Numbers for AES Decryption - Round 10 Key (average)

#### Threadripper 1950x (2 AES NI Units per Core)

4 Byte - 32 bit - aes ni 16 threads : ~0m0,459s  
5 Byte - 40 bit - aes ni 16 threads : ~1m56,989s  
6 Byte - 48 bit - aes ni 16 threads : ~7h
7 Byte - 56 bit - aes ni 16 threads : ~74 days

#### Core i7-6700k @ 4ghz (1 AES NI Unit per Core)   

4 Byte - 32 bit - aes ni 4 threads : real 0m12.053s  
4 Byte - 32 bit - aes ni 8 threads : real 0m15.999s


# Installation

Compile and test with the given script ./build_and_test.sh or by using clang:

	clang++-7 aes.cpp -O3 -march=native -fms-extensions -o hulk -lpthread -g


# Usage

#### ./hulk e|d input output key 10:Optional

e|d         - Attack (e) encryption or (d) decryption  
input       - The to input to the AES whitebox  
output      - The output of the AES whitebox  
key         - The partial key retrieved by the DCA attack  

              Mark the missing bytes with '??'
								
10:Optional - Handle the key as a round 10 key  

              Hulk will calculate the round 0 key and test it against the given test vector 
								


# Example

#### time ./hulk d 00000000000000000000000000000000 ac589cfe8a7ae5dd875d9786e5832400 462f8e8e6ec0fe2b1d63????9f7f???? 10

	Hulk v1.2 (Peter Garba 2018)  
	[*] AES-NI is supported by this CPU!  
	[*] Round           : 10  
	[*] Mode            : Decryption  
	[*] Key             : 462F8E8E6EC0FE2B1D63??A59F??????  
	[*] Input           : 00000000000000000000000000000000  
	[*] Expected        : ac589cfe8a7ae5dd875d9786e5832400  
	[!] Bruteforce      : 4 missing bytes  
	[*] Byte 0 Index 10  
	[*] Byte 1 Index 13  
	[*] Byte 2 Index 14  
	[*] Byte 3 Index 15  
	[*] AES-NI Units    : 32  
	[*] Range           : 00000000 - FFFFFFFF  
	[*] Step            : 07FFFFFF  
	[*] T00 Range       : 00000000 - 07FFFFFF  
	[*] T01 Range       : 08000000 - 0FFFFFFF  
	[*] T02 Range       : 10000000 - 17FFFFFF  
	[*] T03 Range       : 18000000 - 1FFFFFFF  
	[*] T04 Range       : 20000000 - 27FFFFFF  
	[*] T05 Range       : 28000000 - 2FFFFFFF  
	[*] T06 Range       : 30000000 - 37FFFFFF  
	[*] T07 Range       : 38000000 - 3FFFFFFF  
	[*] T08 Range       : 40000000 - 47FFFFFF  
	[*] T09 Range       : 48000000 - 4FFFFFFF  
	[*] T10 Range       : 50000000 - 57FFFFFF  
	[*] T11 Range       : 58000000 - 5FFFFFFF  
	[*] T12 Range       : 60000000 - 67FFFFFF  
	[*] T13 Range       : 68000000 - 6FFFFFFF  
	[*] T14 Range       : 70000000 - 77FFFFFF  
	[*] T15 Range       : 78000000 - 7FFFFFFF  
	[*] T16 Range       : 80000000 - 87FFFFFF  
	[*] T17 Range       : 88000000 - 8FFFFFFF  
	[*] T18 Range       : 90000000 - 97FFFFFF  
	[*] T19 Range       : 98000000 - 9FFFFFFF  
	[*] T20 Range       : A0000000 - A7FFFFFF  
	[*] T21 Range       : A8000000 - AFFFFFFF  
	[*] T22 Range       : B0000000 - B7FFFFFF  
	[*] T23 Range       : B8000000 - BFFFFFFF  
	[*] T24 Range       : C0000000 - C7FFFFFF  
	[*] T25 Range       : C8000000 - CFFFFFFF  
	[*] T26 Range       : D0000000 - D7FFFFFF  
	[*] T27 Range       : D8000000 - DFFFFFFF  
	[*] T28 Range       : E0000000 - E7FFFFFF  
	[*] T29 Range       : E8000000 - EFFFFFFF  
	[*] T30 Range       : F0000000 - F7FFFFFF  
	[*] T31 Range       : F8000000 - FFFFFFFF  
	[!] T26 Key found   : 3525ac10bb391d8d5f3914fe94341985  
	[!] Round 10 Key    : 462f8e8e6ec0fe2b1d63b2a59f7fcdd0  
	[*] Output          : ac589cfe8a7ae5dd875d9786e5832400  
	[!] Valid key!  


	real	0m0,564s  
	user	0m17,642s  
	sys	0m0,008s  
