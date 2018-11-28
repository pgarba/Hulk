#!/bin/bash

# compile
clang++-7 hulk.cpp -O3 -march=native -fms-extensions -o hulk -lpthread -g

#./hulk e 00000000000000000000000000000000 66e94bd4ef8a2c3b884cfa59ca342b2e 00000000000000000000000000000000
#./hulk d 66e94bd4ef8a2c3b884cfa59ca342b2e 00000000000000000000000000000000 00000000000000000000000000000000

#./hulk e 6bc1bee22e409f96e93d7e117393172a 3ad77bb40d7a3660a89ecaf32466ef97 2b7e151628aed2a6abf7158809cf4f3c
#./hulk d 3ad77bb40d7a3660a89ecaf32466ef97 6bc1bee22e409f96e93d7e117393172a 2b7e151628aed2a6abf7158809cf4f3c

#time ./hulk e 00000000000000000000000000000000 a1f6258c877d5fcd8964484538bfc92c FFFFFFFFFFFFFFFFFFFFFFFF????????
#time ./hulk d a1f6258c877d5fcd8964484538bfc92c 00000000000000000000000000000000 ????FFFFFFFFFFFFFFFFFFFFFFFF????

#./hulk d 00000000000000000000000000000000 ac589cfe8a7ae5dd875d9786e5832400 3525ac10bb391d8d5f3914fe94341985
#./hulk e ac589cfe8a7ae5dd875d9786e5832400 00000000000000000000000000000000 3525ac10bb391d8d5f3914fe94341985

#time ./hulk d 00000000000000000000000000000000 ac589cfe8a7ae5dd875d9786e5832400 462f????6ec0fe2b1d63??a59f??cdd0
#./hulk d 00000000000000000000000000000000 ac589cfe8a7ae5dd875d9786e5832400 462f8e8e6ec0fe2b1d63b2a59f7fcdd0 10

# bruteforce
#./hulk d 00000000000000000000000000000000 ac589cfe8a7ae5dd875d9786e5832400 462f????6ec0fe2b1d63??a59f??cdd0 10

#time ./hulk d 00000000000000000000000000000000 ac589cfe8a7ae5dd875d9786e5832400  462f8e8e6ec0fe2b1d63??a59f?????? 10

#time ./hulk e ac589cfe8a7ae5dd875d9786e5832400 00000000000000000000000000000000 3525ac10bb391d8d5f3914fe????????

time ./hulk d 00000000000000000000000000000000 ac589cfe8a7ae5dd875d9786e5832400 3525ac10bb391d8d5f3914fe????????
