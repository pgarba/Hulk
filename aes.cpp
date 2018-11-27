#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <vector>
#include <cmath>
#include <thread>

// aes ni
#include "aesni.h"

// key schedule to get round 0 key from round 10 key
#include "keyschedule.h"

typedef struct {
  int ThreadID;
  uint64_t Min;
  uint64_t Max;
} Range;
static std::vector<Range> Ranges;

typedef struct {
  int Index;
  uint8_t Value;
  int Shift;
} BByte;
static std::vector<BByte> MissingBytes;


static uint8_t *CHRHEX = (uint8_t *)
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\x0A\x0B\x0C\x0D\x0E\x0F\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\x0A\x0B\x0C\x0D\x0E\x0F\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
 

static bool GetNNICapability()
{
    unsigned int b;

    __asm
    {
        mov     eax, 1
        cpuid
        mov     b, ecx
    }

    return (b & (1 << 25)) != 0;
}

static void phex(uint8_t* str)
{
    unsigned char i;
    for(i = 0; i < 16; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}

static void parseInput(char *I, uint8_t *Out) {
  int n=0;
  const uint8_t *p;
  const uint8_t *D;
  uint8_t c=0, e, *d;
  p = (const uint8_t *) I;
  d = Out;
  D = (d + 16);
  for (; d != D && *p; p++) {
      e = CHRHEX [(int) *p];
      if (e != 0xFF) {
          c = ((c << 4) | e);
          n++;
          if (n == 2) {
              *(d++) = c;
              n = 0;
          }
      }
  }
}

__attribute__((always_inline)) static bool CompareResult(const uint8_t *A, const uint8_t *B) {
  return !memcmp(A,B,16);
}

__attribute__((always_inline)) static void EncryptNI(uint8_t *I, const uint8_t *K) {
  __m128i key_schedule[11];
  aes128_load_key_enc_only(K,key_schedule);
  aes128_enc(key_schedule,I,I);    
}

__attribute__((always_inline)) static void DecryptNI(uint8_t *I, const uint8_t *K) {  
  __m128i key_schedule[20];
  aes128_load_key(K,key_schedule);
  aes128_dec(key_schedule,I,I);
}

__attribute__((always_inline)) static void DecryptNI_fast(uint8_t *I, __m128i key_schedule[20]) {      
  aes128_dec(key_schedule,I,I);
}

static void parseKey(char *I, uint8_t *Out) {
  int n=0;
  const uint8_t *p;
  const uint8_t *D;
  uint8_t c=0, e, *d;
  p = (const uint8_t *) I;
  d = Out;
  D = (d + 16);
  int Index = 0;
  for (; d != D && *p; p++) {
      if (*p == '?') {
        // Unknown Byte
        BByte BB;
        BB.Index = Index;
        BB.Value = 0;
        BB.Shift = MissingBytes.size() * 8;
        MissingBytes.push_back(BB);

        p++;
        *d = 0;
        d++;
        n = 0;
        Index++;
      } else {
        e = CHRHEX [(int) *p];
        if (e != 0xFF) {
            c = ((c << 4) | e);
            n++;
            if (n == 2) {
                *(d++) = c;
                n = 0;
                Index++;
            }
        }
      }      
  }
}

static void BruteforceMissingBytes(const uint8_t Input[16], const uint8_t Expected[16], uint8_t IKey[16], bool Enc, int Round=0) {  
  printf("\nMissing Bytes (%li):\n", MissingBytes.size());

  int B = 0;
  for (auto &BB : MissingBytes) {
    printf("[*] Byte %i\n", B++);
    printf("[*] Index %i\n", BB.Index);        
  }  
  printf("\n");

  if (MissingBytes.size() > 5) {
    printf("[!] Too many missing bytes! (5 max)");
    return;
  }

  // Get amount of threads
  uint64_t V=0;
  uint64_t Max = (uint64_t) ((std::pow(2, MissingBytes.size() *8)) - 1);      

  const int AESNI_Threads = std::thread::hardware_concurrency();
  uint64_t Step = (Max) / AESNI_Threads;
  uint64_t Min = 0;

  printf("[*] AES-NI Units: %i\n", AESNI_Threads);
  printf("[*] Range       : %08lX - %08lX\n", Min, Max);  
  printf("[*] Step        : %08lX\n", Step);
  
  for (int i=0;i<AESNI_Threads;i++) {
    Range R;
    R.Min = Min;    
    if (Min + Step > Max) {
      R.Max = Max;
    } else {
      R.Max = Min + Step;
    }
    
    Min += Step + 1;

    Ranges.push_back(R);
  }

  int TID = 0;
  for (auto &R : Ranges) {
    R.ThreadID = TID++;
    printf("[*] T%i Range       : %08lX - %08lX\n", R.ThreadID,R.Min,R.Max);
  }
 
  // Bruteforce threads
  bool Finished = false;
  std::vector<std::thread> workers;  
  for (auto &R : Ranges) {    
    // Encryption Thread
    if (Enc) {
      workers.push_back(std::thread([&]() {
      uint8_t I[16] = {0};
      uint8_t KeyThread[16] = {0};
      
      // Bruteforce
      for (uint64_t i=R.Min; i<=R.Max; i++) {
        if (Finished)
          return;

        // Set input key
        memcpy(KeyThread, IKey, 16);        
        memcpy(I, Input, 16);        
        
        // Set bruteforced bytes
        for (auto &B : MissingBytes) {
          KeyThread[B.Index] = (uint8_t) ((i >> B.Shift));
        }        
            
        // Encrypt or decrcypt                    
        EncryptNI(I, KeyThread);               

        // Compare if result found
        if (CompareResult(I, Expected) == true) {          
            // Key found
            Finished = true;

            printf("[!] T%i Key found : ", R.ThreadID);
            memcpy(IKey, KeyThread, 16);
            phex(IKey);                          
            return;
          }
      }      
    }));
    } else {
      // Decryption Thread
      workers.push_back(std::thread([&]() {
      uint8_t I[16] = {0};
      //uint8_t KeyThread[16] = {0};            
      __m128i key_schedule_fast[20];
      uint8_t *KeyThread = (uint8_t *) &key_schedule_fast[10];
      memcpy(KeyThread, IKey, 16);
      
      // Bruteforce
      for (uint64_t i=R.Min; i<=R.Max; i++) {
        if (Finished)
          return;

        // Set input key              
        memcpy(I, Input, 16);        
        
        // Set bruteforced bytes
        for (auto &B : MissingBytes) {
          KeyThread[B.Index] = (uint8_t) ((i >> B.Shift));
        }        
            
        // Encrypt or decrcypt    
        // Attack Round 10 on decryption if needed
        if (Round > 0) {     
          KeyExpansionFast(key_schedule_fast);
          aes128_load_dec_only(key_schedule_fast);
          DecryptNI_fast(I, key_schedule_fast);
        } else {
          //KeyExpansion(KeyThread);                                     
          //DecryptNI(I, KeyThread);   
        }        

        // Compare if result found
        if (CompareResult(I, Expected) == true) {          
            // Key found
            Finished = true;

            printf("[!] T%i Key found : ", R.ThreadID);
            if (Round > 0) {              
              memcpy(IKey, &key_schedule_fast[0], 16);
              phex(IKey);   
              printf("[!] Round 10 Key: ");  
              phex(KeyThread);                   
            } else {
              memcpy(IKey, KeyThread, 16);
              phex(IKey);     
            }            
            return;
          }
      }      
    }));
    }
  }

  // Wait until all threads are finished
  for (auto &t : workers) {        
        t.join();                    
    };
}
/*
  Test faster key expension
*/
void TestKey() {
  uint8_t I[16]  = { 0};
  uint8_t Round0[16] = { 0x11 ,0x11 ,0x11 ,0x11 ,0x11 ,0x11 ,0x11 ,0x11 ,0x11 ,0x11 ,0x11 ,0x11 ,0x11 ,0x11 ,0x11 ,0x11};
  __m128i key_schedule[20] = { 0 };
  __m128i key_schedule_fast[20] = { 0 };
  
  aes128_load_key(Round0, key_schedule);  
  

  //copy round 10
  memcpy((uint8_t *) &key_schedule_fast[10], (uint8_t *) &key_schedule[10], 16 );

  for (int i=0;i<20;i++) {
    printf("%02i ", i);
    phex((uint8_t *) &key_schedule[i]);
  }

  memcpy(I, Round0, 16);
  DecryptNI(I, Round0);
  phex(I);
  
  printf("\n");

  KeyExpansionFast(key_schedule_fast);
  aes128_load_dec_only(key_schedule_fast);

  for (int i=0;i<20;i++) {
    printf("%02i ", i);
    phex((uint8_t *) &key_schedule_fast[i]);
  }
  
  memcpy(I, Round0, 16);
  DecryptNI_fast(I, key_schedule_fast);
  phex(I);
}



int main(int argc, char **argv) {
  bool Enc = true;
  int KeyScheduleRound = 0;
  uint8_t plaintext[16] = {0};
  uint8_t ciphertext[16] = {0};
  uint8_t key[16] = {0};

  /*
  TestKey();
  return 0;
  */

  printf("Hulk v0.11 (pgarba 2018)\n");
  if (argc < 5) {
    printf("Usage: %s mode<Enc e | Dec d> <In> <Out> <key> <keyschduleRound:opt>\n", argv[0]);
    return 1;  
  }

  if (GetNNICapability() == false) {
    printf("AES-NI is not supported by this CPU!\n");
    return 0;
  } 

  printf("[*] AES-NI is supported by this CPU!\n");

  if (argv[1][0] != 'e')
    Enc = false;
  
  parseInput(argv[2], plaintext);
  parseInput(argv[3], ciphertext);  
  // parse key and keep ??
  parseKey(argv[4], key);  
  std::string StrKey = argv[4];
  for (auto &c : StrKey) {
    c = std::toupper(c);
  }

   if (argc == 6) {
    KeyScheduleRound = atoi(argv[5]);
    printf("[*] KeySchedule Round: %i\n", KeyScheduleRound);
  }
 
  printf("[*] Mode:       ");
  if (Enc == true)
    printf("Encryption\n");
  else
    printf("Decryption\n");


  printf("[*] Key:        ");
  printf("%s\n", StrKey.c_str());

  printf("[*] Input:      ");
  phex(plaintext);

  printf("[*] Expected:   ");
  phex(ciphertext);

  if (MissingBytes.size() > 0) {
    printf("\n[!] Bruteforce: %li missing bytes\n", MissingBytes.size());
    BruteforceMissingBytes(plaintext, ciphertext, key, Enc, KeyScheduleRound);
  }

  if (MissingBytes.size() == 0 && KeyScheduleRound > 0) {
    __m128i key_schedule_fast[20];
    KeyExpansionFast(key_schedule_fast);
    memcpy(key, &key_schedule_fast[0], 16);    
  }

  if (Enc) {    
    EncryptNI(plaintext, key);
  } else {    
    DecryptNI(plaintext, key);
  }

  printf("[*] Output:     ");
  phex(plaintext);

  bool R = CompareResult(plaintext, ciphertext);
  if (R == true) {
    printf("[!] Valid key!\n");
  } else {
    printf("[!] Wrong key!\n");
  }

  printf("\n");

  return 0;
}
