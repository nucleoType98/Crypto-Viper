#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include "lib/viper.hpp"

using namespace std;
using namespace ViperCipher;

int main(int argc, char **argv) {

    Viper *viper = new Viper();                                                                           

    string_view pipe_file         = "attack_table.txt";                                                  // <-- dictionary table source file(supposing is in current dir)

    /**
     *  Using 5 pre-computed hash values for the demo purpose, those can be how many you want, but the hash algorithm must be the same for all.
     *  For the following records i've used a sha256 bit function algorithm, possible algorithm are (SHA1, SHA224, SHA256, SHA384, SHA512)
     **/
    string  sha256_cipher_target1 = "FB5597D8647D451ABA9CE78B8CEDC238E3F0EAE6D7D4900C7DEA9D82CEC872C0";  // <-- hashed "agony" with 256 bit block size
    string  sha256_cipher_target2 = "BCC649CFDB8CC557053DA67DF7E7FCB740DCF7F721CEBE1F2082597AD0D5E7D8";  // <-- hashed "found" with 256 bit block size
    string  sha256_cipher_target3 = "5E884898DA28047151D0E56F8DC6292773603D0D6AABBDD62A11EF721D1542D8";  // <-- hashed "password" with 256 bit block size
    string  sha256_cipher_target4 = "921A320AA9782C475560FF5136A8CC0B25F3ADF0DE751D918C9D78B105D2E368";  // <-- hashed "conspire" with 256 bit block size
    string  sha256_cipher_target5 = "D90EE9CCF6BEA1D2942A7B21319338198DEC2A746F8A0D0771621F00DA2E0864";  // <-- hashed "drop" with 256 bit block size

    const uint64_t operation_speed = 1000UL;                                                             // <-- loop execution speed in microseconds format,  1 second = 1000000 microseconds

    /**
      * ----------- PARAMETER LIST ------------
      * @param initializer_list<string>                  -> Mandatory   -> the list of records to attack
      * @param string_view                               -> Mandatory   -> the file name to scan
      * @param SHA_BLOCK_SIZE                            -> Optional    -> the hash algorithm to use                               / Default  =SHA_BLOCK_SIZE::SHA256
      * @param CIPHER_ATTACK_ALGO_MODE                   -> Optional    -> the algorithm deduction mode                            / Default  = CIPHER_ATTACK_ALGO_MODE::DEFAULT
      * @param uint64_t                                  -> Optional    -> the loop execution speed in microseconds format         / Default  = 10000  
      */

    viper->CipherAttack( { sha256_cipher_target5, sha256_cipher_target4, sha256_cipher_target3, sha256_cipher_target2, sha256_cipher_target1 },
                         pipe_file,
                         ViperCipher::SHA_BLOCK_SIZE::SHA256,
                         CIPHER_ATTACK_ALGO_MODE::DEFAULT,
                         operation_speed );

    delete viper;
    return 0;
};


