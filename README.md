
# C++ Crypto Viper

A simple light-weight crypto library written in c++ for c++.
 
## Code Semantics

### Simple Encryption/Decryption

> Symmetric Encryption/Decryption using AES/CBC encryption.

```cpp
#include "lib/viper.hpp"

using namespace std;
using namespace ViperCipher;

int main(int argc, char **argv)
{

    string  plain = "something to hash";

    Viper *viper = new Viper();

    string_view enc = viper->Encrypt(plain);
    string_view dec = viper->Decrypt(enc);
    
    std::cout << "Encrypted: " << enc << std::endl;
    std::cout << "Decrypted: " << dec << std::endl;
 
    delete viper;

    return EXIT_SUCCESS;
};
```

### Hash

> Hash a string using SHA-256(DEFAULT) Algorithm.

```cpp
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include "lib/viper.hpp"

using namespace std;
using namespace ViperCipher;

int main(int argc, char **argv) {

    string plain = "sucker";                                          

    Viper *viper = new Viper();                                                           

    string_view hashed = viper->Hash(plain);                           
    delete viper;
    return 0;
};

```

### Specify Hash Algorithm Flag

Available Flags:

* SHA_BLOCK_SIZE::SHA1
* SHA_BLOCK_SIZE::SHA224
* SHA_BLOCK_SIZE::SHA256
* SHA_BLOCK_SIZE::SHA384
* SHA_BLOCK_SIZE::SHA512

```cpp
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include "lib/viper.hpp"

using namespace std;
using namespace ViperCipher;

int main(int argc, char **argv) {

    string plain = "sucker";                                                       

    Viper *viper = new Viper();                                                                       

    string_view hash_sha1 = viper->Hash(plain, ViperCipher::SHA_BLOCK_SIZE::SHA1);

    string_view hash_sha224 = viper->Hash(plain, ViperCipher::SHA_BLOCK_SIZE::SHA224);

    string_view hash_sha256 = viper->Hash(plain, ViperCipher::SHA_BLOCK_SIZE::SHA256);

    string_view hash_sha384 = viper->Hash(plain, ViperCipher::SHA_BLOCK_SIZE::SHA384);

    string_view hash_sha512 = viper->Hash(plain, ViperCipher::SHA_BLOCK_SIZE::SHA512);    

    delete viper;
    return 0;
};

```

### Gen RSA Public Key

> Generate a public key using RSA standard, 

```cpp
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include "lib/viper.hpp"

using namespace std;
using namespace ViperCipher;

int main(int argc, char **argv) {

    Viper *viper = new Viper();                                                                           

    viper->GenRsaPublicKey();                      // gen key
 
    string   get_key = viper->getPublicKey();     // export key

    /**************** OR *****************/

    string get_key = viper->GenRsaPublicKey().getPublicKey();

    delete viper;
    return 0;
};

```

### Gen RSA Private Key

```cpp
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include "lib/viper.hpp"

using namespace std;
using namespace ViperCipher;

int main(int argc, char **argv) {

    Viper *viper = new Viper();                                                                           

    viper->GenRsaPrivateKey();                         // gen key
 
    string get_key = viper->getPrivateKey();           // export key


    /**************** OR *****************/

    string get_key = viper->GenRsaPrivateKey().getPrivateKey();

    return 0;
};


```

### Gen RSA Private/Public Key and Store *_r* into appropriate File/s

> Provide a path for the file to store key into as first argument, as second argument a Flag describing the destination store type, The default behavior(RSA_KEY_FLAG::SCRIPT_COLLECTOR) is to store the key locally within the code, to store a key within a file RSA_KEY_FLAG::FILE_COLLECTOR Flag is required

Available Flags

* RSA_KEY_FLAG::SCRIPT_COLLECTOR -- no file will be written to
* RSA_KEY_FLAG::FILE_COLLECTOR   -- a file will be used to store the key
* RSA_KEY_FLAG::DEFAULT          -- defaults to SCRIPT_COLLECTOR

```cpp
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include "lib/viper.hpp"

using namespace std;
using namespace ViperCipher;

int main(int argc, char **argv) {

    Viper *viper = new Viper();                                                                           

    viper->GenRsaPrivateKey("private.pem", ViperCipher::RSA_KEY_FLAG::FILE_COLLECTOR);    // gen key
 
    string_view get_key = viper->getPrivateKey();                                                     // export key


    /**************** OR *****************/

    string get_key = viper->GenRsaPrivateKey("private.pem", ViperCipher::RSA_KEY_FLAG::FILE_COLLECTOR).getPrivateKey();
    
    delete viper;
    return 0;
};


```

### Revoke Key/IV

> Revoke the current key/iv used for crypto operations.

```cpp
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include "lib/viper.hpp"

using namespace std;
using namespace ViperCipher;

int main(int argc, char **argv) {

    Viper *viper = new Viper();                                                                           

    viper->RevokeKeyIv();

    delete viper;
 
    return 0;
};



```


### Hash Cipher Attack

> Crack hash computed values, this function uses a table of records(human readable words) to crack a list of hashed values you provide as argument, the list must contain a valid set of hash-[Algo] records in order to de-cipher, the attack fails if any of the records are corrupted or altered, you can provide how many records you need within the list, but the file of records to be scanned must contain at least 1 entry.
> You need to specify an algorithm as well for the attack, such as SHA1, SHA256, etc... and finally provide the loop execution speed used to suspand the operation for an X mcs in order to allow proper operation output. 

```cpp
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

    const uint64_t operation_speed = 5000UL;                                                             // <-- loop execution speed in microseconds format,  1 second = 1000000 microseconds

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
    
    return 0;
};



```

### Hash Cipher Attack Detached Mode

> Same as CipherAttack() but uses a detached thread for attacking operations.

```cpp
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

    const uint64_t operation_speed = 5000UL;                                                             // <-- loop execution speed in microseconds format,  1 second = 1000000 microseconds

    /**
      * ----------- PARAMETER LIST ------------
      * @param initializer_list<string>                  -> Mandatory   -> the list of records to attack
      * @param string_view                               -> Mandatory   -> the file name to scan
      * @param SHA_BLOCK_SIZE                            -> Optional    -> the hash algorithm to use                               / Default  =SHA_BLOCK_SIZE::SHA256
      * @param CIPHER_ATTACK_ALGO_MODE                   -> Optional    -> the algorithm deduction mode                            / Default  = CIPHER_ATTACK_ALGO_MODE::DEFAULT
      * @param uint64_t                                  -> Optional    -> the loop execution speed in microseconds format         / Default  = 10000  
      */

    viper->CipherAttackDetached( { sha256_cipher_target5, sha256_cipher_target4, sha256_cipher_target3, sha256_cipher_target2, sha256_cipher_target1 },
                         pipe_file,
                         ViperCipher::SHA_BLOCK_SIZE::SHA256,
                         CIPHER_ATTACK_ALGO_MODE::DEFAULT,
                         operation_speed );

    viper->ThreadWait(); // wait for the termination signal dispatched by CipherAttack() on operation execution done.
                         // This functoin call can also be chained with CipherAttack().ThreadWait()
    
    return 0;
};



```

## Abstracted Code Semantics

## Description

> The library facilitates encryption, decryption, hashing, and reverse cracking (SHA[x] Reverse Ciphers) functionalities through a lightweight class called "Viper."
You need to create an instance of the "Viper" class to utilize these functionalities.

## Compatibility

* Developed and tested on Linux Mint OS, with potential compatibility issues on other platforms like Windows and macOS due to dependencies.

## Compiler
* Developed using g++20 compiler.
* Compiler required flags: "-lcryptopp"


## Dependencies
* Dependencies include Crypto++ and standard C++ libraries.

## Memory Safety
* Tested for memory safety using g++ address-sanitizer flag, with no reported memory leaks.
* Encourages users to compile the library locally and check for memory leaks using the provided shell script.

## Namespace
* ViperCipher

## Macros
* none

## Class
* Viper

## Structures
* BlockStructure
* CrackedCipherStructure
* ShaModeStructure

## Enumerations
* RSA_KEY_FLAG
* RSA_KEY_FILE
* SHA_BLOCK_SIZE
* CIPHER_ATTACK_ALGO_MODE

## Methods

### Public      

* Constructor(Viper)
* Hash
* Encrypt
* Decrypt
* GenRsaPublicKey
* GenRsaPrivateKey
* getPublicKey
* getPrivateKey
* RevokeKeyIv
* CipherAttack
* CipherAttackDetached
* ThreadWait
* Destructor(~Viper)

### Private

* FileCollect

## Static
* none

## Virtual
* none

## Properties

### Public

* Blocks
* CrackRegister
* SystemEntropy
* use_key
* use_iv
* sha_mode
* is_cracker_running
* crack_deck
* cipher_crack_entries

### Static
* none
