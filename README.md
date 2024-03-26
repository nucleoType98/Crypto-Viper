
# C++ Crypto Viper

A simple light-weight crypto library written in c++ for c++.
 
## Detailed Code Semantics

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

    string enc = viper->Encrypt(plain);
    string dec = viper->Decrypt(enc);
    
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

    string hashed = viper->Hash(plain);                           
    delete viper;
    return 0;
};

```

### Specify Hash Algorithm

Available Options:

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

    string hash_sha1 = viper->Hash(plain, ViperCipher::SHA_BLOCK_SIZE::SHA1);

    string hash_sha1224 = viper->Hash(plain, ViperCipher::SHA_BLOCK_SIZE::SHA224);

    string hash_sha256 = viper->Hash(plain, ViperCipher::SHA_BLOCK_SIZE::SHA256);

    string hash_sha384 = viper->Hash(plain, ViperCipher::SHA_BLOCK_SIZE::SHA384);

    string hash_sha512 = viper->Hash(plain, ViperCipher::SHA_BLOCK_SIZE::SHA512);    

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
 
    string get_key = viper->GetPublicKey();     // export key

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
 
    string get_key = viper->GetPrivateKey();           // export key


    /**************** OR *****************/

    string get_key = viper->GenRsaPrivateKey().getPrivateKey();

    return 0;
};


```

### Gen RSA Private/Public Key and Store them File

> Provide a path for the file to store key into as first argument, as second argument a Flag describing the destination store type, The default behavior(RSA_KEY_FLAG::SCRIPT_COLLECTOR) is to store the key locally within the code, to store a key within a file RSA_KEY_FLAG::FILE_COLLECTOR Flag is required

```cpp
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include "lib/viper.hpp"

using namespace std;
using namespace ViperCipher;

int main(int argc, char **argv) {

    Viper viper = new Viper();                                                                           

    viper->GenRsaPrivateKey("private.pem", ViperCipher::Viper::RSA_KEY_FLAG::FILE_COLLECTOR);    // gen key
 
    string get_key = viper->GetPrivateKey();                                                     // export key


    /**************** OR *****************/

    string get_key = viper->GenRsaPrivateKey("private.pem", ViperCipher::Viper::RSA_KEY_FLAG::FILE_COLLECTOR).getPrivateKey();

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

    Viper viper = new Viper();                                                                           

    viper->RevokeKeyIv();
 
    return 0;
};


```


### Hash Cipher Attack

> Crack some hashed entries.

```cpp
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include "lib/viper.hpp"

using namespace std;
using namespace ViperCipher;

int main(int argc, char **argv) {

    Viper viper = new Viper();                                                                           

    
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

## Methods

### Public      

* Constructor(Viper)
* Hash
* Encrypt
* Decrypt
* GenRsaPublicKey
* GenRsaPrivateKey
* GetPublicKey
* GetPrivateKey
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
