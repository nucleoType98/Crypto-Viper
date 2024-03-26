
# C++ Crypto Viper

A simple light-weight crypto library written in c++ for c++.

## Detailed Code Semantics

### Simple Encryption/Decryption

> Symmetric Encryption/Decryption using AES encryption algorithm, this uses a fixed size data blocks [256 bits].  

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

> Hash a string using a SHA-256 bit Block Size(64 bytes), the function takes a reference to a plain text string and returns a hashed version.

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

### Specify Hash Block Size

> In the previous section we used a default block size(256 bits), you can also specify a different block size directly within the function argument.
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

    string hashed = viper->Hash(plain, ViperCipher::SHA_BLOCK_SIZE::SHA1);    
    delete viper;
    return 0;
};

```

### Gen AES Public Key

```cpp
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include "lib/viper.hpp"

using namespace std;
using namespace ViperCipher;

int main(int argc, char **argv) {

    Viper *viper = new Viper();                                                                           

    viper->GenRsaPublicKey("public.pem");
 
    string get_key = viper->GetRsaPublicKey();
    delete viper;
    return 0;
};

```

### Gen AES Private Key

```cpp
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include "lib/viper.hpp"

using namespace std;
using namespace ViperCipher;

int main(int argc, char **argv) {

    Viper *NewViper = new Viper();                                                                           

    BlackMamba->GenRsaPrivateKey("private.pem");
 
    string get_key = BlackMamba->GetRsaPrivateKey();

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
