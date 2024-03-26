
# Crypto Viper c++ Crypto Blaster

A simple light-weight crypto library written in c++ for c++.

## Detailed Code Semantics

> In this Section we will go deeper into code semantics and it's approach.

### Simple Encryption/Decryption
```cpp
#include "lib/viper.hpp"

using namespace std;
using namespace ViperCipher;

using String std::basic_string_view<char>; // alias

int main(int argc, char **argv)
{

    String  plain = "something to hash";

    Viper *viper = new Viper();

    String enc = viper->Encrypt(plain);
    String dec = viper->Decrypt(enc);
    
    std::cout << "Encrypted: " << enc << std::endl;
    std::cout << "Decrypted: " << dec << std::endl;
 
    delete viper;

    return EXIT_SUCCESS;
};
```

### Hash

```cpp
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include "lib/viper.hpp"

using namespace std;
using namespace ViperCipher;

int main(int argc, char **argv) {

    std::basic_string_view<char> plain = "sucker";                                           // plain text string to hash

    Viper *NewViper = new Viper();                                                           // use default constructor

    std::basic_string_view<char> hashed = NewViper->Hash(plain);                             // Hash plain text

    return 0;
};

```

### Encrypt

```cpp
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include "lib/viper.hpp"

using namespace std;
using namespace ViperCipher;

int main(int argc, char **argv) {

    std::string plain = "sucker";                                                            // plain text string to hash

    Viper *NewViper = new Viper();                                                           // use default constructor

    std::string encrypted = NewViper->Encrypt(plain);                                        // Encrypt plain text

    return 0;
};

```

### Decrypt

```cpp
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include "lib/viper.hpp"

using namespace std;
using namespace ViperCipher;

int main(int argc, char **argv) {

    std::basic_string_view<char> plain = "sucker";                                                            // plain text string to hash

    Viper *NewViper = new Viper();                                                                            // use default constructor

    std::basic_string_view<char> encrypted = NewViper->Encrypt(plain);                                        // Encrypt plain text

    std::basic_string_view<char> decrypted = NewViper->Decrypt(static_cast<std::string>(encrypted));          // Decrypt encrypted cipher

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
