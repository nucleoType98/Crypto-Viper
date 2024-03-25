
# Crypto Viper c++ Crypto Blaster

A simple light-weight crypto library written in c++ for c++.

## Description

> this library allows you to easily integrate encryption, decryption, hashing and SHA[x] Reverse(Crack) Ciphers.
Implementation resides within a light-weight class named Viper(here the repository name), to work with any of the above functionalities a Viper instance must be created.

## Compatibility

> I built and compiled this program on Linux Mint OS, IDK if it will work on Windows and Mac OS as well, some of the dependencies may not work on other platforms...


## Dependencies
* Crypto++
* Standard C++ Libraries

## Memory Safety
> The library is pretty safe by itself, been tested and compiled using g++ address-sanitizer flag, no memory leaks have been reported so far, you can try to compile the library again within your local environment, and see for yourself, you can re-compile using "compile.sh" shell script located in the root directory of the project.

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

  
