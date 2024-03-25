c++ crypto viper
## C++ Encryption/Decryption/Hashing Lazy Job Done

> The main.cpp source file, serves only to the purpose of showing how to interact with Viper(the useless abstraction Blaster).
> The library resides in the lib folder named "viper.hpp", you need to include that translation unit in order to execute such functions.

## What is About
> this is just an abstracted version of the Crypto++ library in c++, the program(Viper) takes the original library(crypto++) and hides all the details often not important to the programmer, such as generating key/iv blocks.
> This Library is light weight, so it is pretty small in size, actually the only operations allowed are:
* Hash
* Encrypt
* Decrypt

> If you edit the viper.hpp translation unit, then you need to re-compile the main.cpp source file in order to re-assert the unit test using the main entry point, otherwise no changes will take place.
> If you don't care about the unit test within the main source file, then NO need for re-compilation.

### For Installing g++ compiler on Linux OS you can run: 

> $ sudo apt install g++ 

### Then to check the version and installation state run:
