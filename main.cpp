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
