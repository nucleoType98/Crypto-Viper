#include "lib/viper.hpp"

using namespace std;
using namespace ViperCipher;

int main(int argc, char **argv)
{

    std::basic_string_view<char>  plain_text = "something to hash";

    Viper *BlackMamba = new Viper();

    std::basic_string_view<char> encrypted = BlackMamba->Encrypt(plain_text);
    WStr decrypted = BlackMamba->Decrypt(encrypted);
    
    std::cout << "Encrypted: " << encrypted << std::endl;
    std::cout << "Decrypted: " << decrypted << std::endl;
 
    delete BlackMamba;

    return EXIT_SUCCESS;
};
