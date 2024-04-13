#include "lib/viper.cpp"

using namespace std;
using namespace ViperCipher;

int main(int argc, char **argv)
{

    std::string  plain = "something to hash";

    Viper *viper = new Viper();

    // ---------------- Encrypt/Decrypt ------------------- //

    std::string_view enc = viper->Encrypt(plain);
    std::string_view dec = viper->Decrypt(enc);

    std::cout << "plain text: " << plain << std::endl;
    std::cout << "Encrypted: " << enc << std::endl;
    std::cout << "Decrypted: " << dec << std::endl;


    
    // ---------------- Garbage Collection ------------------- //

    delete viper;

    return EXIT_SUCCESS;
};
