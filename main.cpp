#include "lib/viper.cpp"

using namespace std;
using namespace ViperCipher;

int main(int argc, char **argv)
{

    std::string  plain = "something to hash";

    Viper *viper = new Viper();

    Viper *_viper = new Viper();
    
    Viper *__viper = new Viper();

    // ---------------- Encrypt/Decrypt ------------------- //

    std::string_view enc = viper->Encrypt(plain);
    std::string_view dec = viper->Decrypt(enc);
    
    std::cout << "Encrypted: " << enc << std::endl;
    std::cout << "Decrypted: " << dec << std::endl;

    // ---------------- Hash / Hash+Salt ------------------ //

    const char *hash_salt = "123Salt";

    std::cout << "Target Plain: " << plain << std::endl;

    std::string target = "something here";
    std::string target_2 = "something here .";
    std::string target_3 = "something here ..";

    std::string_view hash = _viper->Hash(target_2);
    std::string_view hash2 = _viper->Hash(target_3);

    std::cout << "Hash  : " << hash << std::endl;
    std::cout << "Hash2 : " << hash2 << std::endl;

    std::cout << "\n-----------------------------------\n";

    
    // ---------------- Garbage Collection ------------------- //

    delete viper;
    delete _viper;
    delete __viper;

    return EXIT_SUCCESS;
};
