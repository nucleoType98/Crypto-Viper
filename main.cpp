#include "lib/viper.hpp"

using namespace std;
 
using namespace ViperCipher;

typedef std::basic_string_view<char> WStr;
typedef std::basic_string<char> Str;

int main(int argc, char **argv)
{

    Str  original_text    = "something to hash";
    WStr pem_public_file  = "public_key.pem";
    WStr pem_private_file = "private_key.pem";

    Viper *BlackMamba = new Viper();

    WStr hashed        = BlackMamba->Hash(original_text, ViperCipher::SHA_BLOCK_SIZE::SHA256);
    WStr encrypted     = BlackMamba->Encrypt(original_text);
    WStr decrypted     = BlackMamba->Decrypt(static_cast<std::string>(encrypted));
    Str  PublicKeyPem  = BlackMamba->GenRsaPublicKey(pem_public_file, ViperCipher::RSA_KEY_FLAG::DEFAULT).getPublicKey();
    Str  PrivateKeyPem = BlackMamba->GenRsaPrivateKey(pem_private_file, ViperCipher::RSA_KEY_FLAG::FILE_COLLECTOR).getPrivateKey();
    Str  hash_attack1  = "";
    Str  hash_attack2  = "";
    Str  hash_attack3  = "";
    Str  hash_attack4  = "";
    Str  hash_attack5  = "";

    std::cout << "Hashed: " << hashed << std::endl;
    std::cout << "Encrypted: " << encrypted << std::endl;
    std::cout << "Decrypted: " << decrypted << std::endl;
    std::cout << "PublicKey: " << PublicKeyPem << std::endl;
    std::cout << "PrivateKey: " << PrivateKeyPem << std::endl;
    std::cout << std::flush;

    hash_attack1 = "agony";     // <-- raw bytes data
    hash_attack2 = "found";     // <-- raw bytes data
    hash_attack3 = "password";  // <-- raw bytes data
    hash_attack4 = "conspire";  // <-- raw bytes data
    hash_attack5 = "drop";      // <-- raw bytes data

    WStr pipe_file             = "attack_table.txt";                                                  // <-- dictionary table source file
    Str  sha256_cipher_target1 = "FB5597D8647D451ABA9CE78B8CEDC238E3F0EAE6D7D4900C7DEA9D82CEC872C0";  // <-- hashed "agony" with 256 bit block size
    Str  sha256_cipher_target2 = "BCC649CFDB8CC557053DA67DF7E7FCB740DCF7F721CEBE1F2082597AD0D5E7D8";  // <-- hashed "found" with 256 bit block size
    Str  sha256_cipher_target3 = "5E884898DA28047151D0E56F8DC6292773603D0D6AABBDD62A11EF721D1542D8";  // <-- hashed "password" with 256 bit block size
    Str  sha256_cipher_target4 = "921A320AA9782C475560FF5136A8CC0B25F3ADF0DE751D918C9D78B105D2E368";  // <-- hashed "conspire" with 256 bit block size
    Str  sha256_cipher_target5 = "D90EE9CCF6BEA1D2942A7B21319338198DEC2A746F8A0D0771621F00DA2E0864";  // <-- hashed "drop" with 256 bit block size

    const unsigned long int operation_speed = 5000;

    BlackMamba->CipherAttack({sha256_cipher_target5, sha256_cipher_target4, sha256_cipher_target3, sha256_cipher_target2, sha256_cipher_target1}, pipe_file, ViperCipher::SHA_BLOCK_SIZE::SHA256, operation_speed).ThreadWait();

    delete BlackMamba;

    return EXIT_SUCCESS;
};
