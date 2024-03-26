#pragma once
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <iostream>
#include <memory.h>
#include <mutex>
#include <random>
#include <sstream>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <thread>
#include <time.h>
#include <typeinfo>
#include <unistd.h>

// Encryption Libraries
#include <crypto++/aes.h>
#include <crypto++/base64.h>
#include <crypto++/files.h>
#include <crypto++/filters.h>
#include <crypto++/hex.h>
#include <crypto++/modes.h>
#include <crypto++/osrng.h>
#include <crypto++/rijndael.h>
#include <crypto++/rsa.h>
#include <crypto++/sha.h>
#include <cryptopp/cryptlib.h>

using namespace CryptoPP;

namespace ViperCipher
{ 

std::mutex gMutex;

#define __BUFFER_MAX_SIZE__ (unsigned int)4096u

 typedef struct alignas(void *)
    {
        std::basic_string<char> plain;
        std::basic_string<char> hashed;
        std::basic_string<char> encrypted;
        std::basic_string<char> decrypted;
        std::basic_string<char> public_key_pem;
        std::basic_string<char> private_key_pem;
    } BlockStructure;

    typedef struct alignas(void *)
    {
        std::string raw;
        std::string hash;
    } CrackedCipherStructure;

    typedef struct alignas(void *)
    {
        SHA1 s1;
        SHA224 s224;
        SHA256 s256;
        SHA384 s384;
        SHA512 s512;
    } ShaModeStructure;

    enum class RSA_KEY_FLAG : unsigned short int
    {
        FILE_COLLECTOR = 0,
        SCRIPT_COLLECTOR,
        DEFAULT
    };

    enum class RSA_KEY_FILE : unsigned short int
    {
        PUBLIC = 0,
        PRIVATE = 1
    };

    enum class SHA_BLOCK_SIZE : unsigned short int
    {
        SHA1 = 1,
        SHA224 = 224,
        SHA256 = 256,
        SHA384 = 384,
        SHA512 = 512
    };

class Viper
{   
  private:
    BlockStructure Blocks;
    std::vector<CrackedCipherStructure> CrackRegister;

    AutoSeededRandomPool SystemEntropy;

    SecByteBlock use_key;
    SecByteBlock use_iv;
    ShaModeStructure ShaMode;
    bool is_cracker_running = false;
    std::vector<std::string> crack_deck;
    unsigned short int cipher_crack_entries = 0;

  public:
    Viper() : Blocks({})
    {
        this->use_key.resize(AES::DEFAULT_KEYLENGTH);
        this->use_iv.resize(AES::BLOCKSIZE);
        this->SystemEntropy.GenerateBlock(this->use_key, this->use_key.size());
        this->SystemEntropy.GenerateBlock(this->use_iv, this->use_iv.size());
    };

    /**
     * Hash buffer
     * @param const std::string
     * @returns const std::basic_string_view<char>
     */
    const std::basic_string_view<char> Hash(const std::string &target, const SHA_BLOCK_SIZE ShaSize = SHA_BLOCK_SIZE::SHA256) noexcept
    {
        try
        {
            this->Blocks.hashed.clear();

            if (target.empty() == false && target.size() > 0)
            {
                if (ShaSize == SHA_BLOCK_SIZE::SHA1)
                    StringSource(target, true, new HashFilter(this->ShaMode.s1, new HexEncoder(new StringSink(this->Blocks.hashed))));
                else if (ShaSize == SHA_BLOCK_SIZE::SHA224)
                    StringSource(target, true, new HashFilter(this->ShaMode.s224, new HexEncoder(new StringSink(this->Blocks.hashed))));
                else if (ShaSize == SHA_BLOCK_SIZE::SHA256)
                    StringSource(target, true, new HashFilter(this->ShaMode.s256, new HexEncoder(new StringSink(this->Blocks.hashed))));
                else if (ShaSize == SHA_BLOCK_SIZE::SHA384)
                    StringSource(target, true, new HashFilter(this->ShaMode.s384, new HexEncoder(new StringSink(this->Blocks.hashed))));
                else if (ShaSize == SHA_BLOCK_SIZE::SHA512)
                    StringSource(target, true, new HashFilter(this->ShaMode.s512, new HexEncoder(new StringSink(this->Blocks.hashed))));
            }
        }
        catch (const CryptoPP::Exception &__E)
        {
            std::cerr << "Error Crypto: " << __E.what() << std::endl;
        }
        catch (...)
        {
            std::cerr << "Unkown Error: " << std::endl;
        }
        return this->Blocks.hashed;
    };

    /**
     * Encrypt Buffer
     * @param const std::string target
     * @returns const std::basic_string_view<char>
     */
    const std::basic_string_view<char> Encrypt(const std::string &target) noexcept
    {
        try
        {
            this->Blocks.encrypted.clear();
            if (target.empty() == false && target.size() > 0)
            {
                AES::Encryption AesEncryption;
                CBC_Mode<AES>::Encryption CbcEncryption;
                CbcEncryption.SetKeyWithIV(this->use_key, this->use_key.size(), this->use_iv);
                StringSource(target, true, new StreamTransformationFilter(CbcEncryption, new HexEncoder(new StringSink(this->Blocks.encrypted))));
            }
        }
        catch (const CryptoPP::Exception &__E)
        {
            std::cerr << "Error Crypto: " << __E.what() << std::endl;
        }
        catch (...)
        {
            std::cerr << "Unkown Error: " << std::endl;
        }
        return this->Blocks.encrypted;
    };

    /**
     * Decrypt Buffer
     * @param const std::string target
     * @returns const std::basic_string_view<char>
     */
    const std::basic_string_view<char> Decrypt(const std::basic_string_view<char> &target) noexcept
    {
        try
        {
            this->Blocks.decrypted.clear();
            if (target.empty() == false && target.size() > 0)
            {
                AES::Decryption Decryption;
                CBC_Mode<AES>::Decryption CbcDecryption;

                CbcDecryption.SetKeyWithIV(this->use_key, this->use_key.size(), this->use_iv);
                StringSource((this->Blocks.encrypted.length() > 0) ? this->Blocks.encrypted : (std::string)target, true, new HexDecoder(new StreamTransformationFilter(CbcDecryption, new StringSink(this->Blocks.decrypted))));
            }
        }
        catch (const CryptoPP::Exception &__E)
        {
            std::cerr << "Crypto Error: " << __E.what() << std::endl;
        }
        catch (...)
        {
            std::cerr << "Unknown Error" << std::endl;
        }
        return this->Blocks.decrypted;
    };

    /**
     * Generate an public RSA Key, store it in a local file or in a local variable
     * @param const std::basic_string_view<char>&
     * @param const RSA_KEY_FLAG& - a flag indicating if key is supposed to be saved to a file named "KeyFileName" or not
     * @returns this
     */
    ViperCipher::Viper &GenRsaPublicKey(const std::basic_string_view<char> &KeyFileName = "", const ViperCipher::RSA_KEY_FLAG &Flag = ViperCipher::RSA_KEY_FLAG::SCRIPT_COLLECTOR) noexcept
    {
        try
        {
            this->Blocks.public_key_pem.clear();
            if (KeyFileName.empty() == false && KeyFileName.length() > 0)
            {
                const unsigned short int BLOCK_SIZE = 2048u;
                memset((void *)&this->Blocks.public_key_pem, 0, sizeof(std::string));

                InvertibleRSAFunction RSAKeyGen;

                RSAKeyGen.GenerateRandomWithKeySize(this->SystemEntropy, BLOCK_SIZE);
                RSA::PublicKey publicKey(RSAKeyGen);

                publicKey.Save(Base64Encoder(new StringSink(this->Blocks.public_key_pem)).Ref());

                if (static_cast<int>(Flag) == static_cast<int>(RSA_KEY_FLAG::DEFAULT) || static_cast<int>(Flag) == static_cast<int>(RSA_KEY_FLAG::FILE_COLLECTOR))
                {
                    this->FileCollect(KeyFileName, RSA_KEY_FILE::PUBLIC);
                }
            }
        }
        catch (const CryptoPP::Exception &__E)
        {
            std::cerr << "CryptoPP Error: " << __E.what() << std::endl;
        }
        catch (...)
        {
            std::cerr << "Unknown Error" << std::endl;
        }
        return *this;
    };

    /**
     * Generate an RSA Private Key, store it in a local file or in a local variable
     * @param const std::basic_string_view<char>&
     * @param const RSA_KEY_FLAG& - a flag indicating if key is supposed to be saved to a file named "KeyFileName" or not
     * @returns this
     */
    ViperCipher::Viper &GenRsaPrivateKey(const std::basic_string_view<char> &KeyFileName = "", const ViperCipher::RSA_KEY_FLAG &Flag = ViperCipher::RSA_KEY_FLAG::SCRIPT_COLLECTOR) noexcept
    {
        try
        {
            this->Blocks.private_key_pem.clear();
            if (KeyFileName.empty() == false && KeyFileName.length() > 0)
            {
                const unsigned short int BLOCK_SIZE = 2048u;
                memset((void *)&this->Blocks.private_key_pem, 0, sizeof(std::string));

                InvertibleRSAFunction RSAKeyGen;

                RSAKeyGen.GenerateRandomWithKeySize(this->SystemEntropy, BLOCK_SIZE);
                RSA::PrivateKey privateKey(RSAKeyGen);

                privateKey.Save(Base64Encoder(new StringSink(this->Blocks.private_key_pem)).Ref());

                if (static_cast<int>(Flag) == static_cast<int>(RSA_KEY_FLAG::DEFAULT) || static_cast<int>(Flag) == static_cast<int>(RSA_KEY_FLAG::FILE_COLLECTOR))
                {
                    this->FileCollect(KeyFileName, RSA_KEY_FILE::PRIVATE);
                }
            }
        }
        catch (const CryptoPP::Exception &__E)
        {
            std::cerr << "CryptoPP Error: " << __E.what() << std::endl;
        }
        catch (...)
        {
            std::cerr << "Unknown Error" << std::endl;
        }
        return *this;
    };

    const std::string getPublicKey(void) noexcept
    {
        return this->Blocks.public_key_pem;
    };

    const std::string getPrivateKey(void) noexcept
    {
        return this->Blocks.private_key_pem;
    };

    /**
     * Revoke the Key/Initialization Vector Blocks
     * @param void
     * @returns void
     */
    void RevokeKeyIv(void) noexcept
    {
        this->use_key.New(AES::DEFAULT_KEYLENGTH);
        this->use_iv.New(AES::BLOCKSIZE);
        this->SystemEntropy.GenerateBlock(this->use_key, this->use_key.size());
        this->SystemEntropy.GenerateBlock(this->use_iv, this->use_iv.size());
    };

    /**
     * Cipher SHA[x] block attack, expose the real value between a [sha1, sha224, sha256, sha384, sha512] blocks.
     * @param const std::basic_string<char>  -the cipher to attack in hex format
     * @param const std::basic_string_view<char> - the dictionary table source file to collect keys from
     * @param const SHA_BLOCK_SIZE - the sha key size
     * @param const unsigned long int - the speed of each iteration
     * @returns void
     */
    ViperCipher::Viper &CipherAttack(const std::initializer_list<std::basic_string<char>> &cipher_target_list, const std::basic_string_view<char> &target_file,
                                     const SHA_BLOCK_SIZE use_sha_mode = SHA_BLOCK_SIZE::SHA256, const unsigned long int crack_speed_ms = 10000) noexcept
    {

        std::cout << "Nunber of entries to crack: " << cipher_target_list.size() << std::endl;
        this->cipher_crack_entries = cipher_target_list.size();
        if (cipher_target_list.size() > 0)
        {
            std::vector<std::string> attack_list;
            std::fstream TableGetEntries(target_file.data());
            std::string collect;
            if (TableGetEntries.is_open())
            {
                std::cout << "Aquiring Resources from <" << target_file << ">" << std::endl;
                while (std::getline(TableGetEntries, collect))
                {
                    std::cout << collect << std::flush;
                    attack_list.push_back(collect);
                    std::cout << std::endl;
                }
            }

            TableGetEntries.close();

            std::cout << "\nCollected (" << attack_list.size() << ")\n"
                      << "Loading entries, 1 second ..." << std::endl;

            std::this_thread::sleep_for(std::chrono::microseconds(4000000));

            std::string result = "";

            std::function<bool()> block_match = [&]() -> bool {
                bool got_exposed = false;
                for (auto &x : cipher_target_list)
                    if (result == x)
                        got_exposed = true;

                return got_exposed;
            };

            for (auto &list_target : attack_list)
            {
                if (list_target.empty() == false && list_target.length() > 0)
                {
                    this->is_cracker_running = true;
                    if (use_sha_mode == SHA_BLOCK_SIZE::SHA256)
                    {
                        result.clear();
                        StringSource(list_target, true, new HashFilter(this->ShaMode.s256, new HexEncoder(new StringSink(result))));
                        std::cout << result << std::flush << std::endl;
                        if (block_match() == true)
                        {
                            gMutex.try_lock();
                            this->CrackRegister.push_back({list_target, result});
                            gMutex.unlock();
                        }
                        std::this_thread::sleep_for(std::chrono::microseconds(crack_speed_ms));
                    }
                }
            }
            std::cout << "Resource Scan Finished!" << std::endl;
            this->is_cracker_running = false;
        }
        return *this;
    };

    ViperCipher::Viper &CipherAttackDetached(const std::initializer_list<std::basic_string<char>> &cipher_target, const std::basic_string_view<char> &target_file,
                                             const SHA_BLOCK_SIZE use_sha_mode = SHA_BLOCK_SIZE::SHA256, const unsigned long int crack_speed_ms = 10000) noexcept
    {

        std::function<void()> cb = [&](void) -> void {
            this->CipherAttack(cipher_target, target_file, use_sha_mode, crack_speed_ms);
            return;
        };
        std::thread execThread(cb);
        if (execThread.joinable())
        {
            execThread.detach();
        }

        return *this;
    };

    /**
     * Wait Cipher Attacker to complete before exiting.
     * @param void
     * @returns void
     */
    void ThreadWait(void) noexcept
    {
        std::thread observer([&]() {
            std::this_thread::sleep_for(std::chrono::seconds(6));
            while (this->is_cracker_running)
            {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        });
        if (observer.joinable())
            observer.join();

        std::cout << "Reversed " << this->CrackRegister.size() << "/" << this->cipher_crack_entries << " cipher blocks!" << std::endl;
        std::cout << "\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n" << std::endl;
        if (this->CrackRegister.size() > 0)
        {
            for (unsigned short int i = 0; i < this->CrackRegister.size(); ++i)
                std::cout << this->CrackRegister[i].hash << " = " << this->CrackRegister[i].raw << std::endl;
        }
        std::cout << "\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n" << std::endl;
    };

    ~Viper()
    {
        std::cout << "Goodbye..." << std::endl;
    };

  private:
    /**
     * Store public/private into KeyFileName file
     * @param std::basic_string_view<char>&
     * @Param const Viper::RSA_KEY_FILE - a flag indicating if the key is public or private
     * @returns const void
     */
    const void FileCollect(const std::basic_string_view<char> &KeyFileName, const RSA_KEY_FILE Flag) noexcept
    {
        FileSink KeyFileSinker(KeyFileName.data());
        if (Flag == ViperCipher::RSA_KEY_FILE::PUBLIC)
            KeyFileSinker.Put(reinterpret_cast<const CryptoPP::byte *>(this->Blocks.public_key_pem.data()), this->Blocks.public_key_pem.size());
        else
            KeyFileSinker.Put(reinterpret_cast<const CryptoPP::byte *>(this->Blocks.private_key_pem.data()), this->Blocks.private_key_pem.size());
    };
};

}; // namespace ViperCipher
