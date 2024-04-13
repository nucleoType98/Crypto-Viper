#pragma once

#ifndef _GLOBAL_VIPER_

#include "viper.hpp"

ViperCipher::Viper::Viper() : Blocks({}) {
  this->use_key.resize(AES::DEFAULT_KEYLENGTH);
  this->use_iv.resize(AES::BLOCKSIZE);
  this->SystemEntropy.GenerateBlock(this->use_key, this->use_key.size());
  this->SystemEntropy.GenerateBlock(this->use_iv, this->use_iv.size());
  this->Blocks = {};
  this->Blocks.decrypted = "";
  this->Blocks.encrypted = "";
  this->Blocks.hashed = "";
  this->Blocks.plain = "";
  this->Blocks.private_key_pem = "";
  this->Blocks.public_key_pem = "";
  this->cipher_crack_entries = 0;
  this->crack_deck = {};
  this->CrackRegister = {};
  this->is_cracker_running = false;
};

/**
 * Hash buffer
 * @param const std::string
 * @returns const std::basic_string_view<char>
 */
const std::basic_string_view<char> ViperCipher::Viper::Hash(const std::string &target, const ViperCipher::SHA_BLOCK_SIZE ShaSize = ViperCipher::SHA_BLOCK_SIZE::SHA256) noexcept {
  try {
    if (!this->Blocks.hashed.empty())
      this->Blocks.hashed.clear();

    if (!target.empty()) {
      if (ShaSize == ViperCipher::SHA_BLOCK_SIZE::SHA1)
        StringSource(target, true, new HashFilter(this->ShaMode.s1, new HexEncoder(new StringSink(this->Blocks.hashed))));
      else if (ShaSize == ViperCipher::SHA_BLOCK_SIZE::SHA224)
        StringSource(target, true, new HashFilter(this->ShaMode.s224, new HexEncoder(new StringSink(this->Blocks.hashed))));
      else if (ShaSize == ViperCipher::SHA_BLOCK_SIZE::SHA256)
        StringSource(target, true, new HashFilter(this->ShaMode.s256, new HexEncoder(new StringSink(this->Blocks.hashed))));
      else if (ShaSize == ViperCipher::SHA_BLOCK_SIZE::SHA384)
        StringSource(target, true, new HashFilter(this->ShaMode.s384, new HexEncoder(new StringSink(this->Blocks.hashed))));
      else if (ShaSize == ViperCipher::SHA_BLOCK_SIZE::SHA512)
        StringSource(target, true, new HashFilter(this->ShaMode.s512, new HexEncoder(new StringSink(this->Blocks.hashed))));
    }
  } catch (const CryptoPP::Exception &__E) {
    std::cerr << "Error Crypto: " << __E.what() << std::endl;
  } catch (...) {
    std::cerr << "Unkown Error: " << std::endl;
  }
//  std::cout << "Hashed Result: " << this->Blocks.hashed << std::endl;
  std::string_view __r = this->Blocks.hashed.c_str();
  return __r.empty() ? "" : __r;
};

/**
 * Encrypt Buffer
 * @param const std::string target
 * @returns const std::basic_string_view<char>
 */
const std::basic_string_view<char> ViperCipher::Viper::Encrypt(const std::string &target) noexcept {
  try {
    if (!this->Blocks.encrypted.empty())
      this->Blocks.encrypted.clear();

    if (target.empty() == false && target.size() > 0) {
      AES::Encryption AesEncryption;
      CBC_Mode<AES>::Encryption CbcEncryption;
      CbcEncryption.SetKeyWithIV(this->use_key, this->use_key.size(), this->use_iv);
      StringSource(target, true, new StreamTransformationFilter(CbcEncryption, new HexEncoder(new StringSink(this->Blocks.encrypted))));
    }
  } catch (const CryptoPP::Exception &__E) {
    std::cerr << "Error Crypto: " << __E.what() << std::endl;
  } catch (...) {
    std::cerr << "Unkown Error: " << std::endl;
  }
  return !this->Blocks.encrypted.empty() ? this->Blocks.encrypted.c_str() : "";
};

/**
 * Decrypt Buffer
 * @param const std::string target
 * @returns const std::basic_string_view<char>
 */
const std::basic_string_view<char> ViperCipher::Viper::Decrypt(const std::basic_string_view<char> &target) noexcept {
  try {
    if (!this->Blocks.decrypted.empty())
      this->Blocks.decrypted.clear();

    if (!target.empty()) {
      AES::Decryption Decryption;
      CBC_Mode<AES>::Decryption CbcDecryption;

      CbcDecryption.SetKeyWithIV(this->use_key, this->use_key.size(), this->use_iv);
      StringSource((this->Blocks.encrypted.length() > 0) ? this->Blocks.encrypted : (std::string)target, true, new HexDecoder(new StreamTransformationFilter(CbcDecryption, new StringSink(this->Blocks.decrypted))));
    }
  } catch (const CryptoPP::Exception &__E) {
    std::cerr << "Crypto Error: " << __E.what() << std::endl;
  } catch (...) {
    std::cerr << "Unknown Error" << std::endl;
  }
  return !this->Blocks.decrypted.empty() ? this->Blocks.decrypted.c_str() : "";
};

/**
 * Generate an public RSA Key, store it in a local file or in a local variable
 * @param const std::basic_string_view<char>&
 * @param const RSA_KEY_FLAG& - a flag indicating if key is supposed to be saved to a file named "KeyFileName" or not
 * @returns this
 */
ViperCipher::Viper &ViperCipher::Viper::GenRsaPublicKey(const std::basic_string_view<char> &KeyFileName = "", const ViperCipher::RSA_KEY_FLAG &Flag = ViperCipher::RSA_KEY_FLAG::SCRIPT_COLLECTOR) noexcept {
  try {
    if (!this->Blocks.public_key_pem.empty())
      this->Blocks.public_key_pem.clear();

    const unsigned short int BLOCK_SIZE = 2048u;
    memset((void *)&this->Blocks.public_key_pem, 0, sizeof(std::string));

    InvertibleRSAFunction RSAKeyGen;

    RSAKeyGen.GenerateRandomWithKeySize(this->SystemEntropy, BLOCK_SIZE);
    RSA::PublicKey publicKey(RSAKeyGen);

    publicKey.Save(Base64Encoder(new StringSink(this->Blocks.public_key_pem)).Ref());

    if (!KeyFileName.empty()) {
      if (static_cast<int>(Flag) == static_cast<int>(RSA_KEY_FLAG::DEFAULT) || static_cast<int>(Flag) == static_cast<int>(RSA_KEY_FLAG::FILE_COLLECTOR)) {
        this->FileCollect(KeyFileName, RSA_KEY_FILE::PUBLIC);
      }
    }
  } catch (const CryptoPP::Exception &__E) {
    std::cerr << "CryptoPP Error: " << __E.what() << std::endl;
  } catch (...) {
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
ViperCipher::Viper &ViperCipher::Viper::GenRsaPrivateKey(const std::basic_string_view<char> &KeyFileName = "", const ViperCipher::RSA_KEY_FLAG &Flag = ViperCipher::RSA_KEY_FLAG::SCRIPT_COLLECTOR) noexcept {
  try {
    this->Blocks.private_key_pem.clear();

    const unsigned short int BLOCK_SIZE = 2048u;
    memset((void *)&this->Blocks.private_key_pem, 0, sizeof(std::string));

    InvertibleRSAFunction RSAKeyGen;

    RSAKeyGen.GenerateRandomWithKeySize(this->SystemEntropy, BLOCK_SIZE);
    RSA::PrivateKey privateKey(RSAKeyGen);

    privateKey.Save(Base64Encoder(new StringSink(this->Blocks.private_key_pem)).Ref());

    if (!KeyFileName.empty()) {
      if (static_cast<int>(Flag) == static_cast<int>(RSA_KEY_FLAG::DEFAULT) || static_cast<int>(Flag) == static_cast<int>(RSA_KEY_FLAG::FILE_COLLECTOR)) {
        this->FileCollect(KeyFileName, RSA_KEY_FILE::PRIVATE);
      }
    }
  } catch (const CryptoPP::Exception &__E) {
    std::cerr << "CryptoPP Error: " << __E.what() << std::endl;
  } catch (...) {
    std::cerr << "Unknown Error" << std::endl;
  }
  return *this;
};

const std::string ViperCipher::Viper::getPublicKey(void) noexcept { return this->Blocks.public_key_pem.empty() ? "" : this->Blocks.public_key_pem; };

const std::string ViperCipher::Viper::getPrivateKey(void) noexcept { return this->Blocks.private_key_pem.empty() ? "" : this->Blocks.private_key_pem; };

/**
 * Revoke the Key/Initialization Vector Blocks
 * @param void
 * @returns void
 */
void ViperCipher::Viper::RevokeKeyIv(void) noexcept {
  try {
    this->use_key.New(AES::DEFAULT_KEYLENGTH);
    this->use_iv.New(AES::BLOCKSIZE);
    this->SystemEntropy.GenerateBlock(this->use_key, this->use_key.size());
    this->SystemEntropy.GenerateBlock(this->use_iv, this->use_iv.size());
  } catch (...) {
    std::cerr << "Error: RevokeKeyId" << std::endl;
  }
};

/**
 * Cipher SHA[x] block attack, expose the real value between a [sha1, sha224, sha256, sha384, sha512] blocks.
 * @param const std::basic_string<char>  -the cipher to attack in hex format
 * @param const std::basic_string_view<char> - the dictionary table source file to collect keys from
 * @param const ViperCipher::SHA_BLOCK_SIZE - the sha key size
 * @param const unsigned long int - the speed of each iteration
 * @returns void
 */
ViperCipher::Viper &ViperCipher::Viper::CipherAttack(const std::initializer_list<std::basic_string<char>> &cipher_target_list, const std::basic_string_view<char> &target_file, const ViperCipher::SHA_BLOCK_SIZE use_sha_mode = ViperCipher::SHA_BLOCK_SIZE::SHA256, const CIPHER_ATTACK_ALGO_MODE algo_cipher_mode = CIPHER_ATTACK_ALGO_MODE::DEFAULT, const unsigned long int crack_speed_ms = 10000) noexcept {
  try {

    if (cipher_target_list.size() == 0)
      throw std::underflow_error("Please provide a valid list...");

    if (target_file.empty())
      throw std::underflow_error("Please provide a valid target file name...");

    this->cipher_crack_entries = cipher_target_list.size();

    std::vector<std::string> attack_list;
    std::fstream TableGetEntries(target_file.data());
    std::string collect;
    if (TableGetEntries.is_open()) {
      while (std::getline(TableGetEntries, collect)) {
        std::cout << collect << std::flush;
        attack_list.push_back(collect);
        std::cout << std::endl;
      }
    }

    if (attack_list.empty())
      throw std::underflow_error("attack list is empty!");

    TableGetEntries.close();

    std::this_thread::sleep_for(std::chrono::microseconds(4000000));

    std::string result = "";

    std::function<bool()> block_match = [&]() -> bool {
      bool got_exposed = false;
      for (auto &x : cipher_target_list)
        if (result == x)
          got_exposed = true;

      return got_exposed;
    };

    for (auto &list_target : attack_list) {
      if (!list_target.empty()) {
        this->is_cracker_running = true;
        if (use_sha_mode == ViperCipher::SHA_BLOCK_SIZE::SHA256) {
          result.clear();
          StringSource(list_target, true, new HashFilter(this->ShaMode.s256, new HexEncoder(new StringSink(result))));
          std::cout << result << std::flush << std::endl;
          if (block_match() == true) {
            gMutex.try_lock();
            this->CrackRegister.push_back({list_target, result});
            gMutex.unlock();
          }
          std::this_thread::sleep_for(std::chrono::microseconds(crack_speed_ms));
        }
      }
    }

    this->is_cracker_running = false;

  } catch (const std::underflow_error &__e) {
    std::cerr << "Error: Underflow Error => " << __e.what() << std::endl;
  } catch (...) {
    std::cerr << "Error: Hash Cipher Attack Failure!" << std::endl;
  }
  return *this;
};

ViperCipher::Viper &ViperCipher::Viper::CipherAttackDetached(const std::initializer_list<std::basic_string<char>> &cipher_target_list, const std::basic_string_view<char> &target_file, const ViperCipher::SHA_BLOCK_SIZE use_sha_mode = ViperCipher::SHA_BLOCK_SIZE::SHA256, const CIPHER_ATTACK_ALGO_MODE algo_cipher_mode = CIPHER_ATTACK_ALGO_MODE::DEFAULT, const unsigned long int crack_speed_ms = 10000) noexcept {
  try {
    std::function<void()> cb = [cipher_target_list = std::vector<std::basic_string<char>>(cipher_target_list.begin(), cipher_target_list.end()), target_file, use_sha_mode, algo_cipher_mode, crack_speed_ms, this]() -> void {
      this->cipher_crack_entries = cipher_target_list.size();
      if (cipher_target_list.size() > 0) {
        std::vector<std::string> attack_list;
        std::fstream TableGetEntries(target_file.data());
        std::string collect;
        if (TableGetEntries.is_open()) {
          while (std::getline(TableGetEntries, collect)) {
            std::cout << collect << std::flush;
            attack_list.push_back(collect);
            std::cout << std::endl;
          }
        }

        TableGetEntries.close();

        std::this_thread::sleep_for(std::chrono::microseconds(4000000));

        std::string result = "";

        std::function<bool()> block_match = [&]() -> bool {
          bool got_exposed = false;
          for (auto &x : cipher_target_list)
            if (result == x)
              got_exposed = true;

          return got_exposed;
        };

        for (auto &list_target : attack_list) {
          if (list_target.empty() == false && list_target.length() > 0) {
            this->is_cracker_running = true;
            if (use_sha_mode == ViperCipher::SHA_BLOCK_SIZE::SHA256) {
              result.clear();
              StringSource(list_target, true, new HashFilter(this->ShaMode.s256, new HexEncoder(new StringSink(result))));
              if (block_match() == true) {
                gMutex.try_lock();
                this->CrackRegister.push_back({list_target, result});
                gMutex.unlock();
              }
              std::this_thread::sleep_for(std::chrono::microseconds(crack_speed_ms));
            }
          }
        }
        this->is_cracker_running = false;
      }
    };

    std::thread t(cb);
    t.detach();
  } catch (...) {
    std::cout << "Error: Detached Cipher Attack Failure!" << std::endl;
  }
  return *this;
};

/**
 * Wait Cipher Attacker to complete before exiting.
 * @param void
 * @returns void
 */
void ViperCipher::Viper::ThreadWait(void) noexcept {

  try {
    std::thread observer([&]() {
      std::this_thread::sleep_for(std::chrono::seconds(6));
      while (this->is_cracker_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
      }
    });
    if (observer.joinable())
      observer.join();

  } catch (...) {
    std::cerr << "Error: ThreadWait Call" << std::endl;
  }
};

ViperCipher::Viper::~Viper() {
  if (!this->Blocks.decrypted.empty())
    this->Blocks.decrypted.clear();

  if (!this->Blocks.encrypted.empty())
    this->Blocks.encrypted.clear();

  if (!this->Blocks.hashed.empty())
    this->Blocks.encrypted.clear();

  if (!this->Blocks.plain.empty())
    this->Blocks.plain.clear();

  if (!this->Blocks.private_key_pem.empty())
    this->Blocks.private_key_pem.clear();

  if (!this->Blocks.public_key_pem.empty())
    this->Blocks.public_key_pem.clear();

  this->cipher_crack_entries = 0;
  if (!this->crack_deck.empty()) {
    try {
      for (size_t __c = 0; __c < this->crack_deck.size(); ++__c) {
        if (!this->crack_deck[__c].empty()) {
          this->crack_deck[__c].clear();
          memset((void *)this->crack_deck[__c].data(), 0, sizeof(std::string));
        }
      }
      this->crack_deck.clear();

      if (!this->CrackRegister.empty()) {
        for (size_t __c = 0; __c < this->CrackRegister.size(); ++__c) {
          if (!this->CrackRegister[__c].hash.empty()) {
            this->CrackRegister[__c].hash.clear();
          }
          if (!this->CrackRegister[__c].raw.empty()) {
            this->CrackRegister[__c].raw.clear();
          }
        }
        this->CrackRegister.clear();
      }

    } catch (...) {
      std::cerr << "Some Error Occured while cleaning up memory..." << std::endl;
    }
  }
};
/**
 * Store public/private into KeyFileName file
 * @param std::basic_string_view<char>&
 * @Param const Viper::RSA_KEY_FILE - a flag indicating if the key is public or private
 * @returns const void
 */
const void ViperCipher::Viper::FileCollect(const std::basic_string_view<char> &KeyFileName, const RSA_KEY_FILE Flag) noexcept {
  try {
    FileSink KeyFileSinker(KeyFileName.data());
    if (Flag == ViperCipher::RSA_KEY_FILE::PUBLIC)
      KeyFileSinker.Put(reinterpret_cast<const CryptoPP::byte *>(this->Blocks.public_key_pem.data()), this->Blocks.public_key_pem.size());
    else
      KeyFileSinker.Put(reinterpret_cast<const CryptoPP::byte *>(this->Blocks.private_key_pem.data()), this->Blocks.private_key_pem.size());
  } catch (...) {
    std::cerr << "Error: FileCollect Call" << std::endl;
  };
};

const std::vector<ViperCipher::CrackedCipherStructure> ViperCipher::Viper::get_cracked_block() noexcept {
    if(!this->CrackRegister.empty()){
      return std::as_const(this->CrackRegister);
    }
    return std::vector<ViperCipher::CrackedCipherStructure>{};
};

#endif