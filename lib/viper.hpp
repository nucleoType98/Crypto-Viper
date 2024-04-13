#pragma once

#ifndef _GLOBAL_HEADER_
#include "header.hpp"
#endif


using namespace CryptoPP;

#ifndef _GLOBAL_VIPER_

#define _GLOBAL_VIPER_ 1

namespace ViperCipher {

std::mutex gMutex;


/*                                        MACROS                                             \
\********************************************************************************************/

#define __BUFFER_MAX_SIZE__ (unsigned int)4096u

/*                                      STRUCTURES                                           \
\********************************************************************************************/

typedef struct alignas(void *) {
  std::basic_string<char> plain;
  std::basic_string<char> hashed;
  std::basic_string<char> encrypted;
  std::basic_string<char> decrypted;
  std::basic_string<char> public_key_pem;
  std::basic_string<char> private_key_pem;
} BlockStructure;

typedef struct alignas(void *) {
  std::string raw;
  std::string hash;
} CrackedCipherStructure;

typedef struct alignas(void *) {
  SHA1 s1;
  SHA224 s224;
  SHA256 s256;
  SHA384 s384;
  SHA512 s512;
} ShaModeStructure;



/*                                      ENUMERATIONS                                         \
\********************************************************************************************/

enum class RSA_KEY_FLAG : unsigned short int { FILE_COLLECTOR = 0, SCRIPT_COLLECTOR, DEFAULT };

enum class RSA_KEY_FILE : unsigned short int { PUBLIC = 0, PRIVATE = 1 };

enum class SHA_BLOCK_SIZE : unsigned short int { SHA1 = 1, SHA224 = 224, SHA256 = 256, SHA384 = 384, SHA512 = 512 };

enum class CIPHER_ATTACK_ALGO_MODE : unsigned short int { INFER = 0, ENFORCE, SMART, DEFAULT };


/*                                          Class                                          \
\******************************************************************************************/

class Viper {


/*                                      PRIVATE REGION                                       \
\********************************************************************************************/
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

  const void FileCollect(const std::basic_string_view<char> &KeyFileName, const RSA_KEY_FILE Flag) noexcept;


/*                                      PUBLIC REGION                                        \
\********************************************************************************************/
public:
  Viper();

  const std::basic_string_view<char> Hash(const std::string &target, const SHA_BLOCK_SIZE ShaSize) noexcept;

  const std::basic_string_view<char> Encrypt(const std::string &target) noexcept;

  const std::basic_string_view<char> Decrypt(const std::basic_string_view<char> &target) noexcept;

  ViperCipher::Viper &GenRsaPublicKey(const std::basic_string_view<char> &KeyFileName, const ViperCipher::RSA_KEY_FLAG &Flag) noexcept;

  ViperCipher::Viper &GenRsaPrivateKey(const std::basic_string_view<char> &KeyFileName, const ViperCipher::RSA_KEY_FLAG &Flag) noexcept;

  const std::string getPublicKey(void) noexcept;

  const std::string getPrivateKey(void) noexcept;

  void RevokeKeyIv(void) noexcept;

  ViperCipher::Viper &CipherAttack(const std::initializer_list<std::basic_string<char>> &cipher_target_list, const std::basic_string_view<char> &target_file, const SHA_BLOCK_SIZE use_sha_mode, const CIPHER_ATTACK_ALGO_MODE algo_cipher_mode, const unsigned long int crack_speed_ms) noexcept;

  ViperCipher::Viper &CipherAttackDetached(const std::initializer_list<std::basic_string<char>> &cipher_target_list, const std::basic_string_view<char> &target_file, const SHA_BLOCK_SIZE use_sha_mode, const CIPHER_ATTACK_ALGO_MODE algo_cipher_mode, const unsigned long int crack_speed_ms) noexcept;

  void ThreadWait(void) noexcept;

  ~Viper();
};

}; // namespace ViperCipher


#endif