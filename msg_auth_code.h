#ifndef MSG_AUTH_CODE_H
#define MSG_AUTH_CODE_H

#include <array>
#include <string>
#include <vector>

#include <openssl/evp.h>

namespace jwt_verify {

enum class hash_algorithm : uint8_t { unknown = 0, hs256, hs384, hs512 };

class cryptographic_hash {
  hash_algorithm alg;
  EVP_MD_CTX* evp_ctx;
  std::array<unsigned char, EVP_MAX_MD_SIZE> hash_buf;

  typedef const EVP_MD* (*evp_type)();

  static evp_type hash_algorithm_evp_type(hash_algorithm alg);
  static void init(hash_algorithm alg, EVP_MD_CTX* evp_ctx);

 public:
  ~cryptographic_hash();
  cryptographic_hash(hash_algorithm alg);

  void add_data(const unsigned char* data, unsigned int len);
  void reset();
  std::vector<unsigned char> result();
};

class msg_auth_code {
  hash_algorithm alg;
  cryptographic_hash msg_hash;
  bool msg_hash_init;
  std::vector<unsigned char> msg_key, msg_result;

  static unsigned int hash_block_size(hash_algorithm alg);

  std::vector<unsigned char> hash_key(bool init);
  void init_msg_hash();

 public:
  msg_auth_code(hash_algorithm alg);

  void reset_data();
  void set_key(const std::string& secret_key);
  void add_data(const unsigned char* data, unsigned int len);
  std::vector<unsigned char> result();
};
}
#endif
