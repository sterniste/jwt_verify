#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/evp.h>

#include "msg_auth_code.h"

namespace jwt_verify {
using namespace std;

cryptographic_hash::evp_type
cryptographic_hash::hash_algorithm_evp_type(hash_algorithm alg) {
  switch (alg) {
  case hash_algorithm::hs256:
    return EVP_sha256;
  case hash_algorithm::hs384:
    return EVP_sha384;
  case hash_algorithm::hs512:
    return EVP_sha512;
  default:
    return nullptr;
  }
}

void
cryptographic_hash::init(hash_algorithm alg, EVP_MD_CTX* evp_ctx) {
  if (!evp_ctx || !EVP_DigestInit_ex(evp_ctx, hash_algorithm_evp_type(alg)(), nullptr))
    throw runtime_error{"can't init EVP digest"};
}

cryptographic_hash::~cryptographic_hash() {
  if (evp_ctx)
    EVP_MD_CTX_free(evp_ctx);
}

cryptographic_hash::cryptographic_hash(hash_algorithm alg) : alg{alg}, evp_ctx{EVP_MD_CTX_new()} {
  init(alg, evp_ctx);
}

void
cryptographic_hash::add_data(const unsigned char* data, unsigned int len) {
  if (!evp_ctx || !EVP_DigestUpdate(evp_ctx, data, len))
    throw runtime_error{"can't update EVP digest"};
  memset(hash_buf.data(), 0, EVP_MAX_MD_SIZE);
}

void
cryptographic_hash::reset() {
  init(alg, evp_ctx);
  memset(hash_buf.data(), 0, EVP_MAX_MD_SIZE);
}

vector<unsigned char>
cryptographic_hash::result() {
  unsigned int hash_len{};
  if (!evp_ctx || !EVP_DigestFinal_ex(evp_ctx, hash_buf.data(), &hash_len))
    throw runtime_error{"can't finalize EVP digest"};
  return vector<unsigned char>(hash_buf.cbegin(), hash_buf.cbegin() + hash_len);
}

unsigned int
msg_auth_code::hash_block_size(hash_algorithm alg) {
  switch (alg) {
  case hash_algorithm::hs256: return 64;
  case hash_algorithm::hs384: return 128;
  case hash_algorithm::hs512: return 128;
  default: return 0;
  }
}

vector<unsigned char>
msg_auth_code::hash_key(bool init) {
  const unsigned char mask = init ? 0x36 : 0x5c;
  vector<unsigned char> padded_key(hash_block_size(alg));
  auto msg_key_cit = msg_key.cbegin();
  for (auto& padded_key_uc : padded_key)
    padded_key_uc = (*msg_key_cit++ ^ mask);
  return padded_key;
}

void
msg_auth_code::init_msg_hash() {
  if (msg_hash_init)
    return;
  const unsigned int block_size = hash_block_size(alg);
  if (msg_key.size() > block_size) {
    cryptographic_hash hash{alg};
    hash.add_data(msg_key.data(), msg_key.size());
    msg_key = hash.result();
    hash.reset();
  }
  if (msg_key.size() < block_size) {
    const unsigned int key_size = msg_key.size();
    msg_key.resize(block_size);
    memset(msg_key.data() + key_size, 0, block_size - key_size);
  }
  const vector<unsigned char> key_hash{hash_key(true)};
  msg_hash.add_data(key_hash.data(), key_hash.size());
  msg_hash_init = true;
}

msg_auth_code::msg_auth_code(hash_algorithm alg) : alg{alg}, msg_hash{alg}, msg_hash_init{} {}

void
msg_auth_code::reset_data() {
  msg_result.clear();
  msg_hash.reset();
  msg_hash_init = false;
}

void
msg_auth_code::set_key(const std::string& secret_key) {
  reset_data();
  msg_key.resize(secret_key.size());
  memcpy(msg_key.data(), secret_key.data(), secret_key.size());
}

void
msg_auth_code::add_data(const unsigned char* data, unsigned int len) {
  init_msg_hash();
  msg_hash.add_data(data, len);
}

std::vector<unsigned char>
msg_auth_code::result() {
  if (!msg_result.empty())
    return msg_result;
  init_msg_hash();
  const vector<unsigned char> key_hash{hash_key(false)};
  cryptographic_hash hash{alg};
  hash.add_data(key_hash.data(), key_hash.size());
  const vector<unsigned char> msg_hash{this->msg_hash.result()};
  hash.add_data(msg_hash.data(), msg_hash.size());
  return msg_result = hash.result();
}
}
