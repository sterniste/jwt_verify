#ifndef JSON_WEB_TOKEN_H
#define JSON_WEB_TOKEN_H

#include <string>

#include <nlohmann/json.hpp>

#include "msg_auth_code.h"

namespace jwt_verify {

class json_web_token {
  std::string header;
  std::string payload;
  std::string signature;

  static std::string jwt_base64_decode(const std::string& text);
  static std::string jwt_base64_encode(const std::string& text);
  static void check_header_hash_algorithm(const std::string& header);
  static hash_algorithm parse_hash_algorithm(const std::string& text);

 public:
  json_web_token(const std::string& token);

  hash_algorithm get_hash_algorithm() const;
  nlohmann::json get_header() const { return nlohmann::json::parse(header); }
  nlohmann::json get_payload() const { return nlohmann::json::parse(payload); }
  std::string get_signature() const { return signature; }

  bool verify(const std::string& secret_key) const;
};
}
#endif
