#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/replace.hpp>

#include <nlohmann/json.hpp>

#include <base64.h>

#include "json_web_token.h"
#include "msg_auth_code.h"

namespace jwt_verify {
using namespace std;  
using namespace boost;
using namespace nlohmann;
using namespace universals;

string
json_web_token::jwt_base64_decode(const string& jwt_text) {
  string text{replace_all_copy(replace_all_copy(jwt_text, "-", "+"), "_", "/")};
  text.append(4 - (text.length() % 4), '=');
  return base64_decode(text);
}

string
json_web_token::jwt_base64_encode(const string& text) {
  string jwt_text{base64_encode(text)};
  auto rit = jwt_text.crbegin();
  while (rit != jwt_text.crend() && *rit == '=')
	++rit;
  jwt_text.resize(rit - jwt_text.rbegin());
  return replace_all_copy(replace_all_copy(jwt_text, "+", "-"), "/", "_");
}

hash_algorithm
json_web_token::parse_hash_algorithm(const string& text) {
  if (text == "HS256")
    return hash_algorithm::hs256;
  if (text == "HS384")
    return hash_algorithm::hs384;
  if (text == "HS512")
    return hash_algorithm::hs512;
  return hash_algorithm::unknown;
}

void  
json_web_token::check_header_hash_algorithm(const string& header) {
  const json obj = json::parse(header);
   if (!obj.is_object())
	 throw runtime_error{"invalid header JSON"};
  const auto alg_it = obj.find("alg");
  if (alg_it == obj.end())
	throw runtime_error{"invalid header JSON"};
  if (!alg_it->is_string() || parse_hash_algorithm(alg_it->get<string>()) == hash_algorithm::unknown)
    throw runtime_error{"invalid hash algorithm"};
}

json_web_token::json_web_token(const string& token) {
  vector<string> tokens;
  split(tokens, token, is_any_of("."));
  if (tokens.size() != 3 || tokens[0].empty() || tokens[1].empty() || tokens[2].empty())
    throw runtime_error{"malformed token"};
  auto cit = tokens.cbegin();
  header = jwt_base64_decode(*cit++);
  check_header_hash_algorithm(header);
  payload = jwt_base64_decode(*cit++);
  signature = jwt_base64_decode(*cit);
}

hash_algorithm
json_web_token::get_hash_algorithm() const {
  return parse_hash_algorithm(json::parse(header)["alg"].get<string>());
}

bool
json_web_token::verify(const string& secret_key) const {
  msg_auth_code mac{get_hash_algorithm()};
  mac.set_key(secret_key);
  const string text{jwt_base64_encode(header) + '.' + jwt_base64_encode(payload)};
  mac.add_data(reinterpret_cast<const unsigned char*>(text.data()), text.length());
  const vector<unsigned char> mac_hash{mac.result()};
  return signature == string{reinterpret_cast<const char*>(mac_hash.data()), mac_hash.size()};
}
}
