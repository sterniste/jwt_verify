#include <string>

#include <boost/algorithm/string.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>

#include "base64.h"

namespace universals {
using namespace std;
using namespace boost::algorithm;
using namespace boost::archive::iterators;

string
base64_decode(const string& s) {
  using It = transform_width<binary_from_base64<string::const_iterator>, 8, 6>;
  return trim_right_copy_if(string(It(begin(s)), It(end(s))), [](char c) { return c == '\0'; });
}

string
base64_encode(const string& s) {
  using It = base64_from_binary<transform_width<string::const_iterator, 6, 8>>;
  auto tmp = string{It(begin(s)), It(end(s))};
  return tmp.append((3 - s.size() % 3) % 3, '=');
}
}
