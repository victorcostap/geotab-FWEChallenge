#include <gtest/gtest.h>

#include <cstring>
#include <map>

#include "geotab_crypto.h"
#include "geotab_crypto_errors.h"

TEST(GEOTAB_CRYPTO, test_decrypt) {
  struct crypt_context context;
  uint8_t key[] = {0xc1, 0xab, 0xe5, 0xec, 0x1e, 0x7a};
  context.key = key;
  context.lengthKey = sizeof(key);
  context.index = 0;
  
  struct codeResult {
    std::vector<std::uint8_t> code;
    std::string result;

    codeResult(const std::vector<std::uint8_t> &code, const std::string &result)
    :code(code), result(result) {}
  };

  std::map<int, codeResult> map_codes;

  map_codes.emplace(1, codeResult({0x85, 0xc9, 0x84, 0x80, 0x46, 0x16, 0xaf, 0xca, 0xc9, 0x81,
                                  0x43, 0xe1, 0xac, 0xdd, 0xcb, 0x81, 0x45, 0xa9, 0xa3, 0xca,
                                  0xcd, 0x9b, 0x41, 0xfc, 0xb3, 0xd5, 0x8c, 0x8f, 0x1c, 0x99},
                                  "Decoding seems to be correct.\n"));
  map_codes.emplace(2, codeResult({0x92, 0xc5, 0x90, 0x8a, 0x43, 0xeb, 0xe1, 0xc1, 0x9b, 0x6e,
                                  0x4f, 0xf1, 0xa5, 0x93, 0x97, 0x61, 0x1e, 0xc9, 0xa4, 0xc4,
                                  0x83, 0x2b, 0x62, 0xd4, 0xae, 0x95, 0x9d, 0x63, 0x20, 0xca,
                                  0xa4, 0xc4, 0x9e, 0x63, 0x3e, 0x91, 0xa2, 0xd8, 0x99, 0x75,
                                  0x6e, 0xdb, 0xa8, 0xdf, 0x97, 0x67, 0x72, 0xc2, 0xa8, 0xdc,
                                  0x6d, 0x72, 0x76, 0xb3, 0xa0, 0xd7, 0x66, 0x39, 0x3e, 0xa0,
                                  0xa2, 0xd4, 0x61, 0x79, 0x3a, 0xea, 0xb2, 0xc8, 0x75, 0x76,
                                  0x0c, 0xa8, 0xef, 0xb7},
                                  "Status should be kept, so different code might yield same decoded string.\n"));
  map_codes.emplace(3, codeResult({0x5a, 0x56, 0x07, 0xa0, 0xb4, 0xcd, 0x2b, 0x56, 0x02, 0xb6,
                                  0xb4, 0xd3, 0x69, 0x08, 0x0c, 0xbb, 0xe1, 0xab, 0x6a, 0x5b,
                                  0x06, 0xcf, 0xe1, 0xb2, 0x7e, 0x0e, 0x12, 0x81, 0xa7, 0xa4,
                                  0x76, 0x43, 0x1f, 0x83, 0xb5, 0xe3, 0x76, 0x5b, 0x1a, 0x97,
                                  0xe1, 0xa9, 0x7e, 0x50, 0xea, 0x83, 0xe1, 0xbc, 0x70, 0x5f,
                                  0xea, 0x98, 0xe1, 0xb5, 0x7a, 0x50, 0xef, 0x21, 0xa5, 0xa2,
                                  0x7e, 0x2f, 0xea, 0x63, 0xa5, 0xe8, 0x6c, 0x37, 0xe0, 0x62,
                                  0xaf, 0xae, 0x0f, 0x4c},
                                  "Status should be kept, so different code might yield same decoded string.\n"));
  map_codes.emplace(4, codeResult({0xd7},
                                  "A"));
  map_codes.emplace(5, codeResult({0x1a, 0x8c, 0xbf, 0x50, 0x3d, 0xba, 0x62, 0xae, 0xb9,
                                  0x4e, 0x6c, 0xf8, 0x75, 0xb3, 0xec, 0x54, 0x26, 0xcc,
                                  0x78, 0xad, 0xa8, 0x09, 0x31, 0xce, 0x45, 0xb3, 0xaf,
                                  0x48, 0x21, 0xcf, 0x5b, 0xb2, 0xef, 0x4c, 0x2b, 0x8e,
                                  0x59, 0xa4, 0xbc, 0x43, 0x75, 0xb8},
                                  "\nMust work for single characters as well.\n"));

  uint8_t buffer[1024];

  int ret;
  size_t lengthCode;
  int codeNumber;
  for(const auto& codeTest : map_codes) {
    codeNumber = codeTest.first;
    lengthCode = codeTest.second.code.size();
    ret = crypt_buffer(&context, buffer, codeTest.second.code.data(), lengthCode);
    EXPECT_EQ(ret, GEOTAB_CRYPTO_SUCCESS) << "Error decrypting code" << codeNumber;

    fwrite(buffer, 1, lengthCode, stdout);
    fflush(stdout);

    EXPECT_EQ(codeTest.second.result, std::string(reinterpret_cast<char*>(buffer), lengthCode));
  }
}

TEST(GEOTAB_CRYPTO, test_get_library_version) {
  const auto version = crypt_get_library_version();
  ASSERT_STREQ(version, GEOTAB_CRYPTO_VERSION)
      << "Version not the one expected";
}

TEST(GEOTAB_CRYPTO, test_encrypt_zero_length) {
  struct crypt_context context;
  uint8_t key[] = {0xc1, 0xab, 0xe5, 0xec, 0x1e, 0x7a};
  context.key = key;
  context.lengthKey = sizeof(key);
  context.index = 0;

  std::unique_ptr<uint8_t> input(new uint8_t[0]);
  std::unique_ptr<uint8_t> encrypt(new uint8_t[0]);
  std::unique_ptr<uint8_t> output(new uint8_t[0]);

  auto ret = crypt_buffer(&context, encrypt.get(), input.get(), 0);
  ASSERT_EQ(ret, GEOTAB_CRYPTO_SUCCESS) << "Error encrypting 0 length value";
}

TEST(GEOTAB_CRYPTO, test_buffer_null_context) {
  uint8_t input[] = {0x01, 0x02, 0x03};
  uint8_t output[sizeof(input)];

  auto ret = crypt_buffer(nullptr, output, input, sizeof(input));
  ASSERT_EQ(ret, GEOTAB_CRYPTO_ERROR_INVALID_ARGS)
      << "Expected error when context is null";
}

TEST(GEOTAB_CRYPTO, test_buffer_null_input) {
  struct crypt_context context;
  uint8_t key[] = {0xc1, 0xab, 0xe5, 0xec, 0x1e, 0x7a};
  context.key = key;
  context.lengthKey = sizeof(key);

  uint8_t output[10];

  auto ret = crypt_buffer(&context, output, nullptr, 10);
  ASSERT_EQ(ret, GEOTAB_CRYPTO_ERROR_INVALID_ARGS)
      << "Expected error when input is null";
}

TEST(GEOTAB_CRYPTO, test_buffer_null_output) {
  struct crypt_context context;
  uint8_t key[] = {0xc1, 0xab, 0xe5, 0xec, 0x1e, 0x7a};
  context.key = key;
  context.lengthKey = sizeof(key);

  uint8_t input[] = {0x01, 0x02, 0x03};

  auto ret = crypt_buffer(&context, nullptr, input, sizeof(input));
  ASSERT_EQ(ret, GEOTAB_CRYPTO_ERROR_INVALID_ARGS)
      << "Expected error when output is null";
}

TEST(GEOTAB_CRYPTO, test_buffer_invalid_key) {
  struct crypt_context context;
  uint8_t key[] = {};
  context.key = key;
  context.lengthKey = sizeof(key);  // lengthKey is 0

  uint8_t input[] = {0x01, 0x02, 0x03};
  uint8_t output[sizeof(input)];

  auto ret = crypt_buffer(&context, output, input, sizeof(input));
  ASSERT_EQ(ret, GEOTAB_CRYPTO_ERROR_INVALID_ARGS)
      << "Expected error when key length is zero";
}
