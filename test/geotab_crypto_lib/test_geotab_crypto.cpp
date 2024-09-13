#include <gtest/gtest.h>

#include <cstring>

#include "geotab_crypto.h"
#include "geotab_crypto_errors.h"

TEST(GEOTAB_CRYPTO, test_decrypt) {
  struct crypt_context context;
  uint8_t key[] = {0xc1, 0xab, 0xe5, 0xec, 0x1e, 0x7a};
  context.key = key;
  context.lengthKey = sizeof(key);

  const std::string original_msg = "Decoding seems to be correct.\n";
  uint8_t code[] = {0x85, 0xc9, 0x84, 0x80, 0x46, 0x16, 0xaf, 0xca, 0xc9, 0x81,
                    0x43, 0xe1, 0xac, 0xdd, 0xcb, 0x81, 0x45, 0xa9, 0xa3, 0xca,
                    0xcd, 0x9b, 0x41, 0xfc, 0xb3, 0xd5, 0x8c, 0x8f, 0x1c, 0x99};
  uint8_t decode[sizeof(code)];

  const auto ret = crypt_buffer(&context, decode, code, sizeof(code));
  ASSERT_EQ(ret, GEOTAB_CRYPTO_SUCCESS) << "Error decrypting";

  std::cout << "Decrypted message: ";
  fwrite(decode, 1, sizeof(code), stdout);
  fflush(stdout);
  std::cout << std::endl;

  ASSERT_STREQ(original_msg.c_str(), reinterpret_cast<char*>(decode));
}

TEST(GEOTAB_CRYPTO, test_decrypt_encrypt_code1) {
  struct crypt_context context;
  uint8_t key[] = {0xc1, 0xab, 0xe5, 0xec, 0x1e, 0x7a};
  context.key = key;
  context.lengthKey = sizeof(key);

  uint8_t code[] = {0x85, 0xc9, 0x84, 0x80, 0x46, 0x16, 0xaf, 0xca, 0xc9, 0x81,
                    0x43, 0xe1, 0xac, 0xdd, 0xcb, 0x81, 0x45, 0xa9, 0xa3, 0xca,
                    0xcd, 0x9b, 0x41, 0xfc, 0xb3, 0xd5, 0x8c, 0x8f, 0x1c, 0x99};
  uint8_t decode[sizeof(code)];
  uint8_t reencode[sizeof(code)];

  auto ret = crypt_buffer(&context, decode, code, sizeof(code));
  ASSERT_EQ(ret, GEOTAB_CRYPTO_SUCCESS) << "Error decrypting";
  ret = crypt_buffer(&context, reencode, decode, sizeof(decode));
  ASSERT_EQ(ret, GEOTAB_CRYPTO_SUCCESS) << "Error reencrypting";

  ASSERT_EQ(memcmp(code, reencode, sizeof(code)), 0)
      << "The decrypted data is not equal to the original";
}

TEST(GEOTAB_CRYPTO, test_decrypt_encrypt_code2) {
  struct crypt_context context;
  uint8_t key[] = {0xc1, 0xab, 0xe5, 0xec, 0x1e, 0x7a};
  context.key = key;
  context.lengthKey = sizeof(key);

  uint8_t code[] = {0x92, 0xc5, 0x90, 0x8a, 0x43, 0xeb, 0xe1, 0xc1, 0x9b, 0x6e,
                    0x4f, 0xf1, 0xa5, 0x93, 0x97, 0x61, 0x1e, 0xc9, 0xa4, 0xc4,
                    0x83, 0x2b, 0x62, 0xd4, 0xae, 0x95, 0x9d, 0x63, 0x20, 0xca,
                    0xa4, 0xc4, 0x9e, 0x63, 0x3e, 0x91, 0xa2, 0xd8, 0x99, 0x75,
                    0x6e, 0xdb, 0xa8, 0xdf, 0x97, 0x67, 0x72, 0xc2, 0xa8, 0xdc,
                    0x6d, 0x72, 0x76, 0xb3, 0xa0, 0xd7, 0x66, 0x39, 0x3e, 0xa0,
                    0xa2, 0xd4, 0x61, 0x79, 0x3a, 0xea, 0xb2, 0xc8, 0x75, 0x76,
                    0x0c, 0xa8, 0xef, 0xb7};
  uint8_t decode[sizeof(code)];
  uint8_t reencode[sizeof(code)];

  auto ret = crypt_buffer(&context, decode, code, sizeof(code));
  ASSERT_EQ(ret, GEOTAB_CRYPTO_SUCCESS) << "Error decrypting";
  ret = crypt_buffer(&context, reencode, decode, sizeof(decode));
  ASSERT_EQ(ret, GEOTAB_CRYPTO_SUCCESS) << "Error reencrypting";

  ASSERT_EQ(memcmp(code, reencode, sizeof(code)), 0)
      << "The decrypted data is not equal to the original";
}

TEST(GEOTAB_CRYPTO, test_decrypt_encrypt_code3) {
  struct crypt_context context;
  uint8_t key[] = {0xc1, 0xab, 0xe5, 0xec, 0x1e, 0x7a};
  context.key = key;
  context.lengthKey = sizeof(key);

  const std::string original_msg = "Decoding seems to be correct.\n";
  uint8_t code[] = {0x5a, 0x56, 0x07, 0xa0, 0xb4, 0xcd, 0x2b, 0x56, 0x02, 0xb6,
                    0xb4, 0xd3, 0x69, 0x08, 0x0c, 0xbb, 0xe1, 0xab, 0x6a, 0x5b,
                    0x06, 0xcf, 0xe1, 0xb2, 0x7e, 0x0e, 0x12, 0x81, 0xa7, 0xa4,
                    0x76, 0x43, 0x1f, 0x83, 0xb5, 0xe3, 0x76, 0x5b, 0x1a, 0x97,
                    0xe1, 0xa9, 0x7e, 0x50, 0xea, 0x83, 0xe1, 0xbc, 0x70, 0x5f,
                    0xea, 0x98, 0xe1, 0xb5, 0x7a, 0x50, 0xef, 0x21, 0xa5, 0xa2,
                    0x7e, 0x2f, 0xea, 0x63, 0xa5, 0xe8, 0x6c, 0x37, 0xe0, 0x62,
                    0xaf, 0xae, 0x0f, 0x4c};
  uint8_t decode[sizeof(code)];
  uint8_t reencode[sizeof(code)];

  auto ret = crypt_buffer(&context, decode, code, sizeof(code));
  ASSERT_EQ(ret, GEOTAB_CRYPTO_SUCCESS) << "Error decrypting";
  ret = crypt_buffer(&context, reencode, decode, sizeof(decode));
  ASSERT_EQ(ret, GEOTAB_CRYPTO_SUCCESS) << "Error reencrypting";

  ASSERT_EQ(memcmp(code, reencode, sizeof(code)), 0)
      << "The decrypted data is not equal to the original";
}

TEST(GEOTAB_CRYPTO, test_decrypt_encrypt_code4) {
  struct crypt_context context;
  uint8_t key[] = {0xc1, 0xab, 0xe5, 0xec, 0x1e, 0x7a};
  context.key = key;
  context.lengthKey = sizeof(key);

  const std::string original_msg = "Decoding seems to be correct.\n";
  uint8_t code[] = {0xd7};
  uint8_t decode[sizeof(code)];
  uint8_t reencode[sizeof(code)];

  auto ret = crypt_buffer(&context, decode, code, sizeof(code));
  ASSERT_EQ(ret, GEOTAB_CRYPTO_SUCCESS) << "Error decrypting";
  ret = crypt_buffer(&context, reencode, decode, sizeof(decode));
  ASSERT_EQ(ret, GEOTAB_CRYPTO_SUCCESS) << "Error reencrypting";

  ASSERT_EQ(memcmp(code, reencode, sizeof(code)), 0)
      << "The decrypted data is not equal to the original";
}

TEST(GEOTAB_CRYPTO, test_decrypt_encrypt_code5) {
  struct crypt_context context;
  uint8_t key[] = {0xc1, 0xab, 0xe5, 0xec, 0x1e, 0x7a};
  context.key = key;
  context.lengthKey = sizeof(key);

  const std::string original_msg = "Decoding seems to be correct.\n";
  uint8_t code[] = {0x1a, 0x8c, 0xbf, 0x50, 0x3d, 0xba, 0x62, 0xae, 0xb9,
                    0x4e, 0x6c, 0xf8, 0x75, 0xb3, 0xec, 0x54, 0x26, 0xcc,
                    0x78, 0xad, 0xa8, 0x09, 0x31, 0xce, 0x45, 0xb3, 0xaf,
                    0x48, 0x21, 0xcf, 0x5b, 0xb2, 0xef, 0x4c, 0x2b, 0x8e,
                    0x59, 0xa4, 0xbc, 0x43, 0x75, 0xb8};
  uint8_t decode[sizeof(code)];
  uint8_t reencode[sizeof(code)];

  auto ret = crypt_buffer(&context, decode, code, sizeof(code));
  ASSERT_EQ(ret, GEOTAB_CRYPTO_SUCCESS) << "Error decrypting";
  ret = crypt_buffer(&context, reencode, decode, sizeof(decode));
  ASSERT_EQ(ret, GEOTAB_CRYPTO_SUCCESS) << "Error reencrypting";

  ASSERT_EQ(memcmp(code, reencode, sizeof(code)), 0)
      << "The decrypted data is not equal to the original";
}

TEST(GEOTAB_CRYPTO, test_encrypt_decrypt) {
  struct crypt_context context;
  uint8_t key[] = {0xc1, 0xab, 0xe5, 0xec, 0x1e, 0x7a};
  context.key = key;
  context.lengthKey = sizeof(key);

  const std::string input_msg = "This is a test to check the crypt library";

  std::unique_ptr<uint8_t> input(new uint8_t[input_msg.length() + 1]);
  std::unique_ptr<uint8_t> encrypt(new uint8_t[input_msg.length() + 1]);
  std::unique_ptr<uint8_t> output(new uint8_t[input_msg.length() + 1]);

  memcpy(input.get(), input_msg.c_str(), input_msg.length() + 1);

  auto ret = crypt_buffer(&context, encrypt.get(), input.get(),
                          input_msg.length() + 1);
  ASSERT_EQ(ret, GEOTAB_CRYPTO_SUCCESS) << "Error encrypting";
  crypt_buffer(&context, output.get(), encrypt.get(), input_msg.length() + 1);
  ASSERT_EQ(ret, GEOTAB_CRYPTO_SUCCESS) << "Error decrypting";

  ASSERT_EQ(memcmp(input.get(), output.get(), input_msg.length() + 1), 0)
      << "The decrypted data is not equal to the original";
}

TEST(GEOTAB_CRYPTO, test_get_library_version) {
  const auto version = crypt_get_library_version();
  ASSERT_STREQ(version, GEOTAB_CRYPTO_VERSION)
      << "Version not the one expected";
}

TEST(GEOTAB_CRYPTO, test_encrypt_decrypt_empty_string) {
  struct crypt_context context;
  uint8_t key[] = {0xc1, 0xab, 0xe5, 0xec, 0x1e, 0x7a};
  context.key = key;
  context.lengthKey = sizeof(key);

  const std::string input_msg = "";

  std::unique_ptr<uint8_t> input(new uint8_t[input_msg.length() + 1]);
  std::unique_ptr<uint8_t> encrypt(new uint8_t[input_msg.length() + 1]);
  std::unique_ptr<uint8_t> output(new uint8_t[input_msg.length() + 1]);

  memcpy(input.get(), input_msg.c_str(), input_msg.length() + 1);

  auto ret = crypt_buffer(&context, encrypt.get(), input.get(),
                          input_msg.length() + 1);
  ASSERT_EQ(ret, GEOTAB_CRYPTO_SUCCESS) << "Error encrypting";
  crypt_buffer(&context, output.get(), encrypt.get(), input_msg.length() + 1);
  ASSERT_EQ(ret, GEOTAB_CRYPTO_SUCCESS) << "Error decrypting";

  ASSERT_EQ(memcmp(input.get(), output.get(), input_msg.length() + 1), 0)
      << "The decrypted data is not equal to the original";
}

TEST(GEOTAB_CRYPTO, test_encrypt_decrypt_special_characters) {
  struct crypt_context context;
  uint8_t key[] = {0xc1, 0xab, 0xe5, 0xec, 0x1e, 0x7a};
  context.key = key;
  context.lengthKey = sizeof(key);

  const std::string input_msg = "!@#$%^&*()_+-=[]{}|;':\",./<>?";

  std::unique_ptr<uint8_t> input(new uint8_t[input_msg.length() + 1]);
  std::unique_ptr<uint8_t> encrypt(new uint8_t[input_msg.length() + 1]);
  std::unique_ptr<uint8_t> output(new uint8_t[input_msg.length() + 1]);

  memcpy(input.get(), input_msg.c_str(), input_msg.length() + 1);

  auto ret = crypt_buffer(&context, encrypt.get(), input.get(),
                          input_msg.length() + 1);
  ASSERT_EQ(ret, GEOTAB_CRYPTO_SUCCESS) << "Error encrypting";
  crypt_buffer(&context, output.get(), encrypt.get(), input_msg.length() + 1);
  ASSERT_EQ(ret, GEOTAB_CRYPTO_SUCCESS) << "Error decrypting";

  ASSERT_EQ(memcmp(input.get(), output.get(), input_msg.length() + 1), 0)
      << "The decrypted data is not equal to the original";
}

TEST(GEOTAB_CRYPTO, test_encrypt_decrypt_long_string) {
  struct crypt_context context;
  uint8_t key[] = {0xc1, 0xab, 0xe5, 0xec, 0x1e, 0x7a};
  context.key = key;
  context.lengthKey = sizeof(key);

  const std::string input_msg(1000, 'A');  // Long string of 1000 'A' characters

  std::unique_ptr<uint8_t> input(new uint8_t[input_msg.length() + 1]);
  std::unique_ptr<uint8_t> encrypt(new uint8_t[input_msg.length() + 1]);
  std::unique_ptr<uint8_t> output(new uint8_t[input_msg.length() + 1]);

  memcpy(input.get(), input_msg.c_str(), input_msg.length() + 1);

  auto ret = crypt_buffer(&context, encrypt.get(), input.get(),
                          input_msg.length() + 1);
  ASSERT_EQ(ret, GEOTAB_CRYPTO_SUCCESS) << "Error encrypting";
  crypt_buffer(&context, output.get(), encrypt.get(), input_msg.length() + 1);
  ASSERT_EQ(ret, GEOTAB_CRYPTO_SUCCESS) << "Error decrypting";

  ASSERT_EQ(memcmp(input.get(), output.get(), input_msg.length() + 1), 0)
      << "The decrypted data is not equal to the original";
}

TEST(GEOTAB_CRYPTO, test_encrypt_decrypt_null_terminator) {
  struct crypt_context context;
  uint8_t key[] = {0xc1, 0xab, 0xe5, 0xec, 0x1e, 0x7a};
  context.key = key;
  context.lengthKey = sizeof(key);

  const std::string input_msg = "Test\0StringWithNull",
                    expected_msg = "Test\0StringWithNull";

  std::unique_ptr<uint8_t> input(new uint8_t[input_msg.length() + 1]);
  std::unique_ptr<uint8_t> encrypt(new uint8_t[input_msg.length() + 1]);
  std::unique_ptr<uint8_t> output(new uint8_t[input_msg.length() + 1]);

  memcpy(input.get(), input_msg.c_str(), input_msg.length() + 1);

  auto ret = crypt_buffer(&context, encrypt.get(), input.get(),
                          input_msg.length() + 1);
  ASSERT_EQ(ret, GEOTAB_CRYPTO_SUCCESS) << "Error encrypting";
  crypt_buffer(&context, output.get(), encrypt.get(), input_msg.length() + 1);
  ASSERT_EQ(ret, GEOTAB_CRYPTO_SUCCESS) << "Error decrypting";

  ASSERT_EQ(memcmp(input.get(), output.get(), input_msg.length() + 1), 0)
      << "The decrypted data is not equal to the original";
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

TEST(GEOTAB_CRYPTO, test_buffer_zero_length) {
  struct crypt_context context;
  uint8_t key[] = {0xc1, 0xab, 0xe5, 0xec, 0x1e, 0x7a};
  context.key = key;
  context.lengthKey = sizeof(key);

  uint8_t input[] = {0x01, 0x02, 0x03};
  uint8_t output[sizeof(input)];

  auto ret = crypt_buffer(&context, output, input, 0);
  ASSERT_EQ(ret, GEOTAB_CRYPTO_ERROR_INVALID_ARGS)
      << "Expected error when length in crypt_buffer is zero";
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
