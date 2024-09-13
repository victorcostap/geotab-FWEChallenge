#include <gtest/gtest.h>
#include <iostream>

#include "geotab_crypto.h"

TEST(GEOTAB_CRYPTO, test_get_library_version){
    const auto version = crypto_get_library_version();
    ASSERT_STREQ(version, GEOTAB_CRYPTO_VERSION) << "Version not the one expected";
}