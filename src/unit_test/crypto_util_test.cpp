#include "common/util/crypto_util.h"

#include "unit_test_define.h"

class CryptoUtilTest : public ::testing::Test {
protected:
    void SetUp() override {
        CryptoUtil::InitOpenssl();
    }

protected:
    const std::string public_key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw8UabiiHWEN5UR5SByS28CVCiVUlTkWRCEsP35SZs9a1wE7boirj0hpg7wyu6heydIpl94BewzwM3JHe45S/UYveYQo/zr3Jb46vpoJMQPikNyZSORxmjPlozIuAlYW56X3Aere+YkH1uCFeeeqW0BcT4Nvljn3vyJGYlzO3kWCuinZH0whrxStiyb5SJpjlgxz+MVUuBAJCDYARo6WCuCATTud+/97wspBCecs/ltvUQPaGpehChbC24U3VBmLsSCmxjAPLQJIukH6sy6tVoK5jmjNnFsCrWbkd68H6tsm9dGPcUMgNWxeahU/8tSOtX94AaTfU4cp846Yn7dH4JQIDAQAB";
    const std::string private_key = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDDxRpuKIdYQ3lRHlIHJLbwJUKJVSVORZEISw/flJmz1rXATtuiKuPSGmDvDK7qF7J0imX3gF7DPAzckd7jlL9Ri95hCj/Ovclvjq+mgkxA+KQ3JlI5HGaM+WjMi4CVhbnpfcB6t75iQfW4IV556pbQFxPg2+WOfe/IkZiXM7eRYK6KdkfTCGvFK2LJvlImmOWDHP4xVS4EAkINgBGjpYK4IBNO537/3vCykEJ5yz+W29RA9oal6EKFsLbhTdUGYuxIKbGMA8tAki6QfqzLq1WgrmOaM2cWwKtZuR3rwfq2yb10Y9xQyA1bF5qFT/y1I61f3gBpN9Thynzjpift0fglAgMBAAECggEAIVoJ96xl6m6MU3qD5P2nQOBIJpdf5KbLX4tSJ/fr+4xfqGSG3GjMKTYfP3p8rhrdZydQ2cp/2mj3k/gx7bmgombeus+BMVp538yCNi7KiOMTLuYTafFhszCmXvqBLHf8xT+MNBvrjlfIYdclfkWt7cOQumUcBZuE5zmOsmu4IUb4ArjKsEmGDqdsp3fCESzbMWqBinvOmdUy+3VbBTpSjU/PDWCd/OgnTHpwPY7O9T7zSo8grkkWyq79W5kz7PLXdtqt1DNChUjHHv+ANM3T5L127BlHDskyG24AGrDzLmCmNQab4qFtOjPtHdsXsQm8cllgzD4lvP6ThuAG8DK4IQKBgQDnoCY8CLc2kUNyibdaA5N7y4xaY9vm1t6jKf37fOS069GkUNfOb8r+Pxp70UAKzMBWZ4iVlDbEh3FU0jveYutsUUbjEB4qI19/jvUHahKzaE9DCK3HkGvjT3NkQmZ+LslS/CxJtyZl+mN8/Ur6OA7p/l8BuJMVMXY+G7mQRZVtzQKBgQDYXwZX712DP5DTLcoUwOM9mIa8UFIFoZN+lwKLq8c0wbpZ3uicU90YwCPVvuATp/fwjOgOEId8HkLeBXkbqkJRimI0y4bTPzHNk0JDlTso79ERcglA9wU4j3C6OArB0Id/u2cVSex/JW3arQt2jRk5JCSDtWn7k1cB9qPvckUbuQKBgA3nYSQtacIOyjuv5J+0oz/FIjGy2Npsf4TP2n0kLB5oIXd5mtq7fzXv18ki8HM1gz4sjNhdw0Pc1YK/8/QPgA5KerTanNTutqbTkAXX6jN2yXs+pB/cnX1RoZ2dFsXwTQl8NbRfGCD6/Mnd8og+oTaOnGlgCQQ2qeBkjakJZETpAoGBAIu/FAHHf8Y9T/SVJmexDRPDZ4JI/jDU4sZoEiTTlZ3lYc6ZwfL1118c+ggbd+46FlEvMNGkq1zmzplHP6k2lg7EKhmfOj1GG4yDB9FOmR8fhRCXbpKe+KhHPK+JcqkrXdiJ2VJOpIiaTBFoona3OwtE5LCMgx8RUqjZ+5ezXh9BAoGBAIz5//GXs1kJoGQatr0rvE4CvVLVbKHaVaXy7MAcp4uya3g1cZh3Swje8e4RD6UfiKmx+aPETfw9IkXbrPTYmXCNDx5bSbbPL+WMY8c7F7K0krOfl8Vtzg5cCfo45+IsLCM16sDT0MhLCPUMWj0kcd4bKcAc3CENaL3U03oLE58r";
    const std::string test_str = R"({"name":"meteor", "version":"1.0.1"})";
};

TEST_F(CryptoUtilTest, RsaSignAndVerify) {
    // Sha1WithRsa
    {
        // sign
        std::string b64_sign;
        ASSERT_TRUE(CryptoUtil::Sha1WithRsaPrivateSign(private_key, test_str, b64_sign));
        ASSERT_FALSE(b64_sign.empty());
        ASSERT_FALSE(CryptoUtil::Sha1WithRsaPrivateSign(private_key, "", b64_sign));
        // verify
        ASSERT_TRUE(CryptoUtil::Sha1WithRsaPublicVerify(public_key, test_str, b64_sign));
        ASSERT_FALSE(CryptoUtil::Sha1WithRsaPublicVerify(public_key, test_str, ""));
        ASSERT_FALSE(CryptoUtil::Sha1WithRsaPublicVerify(public_key, "", ""));
    }

    // Sha256WithRsa
    {
        // sign
        std::string b64_sign;
        ASSERT_TRUE(CryptoUtil::Sha256WithRsaPrivateSign(private_key, test_str, b64_sign));
        ASSERT_FALSE(b64_sign.empty());
        ASSERT_FALSE(CryptoUtil::Sha256WithRsaPrivateSign(private_key, "", b64_sign));

        // verify
        ASSERT_TRUE(CryptoUtil::Sha256WithRsaPublicVerify(public_key, test_str, b64_sign));
        ASSERT_FALSE(CryptoUtil::Sha256WithRsaPublicVerify(public_key, test_str, ""));
        ASSERT_FALSE(CryptoUtil::Sha256WithRsaPublicVerify(public_key, "", ""));
    }
}

TEST_F(CryptoUtilTest, RsaEncryptAndDecrypt) {
    // private encrypt and public decrypt
    {
        std::string b64_encrypted_data;
        ASSERT_TRUE(CryptoUtil::RsaPrivateEncrypt(private_key, test_str, b64_encrypted_data));
        ASSERT_FALSE(b64_encrypted_data.empty());
        ASSERT_FALSE(CryptoUtil::RsaPrivateEncrypt(private_key, "", b64_encrypted_data));

        std::string raw_data;
        ASSERT_TRUE(CryptoUtil::RsaPublicDecrypt(public_key, b64_encrypted_data, raw_data));
        ASSERT_STREQ(raw_data.c_str(), test_str.c_str());
        ASSERT_FALSE(CryptoUtil::RsaPublicDecrypt(public_key, "", raw_data));
    }

    // public encrypt and private decrypt
    {
        std::string b64_encrypted_data;
        ASSERT_TRUE(CryptoUtil::RsaPublicEncrypt(public_key, test_str, b64_encrypted_data));
        ASSERT_FALSE(b64_encrypted_data.empty());
        ASSERT_FALSE(CryptoUtil::RsaPublicEncrypt(public_key, "", b64_encrypted_data));

        std::string raw_data;
        ASSERT_TRUE(CryptoUtil::RsaPrivateDecrypt(private_key, b64_encrypted_data, raw_data));
        ASSERT_STREQ(raw_data.c_str(), test_str.c_str());
        ASSERT_FALSE(CryptoUtil::RsaPrivateDecrypt(private_key, "", raw_data));
    }
}

TEST_F(CryptoUtilTest, AesEncryptAndDecrypt) {
    {
        const std::string aes_key = "b2nwTxYsU2h5SGaC";
        const std::string aes_iv = "LDKCXuP7Akn4KUpE";

        std::string b64_encrypted_data;
        ASSERT_TRUE(CryptoUtil::AesEncrypt(aes_key, aes_iv, test_str, b64_encrypted_data, "AES-128-CBC"));
        ASSERT_FALSE(b64_encrypted_data.empty());
        ASSERT_FALSE(CryptoUtil::AesEncrypt(aes_key, aes_iv, "", b64_encrypted_data, "AES-128-CBC"));

        std::string raw_data;
        ASSERT_TRUE(CryptoUtil::AesDecrypt(aes_key, aes_iv, b64_encrypted_data, raw_data, "AES-128-CBC"));
        ASSERT_STREQ(raw_data.c_str(), test_str.c_str());
        ASSERT_FALSE(CryptoUtil::AesDecrypt(aes_key, aes_iv, "", raw_data, "AES-128-CBC"));
        ASSERT_FALSE(CryptoUtil::AesDecrypt(aes_key, "jfkdasjoiw", "", raw_data, "AES-128-CBC"));
    }

    {
        const std::string aes_key = "b2nwTxYsU2h5SGaC";
        const std::string aes_iv = "LDKCXuP7Akn4KUpE";

        std::string b64_encrypted_data;
        ASSERT_TRUE(CryptoUtil::AesEncrypt(aes_key, aes_iv, test_str, b64_encrypted_data, "AES-256-CBC"));
        ASSERT_FALSE(b64_encrypted_data.empty());
        ASSERT_FALSE(CryptoUtil::AesEncrypt(aes_key, aes_iv, "", b64_encrypted_data, "AES-256-CBC"));

        std::string raw_data;
        ASSERT_TRUE(CryptoUtil::AesDecrypt(aes_key, aes_iv, b64_encrypted_data, raw_data, "AES-256-CBC"));
        ASSERT_STREQ(raw_data.c_str(), test_str.c_str());
        ASSERT_FALSE(CryptoUtil::AesDecrypt(aes_key, aes_iv, "", raw_data, "AES-256-CBC"));
        ASSERT_FALSE(CryptoUtil::AesDecrypt(aes_key, "jfkdasjoiw", "", raw_data, "AES-256-CBC"));
    }
}

TEST_F(CryptoUtilTest, Base64EncodeAndDecode) {
    std::string b64_data = CryptoUtil::Base64Encode(test_str);
    ASSERT_FALSE(b64_data.empty());

    std::string raw_data = CryptoUtil::Base64Decode(b64_data);
    ASSERT_STREQ(raw_data.c_str(), test_str.c_str());
}

TEST_F(CryptoUtilTest, Base32EncodeAndDecode) {
    int32_t uid = 400123;
    std::string b32_data = CryptoUtil::Base32Encode((uint8_t*)&uid, sizeof(uid));
    ASSERT_FALSE(b32_data.empty());

    auto raw_data = CryptoUtil::Base32Decode(b32_data);
    ASSERT_EQ(*((const int32_t*)raw_data.data()), uid);
}

TEST_F(CryptoUtilTest, Md5Hash) {
    std::string md5_str = CryptoUtil::Md5(test_str, true);
    ASSERT_STREQ(md5_str.c_str(), "C33B86ECF40480D0863612D717C220AD");
    md5_str = CryptoUtil::Md5(test_str, false);
    ASSERT_STREQ(md5_str.c_str(), "c33b86ecf40480d0863612d717c220ad");
}

TEST_F(CryptoUtilTest, ShaHash) {
    std::string sha_str = CryptoUtil::Sha1(test_str, true);
    ASSERT_STREQ(sha_str.c_str(), "B1F36EB5F16F72FBE880BEAE1537BC8A05745C4F");
    sha_str = CryptoUtil::Sha1(test_str, false);
    ASSERT_STREQ(sha_str.c_str(), "b1f36eb5f16f72fbe880beae1537bc8a05745c4f");

    sha_str = CryptoUtil::Sha256(test_str, true);
    ASSERT_STREQ(sha_str.c_str(), "D0BBFC6603CC2A199CE183E77F43DEE399274A43B12E4FE0ECF24AAD9575FF55");
    sha_str = CryptoUtil::Sha256(test_str, false);
    ASSERT_STREQ(sha_str.c_str(), "d0bbfc6603cc2a199ce183e77f43dee399274a43b12e4fe0ecf24aad9575ff55");

    sha_str = CryptoUtil::Sha512(test_str, true);
    ASSERT_STREQ(sha_str.c_str(), "3C332D8C883D5843DBDA88FFC305329B66EEC2BF1C086E4F28CCEFEE5282C4C08F91F62D9E4950E19348CE33E4ED31AC5C52E1F868D85F9934F919DCE0BDF2A9");
    sha_str = CryptoUtil::Sha512(test_str, false);
    ASSERT_STREQ(sha_str.c_str(), "3c332d8c883d5843dbda88ffc305329b66eec2bf1c086e4f28ccefee5282c4c08f91f62d9e4950e19348ce33e4ed31ac5c52e1f868d85f9934f919dce0bdf2a9");
}

TEST_F(CryptoUtilTest, UrlEncodeAndDecode) {
    std::string url_test_str = R"(abcdefgABCDEFG0123 _)(*&^%$#@!~`';":?></.,+)";
    {
        std::string encoded_str = CryptoUtil::UrlEncode(url_test_str);
        ASSERT_FALSE(encoded_str.empty());
        std::string decoded_str = CryptoUtil::UrlDecode(encoded_str);
        ASSERT_STREQ(url_test_str.c_str(), decoded_str.c_str());
    }

    // non w3c
    {
        std::string encoded_str = CryptoUtil::UrlEncode(url_test_str, false, false);
        ASSERT_FALSE(encoded_str.empty());
        std::string decoded_str = CryptoUtil::UrlDecode(encoded_str, false);
        ASSERT_STREQ(url_test_str.c_str(), decoded_str.c_str());
    }
}

TEST_F(CryptoUtilTest, Hex) {
    {
        std::string hex = CryptoUtil::Hex("12345", 5);
        EXPECT_STREQ(hex.c_str(), "3132333435");
    }
    {
        std::string hex = CryptoUtil::Hex("ABCDEFGHIJKLMN", 14);
        EXPECT_STREQ(hex.c_str(), "4142434445464748494A4B4C4D4E");
    }
    {
        std::string hex = CryptoUtil::Hex("ABCDEFGHIJKLMN", 14, false);
        EXPECT_STREQ(hex.c_str(), "4142434445464748494a4b4c4d4e");
    }
}