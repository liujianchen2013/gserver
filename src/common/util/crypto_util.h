#pragma once
#include <string>

class RsaKey;
class EvpKey;
struct rsa_st;
struct env_md_st;

class CryptoUtil {
public:
    static bool InitOpenssl();

    static bool Sha1WithRsaPublicVerify(const std::string& b64_public_key, const std::string& raw_data, const std::string& b64_sign);
    static bool Sha1WithRsaPrivateSign(const std::string& b64_private_key, const std::string& raw_data, std::string& b64_sign);
    static bool Sha256WithRsaPublicVerify(const std::string& b64_public_key, const std::string& raw_data, const std::string& b64_sign);
    static bool Sha256WithRsaPrivateSign(const std::string& b64_private_key, const std::string& raw_data, std::string& b64_sign);
    static bool RsaPublicEncrypt(const std::string& b64_public_key, const std::string& raw_data, std::string& b64_encrypted_data);
    static bool RsaPublicDecrypt(const std::string& b64_public_key, const std::string& b64_encrypted_data, std::string& raw_data);
    static bool RsaPrivateEncrypt(const std::string& b64_private_key, const std::string& raw_data, std::string& b64_encrypted_data);
    static bool RsaPrivateDecrypt(const std::string& b64_private_key, const std::string& b64_encrypted_data, std::string& raw_data);

    // AES-128-CBC AES-256-CBC DES-CBC BF-CBC ... 使用前需要调用InitOpenssl 
    static bool AesEncrypt(const std::string& key, const std::string& ivec, const std::string& raw_data, std::string& b64_encrypted_data, const std::string& cipher_str = "AES-128-CBC");
    static bool AesDecrypt(const std::string& key, const std::string& ivec, const std::string& b64_encrypted_data, std::string& raw_data, const std::string& cipher_str = "AES-128-CBC");

    static std::string Base64Encode(const std::string& raw_data);
    static std::string Base64Encode(const uint8_t* raw_data, std::size_t len);
    static std::string Base64Decode(const std::string& b64_data);

    static std::string Base32Encode(const uint8_t* raw_data, std::size_t len);
    static std::string Base32Decode(const std::string& b32_data);

    static std::string Md5(const std::string& raw_data, bool upper = true);
    static std::string Md5(const char* raw_data, size_t len, bool upper = true);

    static std::string Hex(const char* raw_data, size_t len, bool upper = true);

    static std::string Sha1(const std::string& raw_data, bool upper = true);
    static std::string Sha1(const char* raw_data, size_t len, bool upper = true);
    static std::string Sha256(const std::string& raw_data, bool upper = true);
    static std::string Sha256(const char* raw_data, size_t len, bool upper = true);
    static std::string Sha512(const std::string& raw_data, bool upper = true);
    static std::string Sha512(const char* raw_data, size_t len, bool upper = true);

    // W3C标准的空格要求编码成+或%20,而RFC2396标准要求编码成%20
    static std::string UrlEncode(const std::string& raw_data, bool w3c = true, bool upper = true);
    static std::string UrlEncode(const char* raw_data, size_t len, bool w3c = true, bool upper = true);
    static std::string UrlDecode(const std::string& url_data, bool w3c = true);
    static std::string UrlDecode(const char* raw_data, size_t len, bool w3c = true);

private:
    using RSA = rsa_st;
    using EVP_MD = env_md_st;
    using RsaCryptoFunc = int32_t (*)(int32_t, const uint8_t*, uint8_t*, RSA*, int32_t);
    static bool Verify(EvpKey& rsa_key, const std::string& raw_data, const std::string& b64_sign, const EVP_MD* evp_md);
    static bool Sign(EvpKey& rsa_key, const std::string& raw_data, std::string& b64_sign, const EVP_MD* evp_md);
    static bool RsaEncrypt(RsaKey& rsa_key, const std::string& raw_data, std::string& b64_encrypted_data, RsaCryptoFunc crypto_func);
    static bool RsaDecrypt(RsaKey& rsa_key, const std::string& b64_encrypted_data, std::string& raw_data, RsaCryptoFunc crypto_func);
};
