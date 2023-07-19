#include "crypto_util.h"

#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <cmath>
#include <cstring>
#include <iostream>
#include <memory>
#include <sstream>
#include <vector>

#include "contrib/cppcodec/base64_rfc4648.hpp"
#include "contrib/cppcodec/base32_rfc4648.hpp"
#include "contrib/cppcodec/base32_crockford.hpp"
#include "contrib/cppcodec/hex_upper.hpp"
#include "contrib/cppcodec/hex_lower.hpp"

enum class KeyType {
    kPkcs1 = 1,
    kPkcs8 = 2,
};

enum class CipherType {
    kAes128Cbc = 1,
    kAes192Cbc = 2,
};

static std::string ConvToPemKey(const std::string& b64_key, bool is_private_key = false, KeyType key_type = KeyType::kPkcs1) {
    if (b64_key.empty()) {
        return "";
    }

    std::string key_str = is_private_key ? "PRIVATE" : "PUBLIC";
    key_str = key_type == KeyType::kPkcs1 ? "RSA " + key_str : key_str;

    std::ostringstream oss;
    oss << "-----BEGIN " << key_str << " KEY-----\n";
    for (int32_t i = 0; i < int32_t(b64_key.size()); ++i) {
        oss << b64_key[i];
        if (((i + 1) % 64) == 0) {
            oss << '\n';
        }
    }
    oss << "\n-----END " << key_str << " KEY-----\n";
    return oss.str();
}

class CryptoKey {
public:
    virtual bool Init(const std::string& b64_key, bool is_private, KeyType key_type);
    virtual int32_t KeySize() const = 0;
    virtual ~CryptoKey();

protected:
    std::string pem_key_;
    BIO* bio_ = nullptr;
};

class EvpKey final : public CryptoKey {
public:
    bool Init(const std::string& b64_key, bool is_private, KeyType key_type = KeyType::kPkcs1) override;
    int32_t KeySize() const override;
    ~EvpKey() override;

public:
    EVP_PKEY* pkey_ = nullptr;
};

class RsaKey final : public CryptoKey {
public:
    bool Init(const std::string& b64_key, bool is_private, KeyType key_type = KeyType::kPkcs1) override;
    int32_t KeySize() const override;
    ~RsaKey() override;

public:
    RSA* rsa_ = nullptr;
};

bool CryptoKey::Init(const std::string& b64_key, bool is_private, KeyType key_type) {
    pem_key_ = ConvToPemKey(b64_key, is_private, key_type);
    if (pem_key_.empty()) {
        return false;
    }

    bio_ = BIO_new_mem_buf(pem_key_.c_str(), -1);
    return bio_;
}
CryptoKey::~CryptoKey() {
    if (bio_) {
        BIO_free(bio_);
        bio_ = nullptr;
    }
}

bool EvpKey::Init(const std::string& b64_key, bool is_private, KeyType key_type /*  = KeyType::kPkcs1 */) {
    if (!CryptoKey::Init(b64_key, is_private, key_type)) {
        return false;
    }

    if (is_private) {
        pkey_ = PEM_read_bio_PrivateKey(bio_, nullptr, nullptr, nullptr);
    } else {
        pkey_ = PEM_read_bio_PUBKEY(bio_, nullptr, nullptr, nullptr);
    }

    return pkey_;
}

int32_t EvpKey::KeySize() const {
    return EVP_PKEY_size(pkey_);
}

EvpKey::~EvpKey() {
    if (pkey_) {
        EVP_PKEY_free(pkey_);
        pkey_ = nullptr;
    }
}

bool RsaKey::Init(const std::string& b64_key, bool is_private, KeyType key_type /*  = KeyType::kPkcs1 */) {
    if (!CryptoKey::Init(b64_key, is_private, key_type)) {
        return false;
    }

    if (is_private) {
        switch (key_type) {
            case KeyType::kPkcs1:
                rsa_ = PEM_read_bio_RSAPrivateKey(bio_, nullptr, nullptr, nullptr);
                break;
            case KeyType::kPkcs8:
                // 暂不支持
                break;
            default:
                break;
        }
    } else {
        switch (key_type) {
            case KeyType::kPkcs1:
                rsa_ = PEM_read_bio_RSAPublicKey(bio_, nullptr, nullptr, nullptr);
                break;
            case KeyType::kPkcs8:
                rsa_ = PEM_read_bio_RSA_PUBKEY(bio_, nullptr, nullptr, nullptr);
                break;
            default:
                break;
        }
    }

    return rsa_;
}

int32_t RsaKey::KeySize() const {
    return RSA_size(rsa_);
}

RsaKey::~RsaKey() {
    if (rsa_) {
        RSA_free(rsa_);
        rsa_ = nullptr;
    }
}

void PrintOpensslError() {
    ERR_load_crypto_strings();
    char err_buff[512];
    ERR_error_string_n(ERR_get_error(), err_buff, sizeof(err_buff));
    std::cout << err_buff << std::endl;
}

bool CryptoUtil::InitOpenssl() {
    OpenSSL_add_all_algorithms();
    return true;
}

bool CryptoUtil::Sha1WithRsaPublicVerify(const std::string& b64_public_key, const std::string& raw_data, const std::string& b64_sign) {
    EvpKey evp_key;
    if (!evp_key.Init(b64_public_key, false, KeyType::kPkcs8)) {
        PrintOpensslError();
        return false;
    }

    return Verify(evp_key, raw_data, b64_sign, EVP_sha1());
}

bool CryptoUtil::Sha1WithRsaPrivateSign(const std::string& b64_private_key, const std::string& raw_data, std::string& b64_sign) {
    EvpKey evp_key;
    if (!evp_key.Init(b64_private_key, true, KeyType::kPkcs1)) {
        PrintOpensslError();
        return false;
    }

    return Sign(evp_key, raw_data, b64_sign, EVP_sha1());
}

bool CryptoUtil::Sha256WithRsaPublicVerify(const std::string& b64_public_key, const std::string& raw_data, const std::string& b64_sign) {
    EvpKey evp_key;
    if (!evp_key.Init(b64_public_key, false, KeyType::kPkcs8)) {
        PrintOpensslError();
        return false;
    }

    return Verify(evp_key, raw_data, b64_sign, EVP_sha256());
}

bool CryptoUtil::Sha256WithRsaPrivateSign(const std::string& b64_private_key, const std::string& raw_data, std::string& b64_sign) {
    EvpKey evp_key;
    if (!evp_key.Init(b64_private_key, true, KeyType::kPkcs1)) {
        PrintOpensslError();
        return false;
    }

    return Sign(evp_key, raw_data, b64_sign, EVP_sha256());
}

bool CryptoUtil::RsaPublicEncrypt(const std::string& b64_public_key, const std::string& raw_data, std::string& b64_encrypted_data) {
    RsaKey rsa_key;
    if (!rsa_key.Init(b64_public_key, false, KeyType::kPkcs8)) {
        PrintOpensslError();
        return false;
    }
    return RsaEncrypt(rsa_key, raw_data, b64_encrypted_data, RSA_public_encrypt);
}

bool CryptoUtil::RsaPublicDecrypt(const std::string& b64_public_key, const std::string& b64_encrypted_data, std::string& raw_data) {
    RsaKey rsa_key;
    if (!rsa_key.Init(b64_public_key, false, KeyType::kPkcs8)) {
        PrintOpensslError();
        return false;
    }
    return RsaDecrypt(rsa_key, b64_encrypted_data, raw_data, RSA_public_decrypt);
}

bool CryptoUtil::RsaPrivateEncrypt(const std::string& b64_private_key, const std::string& raw_data, std::string& b64_encrypted_data) {
    RsaKey rsa_key;
    if (!rsa_key.Init(b64_private_key, true, KeyType::kPkcs1)) {
        PrintOpensslError();
        return false;
    }
    return RsaEncrypt(rsa_key, raw_data, b64_encrypted_data, RSA_private_encrypt);
}

bool CryptoUtil::RsaPrivateDecrypt(const std::string& b64_private_key, const std::string& b64_encrypted_data, std::string& raw_data) {
    RsaKey rsa_key;
    if (!rsa_key.Init(b64_private_key, true, KeyType::kPkcs1)) {
        PrintOpensslError();
        return false;
    }
    return RsaDecrypt(rsa_key, b64_encrypted_data, raw_data, RSA_private_decrypt);
}

bool CryptoUtil::AesEncrypt(const std::string& key, const std::string& ivec, const std::string& raw_data, std::string& b64_encrypted_data, const std::string& cipher_name /*  = "AES-128-CBC" */) {
    const EVP_CIPHER* cipher = EVP_get_cipherbyname(cipher_name.c_str());
    // ***如果cipher总是为null需要检查下是否调用CryptoUtil::InitOpenssl()***
    if (key.size() != ivec.size() || !cipher || raw_data.empty()) {
        return false;
    }

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    const uint8_t* in = reinterpret_cast<const uint8_t*>(raw_data.c_str());
    const uint8_t* k = reinterpret_cast<const uint8_t*>(key.c_str());
    const uint8_t* iv = reinterpret_cast<const uint8_t*>(ivec.c_str());
    if (1 != EVP_EncryptInit_ex(&ctx, cipher, nullptr, k, iv)) {
        PrintOpensslError();
        return false;
    }
    int buff_len = (raw_data.size() / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
    auto out_ptr = std::make_shared<std::vector<uint8_t>>(buff_len, 0);
    uint8_t* out = out_ptr->data();
    int out_len = 0;
    if (1 != EVP_EncryptUpdate(&ctx, out, &out_len, in, raw_data.size())) {
        PrintOpensslError();
        return false;
    }
    int total_len = out_len;
    if (1 != EVP_EncryptFinal_ex(&ctx, out + out_len, &out_len)) {
        PrintOpensslError();
        return false;
    }

    total_len += out_len;
    if (total_len > buff_len) {
        return false;
    }

    b64_encrypted_data = Base64Encode(out, total_len);
    return true;
}

bool CryptoUtil::AesDecrypt(const std::string& key, const std::string& ivec, const std::string& b64_encrypted_data, std::string& raw_data, const std::string& cipher_name /*  = "AES-128-CBC" */) {
    const EVP_CIPHER* cipher = EVP_get_cipherbyname(cipher_name.c_str());
    // ***如果cipher总是为null需要检查下是否调用CryptoUtil::InitOpenssl()***
    if (key.size() != ivec.size() || !cipher || b64_encrypted_data.empty()) {
        return false;
    }

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    std::string bin_data = Base64Decode(b64_encrypted_data);
    const uint8_t* in = reinterpret_cast<const uint8_t*>(bin_data.c_str());
    const uint8_t* k = reinterpret_cast<const uint8_t*>(key.c_str());
    const uint8_t* iv = reinterpret_cast<const uint8_t*>(ivec.c_str());
    if (1 != EVP_DecryptInit_ex(&ctx, cipher, nullptr, k, iv)) {
        PrintOpensslError();
        return false;
    }
    int buff_len = (bin_data.size() / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
    auto out_ptr = std::make_shared<std::vector<uint8_t>>(buff_len, 0);
    uint8_t* out = out_ptr->data();
    int out_len = 0;
    if (1 != EVP_DecryptUpdate(&ctx, out, &out_len, in, bin_data.size())) {
        PrintOpensslError();
        return false;
    }
    int total_len = out_len;
    if (1 != EVP_DecryptFinal_ex(&ctx, out + out_len, &out_len)) {
        PrintOpensslError();
        return false;
    }
    total_len += out_len;
    if (total_len > buff_len) {
        return false;
    }

    raw_data.assign(reinterpret_cast<char*>(out), total_len);
    return true;
}

std::string CryptoUtil::Base64Encode(const std::string& raw_data) {
    return Base64Encode(reinterpret_cast<const uint8_t*>(raw_data.c_str()), raw_data.size());
}

std::string CryptoUtil::Base64Encode(const uint8_t* raw_data, std::size_t len) {
    return cppcodec::base64_rfc4648::encode(raw_data, len);
}

std::string CryptoUtil::Base64Decode(const std::string& b64_data) {
    return cppcodec::base64_rfc4648::decode<std::string>(b64_data);
}

std::string CryptoUtil::Base32Encode(const uint8_t* raw_data, std::size_t len) {
    return cppcodec::base32_rfc4648::encode(raw_data, len);
}

std::string CryptoUtil::Base32Decode(const std::string& b32_data) {
    return cppcodec::base32_rfc4648::decode<std::string>(b32_data);
}

std::string CryptoUtil::Md5(const std::string& raw_data, bool upper) {
    return Md5(raw_data.c_str(), raw_data.size(), upper);
}

std::string CryptoUtil::Md5(const char* raw_data, size_t len, bool upper) {
    uint8_t md[MD5_DIGEST_LENGTH];
    MD5(reinterpret_cast<const uint8_t*>(raw_data), len, md);
    return Hex(reinterpret_cast<const char*>(md), MD5_DIGEST_LENGTH, upper);
}

std::string CryptoUtil::Hex(const char* raw_data, size_t len, bool upper /* = true */) {
    return upper ? cppcodec::hex_upper::encode(raw_data, len) : cppcodec::hex_lower::encode(raw_data, len);
}

std::string CryptoUtil::Sha1(const std::string& raw_data, bool upper /*  = true */) {
    return Sha1(raw_data.c_str(), raw_data.size(), upper);
}

std::string CryptoUtil::Sha1(const char* raw_data, size_t len, bool upper) {
    uint8_t md[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const uint8_t*>(raw_data), len, md);
    return Hex(reinterpret_cast<const char*>(md), SHA_DIGEST_LENGTH, upper);
}

std::string CryptoUtil::Sha256(const std::string& raw_data, bool upper /*  = true */) {
    return Sha256(raw_data.c_str(), raw_data.size(), upper);
}

std::string CryptoUtil::Sha256(const char* raw_data, size_t len, bool upper) {
    uint8_t md[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const uint8_t*>(raw_data), len, md);
    return Hex(reinterpret_cast<const char*>(md), SHA256_DIGEST_LENGTH, upper);
}

std::string CryptoUtil::Sha512(const std::string& raw_data, bool upper /*  = true */) {
    return Sha512(raw_data.c_str(), raw_data.size(), upper);
}

std::string CryptoUtil::Sha512(const char* raw_data, size_t len, bool upper) {
    uint8_t md[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const uint8_t*>(raw_data), len, md);
    return Hex(reinterpret_cast<const char*>(md), SHA512_DIGEST_LENGTH, upper);
}

std::string CryptoUtil::UrlEncode(const std::string& raw_data, bool w3c /*  = true */, bool upper /*  = true */) {
    return UrlEncode(raw_data.c_str(), raw_data.length(), upper, w3c);
}

static uint8_t ToHex(uint8_t x, bool upper) {
    static std::string hex = std::string("0123456789") + (upper ? "ABCDEF" : "abcdef");
    return hex[x & 15];
}

std::string CryptoUtil::UrlEncode(const char* raw_data, size_t len, bool w3c /*  = true */, bool upper /*  = true */) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i) {
        if (w3c && raw_data[i] == ' ') {
            oss << '+';
        } else if (isalnum(raw_data[i]) ||
                   raw_data[i] == '-' ||
                   raw_data[i] == '_' ||
                   raw_data[i] == '.' ||
                   raw_data[i] == '~') {
            oss << raw_data[i];
        } else {
            oss << '%' << ToHex(raw_data[i] >> 4, upper) << ToHex(raw_data[i] & 15, upper);
        }
    }
    return oss.str();
}

static uint8_t FromHex(uint8_t x) {
    return isdigit(x) ? x - '0' : tolower(x) - 'a' + 10;
}

std::string CryptoUtil::UrlDecode(const std::string& url_data, bool w3c /*  = true */) {
    return UrlDecode(url_data.c_str(), url_data.length(), w3c);
}

std::string CryptoUtil::UrlDecode(const char* url_data, size_t len, bool w3c /*  = true */) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; i++) {
        if (w3c && url_data[i] == '+') {
            oss << ' ';
        } else if (url_data[i] == '%') {
            if (i + 2 >= len) {
                return "";
            }
            uint8_t high = FromHex(url_data[++i]);
            uint8_t low = FromHex(url_data[++i]);
            oss << static_cast<uint8_t>(high << 4 | low);
        } else {
            oss << url_data[i];
        }
    }
    return oss.str();
}

bool CryptoUtil::Verify(EvpKey& evp_key, const std::string& raw_data, const std::string& b64_sign, const EVP_MD* evp_md) {
    if (raw_data.empty() || b64_sign.empty()) {
        return false;
    }
    EVP_MD_CTX ctx;
    EVP_MD_CTX_init(&ctx);

    if (EVP_VerifyInit(&ctx, evp_md) != 1) {
        PrintOpensslError();
        return false;
    }

    if (EVP_VerifyUpdate(&ctx, raw_data.c_str(), raw_data.size()) != 1) {
        PrintOpensslError();
        return false;
    }

    auto bin_sign = Base64Decode(b64_sign);
    auto ret = EVP_VerifyFinal(&ctx, (const uint8_t*)bin_sign.c_str(), bin_sign.size(), evp_key.pkey_);
    if (1 != ret) {
        PrintOpensslError();
        return false;
    }

    return true;
}

bool CryptoUtil::Sign(EvpKey& evp_key, const std::string& raw_data, std::string& b64_sign, const EVP_MD* evp_md) {
    if (raw_data.empty()) {
        return false;
    }

    EVP_MD_CTX ctx;
    EVP_MD_CTX_init(&ctx);

    if (EVP_SignInit(&ctx, evp_md) != 1) {
        PrintOpensslError();
        return false;
    }

    if (EVP_SignUpdate(&ctx, raw_data.c_str(), raw_data.size()) != 1) {
        PrintOpensslError();
        EVP_MD_CTX_cleanup(&ctx);
        return false;
    }

    uint32_t buff_len = evp_key.KeySize();
    uint8_t tmp_buff[buff_len];
    auto ret = EVP_SignFinal(&ctx, tmp_buff, &buff_len, evp_key.pkey_);
    if (1 != ret) {
        PrintOpensslError();
        return false;
    }
    b64_sign = Base64Encode(tmp_buff, buff_len);
    return true;
}

bool CryptoUtil::RsaEncrypt(RsaKey& rsa_key, const std::string& raw_data, std::string& b64_encrypted_data, RsaCryptoFunc crypto_func) {
    if (raw_data.empty()) {
        return false;
    }
    int32_t rsa_len = rsa_key.KeySize();
    int32_t block_len = rsa_len - RSA_PKCS1_PADDING_SIZE;
    int32_t input_len = raw_data.size();
    int32_t buff_len = std::ceil((float)input_len / block_len) * rsa_len;
    auto out_ptr = std::make_shared<std::vector<uint8_t>>(buff_len, 0);
    uint8_t* tmp_buff = out_ptr->data();
    int32_t offset = 0;
    int32_t encrypted_total_len = 0;
    while (input_len - offset > 0) {
        int32_t real_len = block_len;
        if (input_len - offset < block_len) {
            real_len = input_len - offset;
        }
        auto encrypt_len = crypto_func(real_len, (const uint8_t*)(raw_data.c_str() + offset), tmp_buff + encrypted_total_len, rsa_key.rsa_, RSA_PKCS1_PADDING);
        if (encrypt_len <= 0) {
            PrintOpensslError();
            return false;
        }
        offset += real_len;
        encrypted_total_len += encrypt_len;
    }

    b64_encrypted_data = Base64Encode(tmp_buff, buff_len);
    return true;
}

bool CryptoUtil::RsaDecrypt(RsaKey& rsa_key, const std::string& b64_encrypted_data, std::string& raw_data, RsaCryptoFunc crypto_func) {
    if (b64_encrypted_data.empty()) {
        return false;
    }
    int32_t rsa_len = rsa_key.KeySize();
    int32_t block_len = rsa_len - RSA_PKCS1_PADDING_SIZE;
    std::string bin_data = Base64Decode(b64_encrypted_data);
    int32_t input_len = bin_data.size();
    int32_t buff_len = std::ceil((float)input_len / rsa_len) * block_len;
    auto out_ptr = std::make_shared<std::vector<uint8_t>>(buff_len, 0);
    uint8_t* tmp_buff = out_ptr->data();
    int32_t offset = 0;
    int32_t decrypted_total_len = 0;
    while (input_len - offset > 0) {
        int32_t real_len = rsa_len;
        if (input_len - offset <= rsa_len) {
            real_len = input_len - offset;
        }
        auto decrypt_len = crypto_func(real_len, (const uint8_t*)(bin_data.c_str() + offset), tmp_buff + decrypted_total_len, rsa_key.rsa_, RSA_PKCS1_PADDING);
        if (decrypt_len <= 0) {
            PrintOpensslError();
            return false;
        }
        offset += real_len;
        decrypted_total_len += decrypt_len;
    }

    raw_data.assign(reinterpret_cast<char*>(tmp_buff), decrypted_total_len);
    return true;
}