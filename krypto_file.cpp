#include "krypto_file.hpp"

#include <boost/iostreams/device/file.hpp>
#include <boost/iostreams/operations.hpp>
#include <boost/iostreams/char_traits.hpp>
#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/filter/aggregate.hpp>
#include <crypto++/cryptlib.h>
#include <crypto++/hex.h>
#include <crypto++/files.h>
#include <crypto++/osrng.h>
#include <crypto++/sha.h>

namespace io = boost::iostreams;

namespace pass_manager {

std::string generate_seed(CryptoPP::HashTransformation& transform) {
    CryptoPP::BlockingRng rng;
    std::string seed;

    auto sink    = new CryptoPP::StringSink(seed);
    auto encoder = new CryptoPP::HexEncoder(sink);
    CryptoPP::RandomNumberSource source(rng, transform.DigestSize(), true, encoder);
    return seed;
}

CryptoPP::Filter* prepare_digest(CryptoPP::HashTransformation& transform,
                                 std::string& digest) {
    auto sink    = new CryptoPP::StringSink(digest);
    auto encoder = new CryptoPP::HexEncoder(sink);
    return new CryptoPP::HashFilter(transform, encoder);
}

std::string digest(CryptoPP::HashTransformation& transform,
                   const std::string& input) {
    std::string digest;
    CryptoPP::StringSource source(input, true, prepare_digest(transform, digest));

    return digest;
}

std::string digest(CryptoPP::HashTransformation& transform,
                   std::istream& input) {
    std::string digest;
    CryptoPP::FileSource source(input, true, prepare_digest(transform, digest));

    return digest;
}

std::string xor_str(const std::string& lhs, const std::string& rhs) {
    std::string result(lhs.length(), ' ');

    for (std::size_t i = 0; i < lhs.length(); ++i) {
        result[i] = lhs[i] ^ rhs[i];
    }

    return result;
}

std::string hex_encode(const std::string& str) {
    CryptoPP::HexEncoder encoder;
    encoder.Put(reinterpret_cast<const byte*>(str.data()), str.length());
    std::string encoded(encoder.MaxRetrievable(), ' ');
    encoder.Get(reinterpret_cast<byte*>(&encoded[0]), encoded.size());
    return encoded;
}

class EncryptionFilter : public io::dual_use_filter {
public:
    EncryptionFilter(const std::string& pass);

    template<typename Sink>
    bool put(Sink& dest, int c) {
        if (!initialized_) {
            initialize(generate_seed(key_hash_));
            io::write(dest, seed_.data(), seed_.length());
        }

        if (c != EOF) {
            c = transform(c);
        }
        byte b = c;
        message_hash_.Update(&b, 1);

        return io::put(dest, c);
    }

    template<typename Source>
    int get(Source& src) {
        if (!initialized_) {
            std::streamsize size = key_hash_.DigestSize() * 2;
            std::string seed(size, ' ');
            if (io::read(src, &seed[0], size) == -1) {
                return EOF;
            }
            initialize(seed);
        }

        int c = io::get(src);
        if (c == EOF || c == io::WOULD_BLOCK) {
            return c;
        }
        return transform(c);
    }

    template<typename Device>
    void close(Device& device, std::ios_base::open_mode mode) {
        if (mode == std::ios_base::out) {
            std::string digest(message_hash_.DigestSize(), ' ');
            message_hash_.Final(reinterpret_cast<byte*>(&digest[0]));
            for (auto c : digest) {
                put(device, c);
            }
            std::cout << hex_encode(digest) << std::endl;
        }
        finalize();
    }

private:
    CryptoPP::SHA256 message_hash_;
    CryptoPP::SHA256 key_hash_;
    const std::string pass_;
    std::string seed_;
    std::string current_key_;
    std::size_t key_pos_;
    bool initialized_;

    void initialize(const std::string& seed);
    void finalize();
    int transform(int c);
};

EncryptionFilter::EncryptionFilter(const std::string& pass)
    : message_hash_(), key_hash_(),
      pass_(pass), seed_(""), current_key_(""), key_pos_(0), initialized_(false) {}

void EncryptionFilter::initialize(const std::string& seed) {
    seed_        = seed;
    current_key_ = xor_str(digest(key_hash_, seed), digest(key_hash_, pass_));
    initialized_ = true;
}

void EncryptionFilter::finalize() {
    seed_.erase();
    current_key_.erase();
    key_pos_     = 0;
    initialized_ = false;
}

int EncryptionFilter::transform(int c) {
    if (key_pos_ < current_key_.length()) {
        return c ^ current_key_[key_pos_++];
    }

    current_key_ = digest(key_hash_, xor_str(current_key_, seed_));
    key_pos_     = 0;
    return transform(c);
}


class DigestFilter : public io::input_filter {
public:

    template<typename Sink>
    bool put(Sink& dest, int c) {
        if (c != EOF) {
            byte b = c;
            hash_.Update(&b, 1);
        }

        return io::put(dest, c);
    }

    template<typename Sink>
    void close(Sink& dest) {
        std::string digest(message_hash_.DigestSize(), ' ');
        message_hash_.Final(reinterpret_cast<byte*>(&digest[0]));
        io::write(dest, digest.data(), digest.length());
    }

private:
    CryptoPP::SHA256 hash_;
};

class VerifyingFilter : public io::aggregate_filter<char> {
    using vector = io::aggregate_filter<char>::vector_type;

    void do_filter(const vector& src, vector& dst) override {
        CryptoPP::SHA256 hash;

        if (src.size() < hash.DigestSize()) {
            return;
        }

        std::size_t message_size = src.size() - hash.DigestSize();
        // hash.Update(reinterpret_cast<const byte*>(&src[0]), message_size);
        std::cout << "Size: " << message_size << std::endl;
        std::string digest1(src.begin() + message_size, src.end());
        std::string message(src.begin(), src.begin() + message_size);
        std::cout << message << std::endl;
        std::cout << hex_encode(digest1) << std::endl;
        std::cout << digest(hash, message) << std::endl;
        if (!hash.Verify(reinterpret_cast<const byte*>(&src[message_size]))) {
            throw "Incorrect Password";
        }
        dst.reserve(message_size);
        std::copy(src.begin(), src.end() - hash.DigestSize(),
                  std::back_inserter(dst));
        // std::string msg(dst.begin(), dst.end());
        // std::cerr << msg << std::endl;
    }
};

KryptoFile::KryptoFile(const std::string& pass, const std::string& file)
    : pass_(pass), file_(file), output_(), input_(), verified_input_(false) {

    output_.push(EncryptionFilter(pass_));
    input_.push(VerifyingFilter());
    input_.push(EncryptionFilter(pass_));
}

using mode = std::ios_base;

std::ostream& KryptoFile::output() {
    output_.push(io::file_sink(file_, mode::binary | mode::out));
    return output_;
}

std::istream& KryptoFile::input() {
    input_.push(io::file_source(file_, mode::binary | mode::in));
    return input_;
}

void KryptoFile::reset() {
    if (input_.is_complete()) {
        input_.pop();
    }
    if (output_.is_complete()) {
        output_.pop();
    }
    verified_input_ = false;
}

}
