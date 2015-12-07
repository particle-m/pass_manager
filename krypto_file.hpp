#pragma once

#include <iostream>
#include <string>

#include <boost/iostreams/filtering_stream.hpp>

namespace pass_manager {

class KryptoFile {
public:
    KryptoFile(const std::string& pass, const std::string& file);

    std::ostream& output();
    std::istream& input();
    void reset();

private:
    const std::string pass_;
    const std::string file_;
    boost::iostreams::filtering_ostream output_;
    boost::iostreams::filtering_istream input_;
    bool verified_input_;
};

class KryptoLock {
public:
    KryptoLock(KryptoFile& file);
    ~KryptoLock();
private:
    KryptoFile& file_;
};

class InputKryptoLock : private KryptoLock {
public:
    InputKryptoLock(KryptoFile& file);
    std::istream& stream;
};

class OutputKryptoLock : private KryptoLock {
public:
    OutputKryptoLock(KryptoFile& file);
    std::ostream& stream;
};

}
