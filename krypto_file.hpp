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

    bool verify_input();

private:
    const std::string pass_;
    const std::string file_;
    boost::iostreams::filtering_ostream output_;
    boost::iostreams::filtering_istream input_;
    bool verified_input_;
};
}
