#include <iostream>
#include <cstdlib>

#include "krypto_file.hpp"
#include "manager.hpp"

int main(int argc, char* argv[]) {
    using namespace pass_manager;

    if (argc < 2) {
        return EXIT_FAILURE;
    }

    KryptoFile file(argv[1], "pass.bin");

    Record in = Record::load(file.input());
    std::cout << in << std::endl;

    file.reset();

    Record record("facebook.com", "test", "test");
    record.dump(file.output());

    return EXIT_SUCCESS;
}
