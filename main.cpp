#include <iostream>
#include <cstdlib>

#include "application.hpp"

using namespace pass_manager;

typedef Application::arguments Args;

void add(Manager& manager, const Args& args) {
    if (args.size() < 3) {
        std::cout << "Usage: add name login pass" << std::endl;
        return;
    }
    manager.add_record(Record(args[0], args[1], args[2]));
}

void find(Manager& manager, const Args& args) {
    if (args.size() < 1) {
        std::cout << "Usage: find name" << std::endl;
        return;
    }
    if (manager.has_record(args[0])) {
        std::cout << manager.find(args[0]) << std::endl;
    } else {
        std::cout << "Not found" << std::endl;
    }
}

void all(Manager& manager, const Args&) {
    for (const Record& record : manager) {
        std::cout << record << "\n";
    }
    std::cout << "Count: " << manager.size() << std::endl;
}

void count(Manager& manager, const Args&) {
    std::cout << manager.size() << std::endl;
}

int main(int argc, char* argv[]) {

    std::string file;

    if (argc < 2) {
        std::cerr
            << "No file provided. "
            << "Selecting 'pass.bin' as a default."
            << std::endl;
        file = "pass.bin";
    } else {
        file = argv[1];
    }

    std::string pass;
    std::cout << "Password: " << std::flush;
    std::getline(std::cin, pass);

    Application app(pass, file);
    app.register_action("all", "Lists all known credentials", all);
    app.register_action("find", "Lookups credentials by name", find);
    app.register_action("add", "Adds new credentials", add);
    app.register_action("count", "Print count of entries", count);

    if (app.initialized()) {
        app.loop();
        return EXIT_SUCCESS;
    } else {
        return EXIT_FAILURE;
    }
}
