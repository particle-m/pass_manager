#pragma once

#include <unordered_map>
#include <functional>
#include <vector>
#include <string>

#include "krypto_file.hpp"
#include "manager.hpp"

namespace pass_manager {

class Application {
public:
    typedef std::vector<std::string> arguments;
    typedef std::function<void(Manager&, const arguments&)> raw_action;
    typedef const std::string description;
    typedef std::pair<description, raw_action> action;
    typedef std::unordered_map<std::string, action> action_map;

    Application(const std::string& pass, const std::string& file);
    ~Application();

    inline bool initialized() { return initialized_; }

    void loop();

    void register_action(const std::string& name,
                         const std::string& description,
                         raw_action new_action);

private:

    void initialize();
    void quit(Manager&, const arguments&);
    void list(Manager&, const arguments&);
    void no_action(Manager&, const arguments&);

    raw_action get_action(const std::string& name);

private:
    KryptoFile file_;
    Manager manager_;

    bool quit_;
    bool initialized_;
    action_map actions_;
};

}
