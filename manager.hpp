#pragma once

#include <string>
#include <unordered_map>

#include "map_iterator.hpp"

namespace pass_manager {

struct Record {
    Record(const std::string& name,
           const std::string& login,
           const std::string& pass);

    void dump(std::ostream&) const;
    static Record load(std::istream&);

    const std::string name;
    const std::string login;
    const std::string pass;
};

std::ostream& operator<<(std::ostream& stream, const Record& record);

class Manager {
    typedef std::unordered_map<std::string, const Record> Relations;
public:
    typedef map_iterator<Relations::const_iterator> RelationsIterator;

    void add_record(const Record& record);
    bool has_record(const std::string& name) const;
    const Record& find(const std::string& name) const;

    std::size_t size() const;
    RelationsIterator begin() const;
    RelationsIterator end() const;

private:
    Relations relations_;
};
}
