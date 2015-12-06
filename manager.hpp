#pragma once

#include <string>
#include <unordered_map>

#include "map_iterator.hpp"

namespace pass_manager {

struct Record {
    Record(const std::string& name,
           const std::string& login,
           const std::string& pass);

    void dump(std::ostream&);
    static Record load(std::istream&);

    const std::string name;
    const std::string login;
    const std::string pass;
};

std::ostream& operator<<(std::ostream& stream, const Record& record);

class Manager {
    typedef std::unordered_map<std::string, Record> Relations;
public:
    typedef map_iterator<Relations::const_iterator> RelationsIterator;

    void addRecord(const Record& record);
    bool hasRecord(const std::string& name) const;
    const Record& find(const std::string& name) const;

    std::size_t size() const;
    RelationsIterator begin() const;
    RelationsIterator end() const;

private:
    Relations relations_;
};
}
