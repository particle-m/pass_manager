#include "manager.hpp"

#include <iostream>
#include <iomanip>

namespace pass_manager {

Record::Record(const std::string& tname,
               const std::string& tlogin,
               const std::string& tpass): name(tname), login(tlogin), pass(tpass) {}

void write_with_len(std::ostream& stream, const std::string& str) {
    std::size_t len = str.length();
    stream.write(reinterpret_cast<const char*>(&len), sizeof(len));
    stream.write(str.data(), len);
}

void Record::dump(std::ostream& stream) const {
    write_with_len(stream, name);
    write_with_len(stream, login);
    write_with_len(stream, pass);
}

std::string read_with_len(std::istream& stream) {
    std::size_t len;
    stream.read(reinterpret_cast<char*>(&len), sizeof(len));
    if (!stream.good()) {
        return std::string();
    }
    std::string str(len, ' ');
    stream.read(&str[0], len);
    return str;
}

Record Record::load(std::istream& stream) {
    std::string name  = read_with_len(stream);
    std::string login = read_with_len(stream);
    std::string pass  = read_with_len(stream);
    return Record(name, login, pass);
}

std::ostream& operator<<(std::ostream& stream, const Record& record) {
    return stream
        << std::setw(20) << std::left
        << record.name  << " "
        << std::setw(20) << std::left
        << record.login << " "
        << std::setw(20) << std::left
        << record.pass  << " ";
}

void Manager::add_record(const Record& record) {
    relations_.insert(std::make_pair(record.name, record));
}

bool Manager::has_record(const std::string& name) const {
    return relations_.find(name) != relations_.end();
}

const Record& Manager::find(const std::string& name) const {
    return relations_.find(name)->second;
}

std::size_t Manager::size() const {
    return relations_.size();
}

Manager::RelationsIterator Manager::begin() const {
    return make_map_iterator(relations_.begin());
}

Manager::RelationsIterator Manager::end() const {
    return make_map_iterator(relations_.end());
}

}
