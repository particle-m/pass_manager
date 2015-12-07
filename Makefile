CXXFLAGS+= -Wall -Wextra -g -std=c++14
LDFLAGS+= -g

# cxxopts
CXXFLAGS+=-I'vendor/cxxopts/src'

# crypto++
CXXFLAGS+=`pkg-config --cflags libcrypto++`
LDFLAGS+=`pkg-config --libs libcrypto++`

# boost_iostreams
LDFLAGS+=-lboost_iostreams

PROJECT=pass_manager

MODULES=krypto_file manager application

.PHONY: main

main: $(PROJECT)

$(PROJECT): main.cpp $(MODULES:=.o)
	$(CXX) main.cpp $(MODULES:=.o) $(CXXFLAGS) $(LDFLAGS) -o $@

%.o: %.cpp %.hpp
	$(CXX) $< $(CXXFLAGS) -c -o $@

clean:
	$(RM) *.o $(PROJECT)
