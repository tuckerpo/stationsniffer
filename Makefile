appname := station-sniffer

CXX ?= g++
CXXFLAGS += -Wall -Werror -std=c++17 `pkg-config --cflags libnl-3.0 libnl-genl-3.0`

srcfiles := $(shell find . -maxdepth 1 -name "*.cpp")
objects  := $(patsubst %.cpp, %.o, $(srcfiles))

all: $(appname)

$(appname): $(objects)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(appname) $(objects) $(LDLIBS) -lpcap -lradiotap -lpthread `pkg-config --libs libnl-3.0 libnl-genl-3.0`

depend: .depend

.depend: $(srcfiles)
	rm -f ./.depend
	$(CXX) $(CXXFLAGS) -MM $^>>./.depend;

clean:
	rm -f $(objects) $(appname)

dist-clean: clean
	rm -f *~ .depend

include .depend
