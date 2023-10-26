appname := uds_client

CXX ?= gcc
CXXFLAGS += -Wall

srcfiles := $(shell find . -maxdepth 1 -name "*.c")
objects  := $(patsubst %.c, %.o, $(srcfiles))

all: $(appname)

$(appname): $(objects)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(appname) $(objects) $(LDLIBS)

depend: .depend

.depend: $(srcfiles)
	rm -f ./.depend
	$(CXX) $(CXXFLAGS) -MM $^>>./.depend;

clean:
	rm -f $(objects) $(appname)

dist-clean: clean
	rm -f *~ .depend

include .depend
