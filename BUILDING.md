### Build:

`git submodule update --init --recursive`

`cd radiotap-library; mkdir -p build; cd build; cmake ..; make`

`g++ -std=c++17 main.cpp -lpcap -lradiotap -L./radiotap-library/build/ -o pcap`

### Running:

`sudo LD_PRELOAD=./radiotap-library/build/libradiotap.so ./pcap <interface>`