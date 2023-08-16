# StationSniffer
[![Build Status](https://gitlab.com/prpl-foundation/prplmesh/stationSniffer/badges/master/pipeline.svg)](https://gitlab.com/prpl-foundation/prplmesh/stationSniffer/pipelines)

## Userspace process for sniffing and serving Unassociated Station Link Metrics Statistics

[[_TOC_]]
### **Building**

You'll need a C++ compiler, `libpcap`, `libradiotap`, and `libnl-dev`

```apt install libpcap-dev```

```apt install libnl-3-dev```

To build and install `libradiotap`:

```
git clone git@github.com:radiotap/radiotap-library.git;
cd radiotap-library;
mkdir -p build;
cd build;
cmake ..;
make && make install
```

Then, to build `station-sniffer`:

```make```

### **Running**

`station-sniffer` requires a promiscuous mode interface as an argument.
If you've got one in mind, use it. If you want to make one, [see "Creating a virtual interface using `iw`"](#creating-a-virtual-interface-using-iw)

Otherwise, run:

```./station-sniffer <interface_name>```


### **Creating a virtual interface using `iw`**

```iw phy <your_phy> interface add <virtual_monitor_interface_name> type monitor```

To find `<your_phy>`, run ```iw dev``` and pick one.

### **Fetching station statistics**

`station-sniffer` has a Unix domain socket server thread running to serve clients. It's found at `/tmp/uslm_socket`

The client should connect to this (stream) socket and make requests there. Requests are made via a minimal binary protocol, the format of which [can be found in messages.h](https://gitlab.com/prpl-foundation/prplmesh/stationsniffer/-/blob/feature/un_sock_ipc/messages.h)

There is a reference client implementation in `tools/test.py` (Python) and `tools/uds_client.c` (C)

### **Contributing**

See `CONTRIBUTING.md` for more details.

### **License**

Distributed under the FreeBSD License. See `LICENSE` for more details.

### **Contact**

```
t.polomik at cablelabs.com
tuckerpo at (buffalo.edu | fsf.org)
```
