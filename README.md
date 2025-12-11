# Overview
This folder contains two independent programs:

**1. PortScanner:** a simple UDP scanner that probes a range of ports on an IPv4 host and prints any UDP responses.

**2. PuzzleSolver:** solves the 4-port challenge (“S.E.C.R.E.T”, “Evil”, “Checksum”, “E.X.P.S.T.N”) by discovering which port is which, completing each protocol, and performing the final knock sequence.

---

# Compiling and building
The Makefile builds both programs and places binaries in `bin/` and objects in `obj/`.

```bash
# clean all build artifacts
make clean

# build both programs
make

# build PortScanner only (two aliases)
make PortScanner
# or
make 1

# build PuzzleSolver only (two aliases)
make PuzzleSolver
# or
make 2
```

---

# Running
### Port Scanner:
```
cd bin/

./scanner <IPv4> <low_port> <high_port>
```

On success, you are supposed to get responses from 4 ports. Let's call them `<port1>`, `<port2>`, `<port3>`, and `<port4>`.

### Puzzle solver:
```bash
cd bin/

./puzzlesolver <IPv4> <port1> <port2> <port3> <port4>  # The 4 ports you got from running ./scanner

# If that fails, then you might need to run it as:
sudo ./puzzlesolver <IPv4> <port1> <port2> <port3> <port4>
```

---

# Hard-coded options

1. **```Timeouts and waits```:** 
In *include/puzzlesolver.h*:

```c++
REPLY_SEC = 1;
REPLY_USEC = 200000;
LONG_REPLY_SEC = 2;
```

And in *src/PortScanner/scanner.cpp*:
```c++
timeval tv;
tv.tv_sec = 1;
tv.tv_usec = 200000;
```

2. **```src/PuzzleSolver/secret.cpp```:** 
The usernames string appended to the first message:
```c++
message += "maximiliang23,daniele23,fridriks23";
```

3. **```src/PuzzleSolver/port_distinguisher.cpp``` & ```src/PortScanner/scanner.cpp```:**
The probe message to make it 6 bytes:
```c++
std::string message = "random";
```
