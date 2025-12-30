CXX     = g++
CLANG   = clang
BPFTOOL = bpftool

BPF_DIR = ebpf
BPF_SRC   = $(BPF_DIR)/xdp_prog.bpf.c
BPF_OBJ   = $(BPF_DIR)/xdp_prog.bpf.o
BPF_SKEL  = $(BPF_DIR)/xdp_prog.skel.h

USER_SRC  = main.cpp
USER_BIN  = xdp_user

BPF_CFLAGS  = -O2 -g -target bpf
USER_CFLAGS = -O2 -g
USER_LIBS   = -lbpf -lelf -lz

.PHONY: all clean

all: $(USER_BIN)

# 1. BPF to Output
$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# 2. Output to Skel
$(BPF_SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# 3. Build CPP User
$(USER_BIN): $(USER_SRC) $(BPF_SKEL)
	$(CXX) $(USER_CFLAGS) $< -o $@ $(USER_LIBS)

clean:
	rm -f $(BPF_OBJ) $(BPF_SKEL) $(USER_BIN)
