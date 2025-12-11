CXX := g++
CXXFLAGS ?= -std=c++17 -O2 -g
INCDIR := include
INCLUDES := -I $(INCDIR)

ifeq ($(ASAN),1)
  CXXFLAGS += -fsanitize=address
endif
ifeq ($(DEBUG),1)
  CXXFLAGS += -ggdb
endif

SRCDIR := src
PSDIR := $(SRCDIR)/PortScanner
PZDIR := $(SRCDIR)/PuzzleSolver
OBJDIR := obj
BINDIR := bin

VPATH := $(PSDIR):$(PZDIR)

SCANNER_SRC := $(PSDIR)/scanner.cpp
SCANNER_OBJS := $(OBJDIR)/scanner.o
SCANNER_BIN := $(BINDIR)/scanner

PZ_SOURCES := $(wildcard $(PZDIR)/*.cpp)
PZ_OBJECTS := $(patsubst $(PZDIR)/%.cpp,$(OBJDIR)/%.o,$(PZ_SOURCES))
PZ_BIN := $(BINDIR)/puzzlesolver

.PHONY: all clean PortScanner PuzzleSolver 1 2

all: $(SCANNER_BIN) $(PZ_BIN)

PortScanner 1: $(SCANNER_BIN)
PuzzleSolver 2: $(PZ_BIN)

$(SCANNER_BIN): $(SCANNER_OBJS) | $(BINDIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $^ -o $@

$(PZ_BIN): $(PZ_OBJECTS) | $(BINDIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $^ -o $@

$(OBJDIR)/%.o: %.cpp | $(OBJDIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

$(OBJDIR) $(BINDIR):
	mkdir -p $@

clean:
	rm -rf $(OBJDIR) $(BINDIR)