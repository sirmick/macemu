# Basilisk II Web Streaming Makefile

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -g -fPIC
LDFLAGS = -lpthread

# Directories
SERVER_DIR = server
CLIENT_DIR = client
BUILD_DIR = build

# libdatachannel paths
LIBDATACHANNEL_DIR = libdatachannel
LIBDATACHANNEL_BUILD = $(LIBDATACHANNEL_DIR)/build
LIBDATACHANNEL_LIB = $(LIBDATACHANNEL_BUILD)/libdatachannel.a
LIBDATACHANNEL_INCLUDES = -I$(LIBDATACHANNEL_DIR)/include

# usrsctp library - needs symbol renaming to avoid conflicts with slirp
USRSCTP_ORIG = $(LIBDATACHANNEL_BUILD)/deps/usrsctp/usrsctplib/libusrsctp.a
USRSCTP_FIXED = $(LIBDATACHANNEL_BUILD)/deps/usrsctp/usrsctplib/libusrsctp_fixed.a

# Symbols that conflict with slirp and need to be localized
CONFLICTING_SYMBOLS = ip_defttl ip_id m_adj m_cat m_free m_get socreate sofree solisten

# libvpx (system package)
VPX_CFLAGS = $(shell pkg-config --cflags vpx 2>/dev/null)
VPX_LIBS = $(shell pkg-config --libs vpx 2>/dev/null || echo "-lvpx")

# Combined flags for datachannel backend
DATACHANNEL_CFLAGS = $(LIBDATACHANNEL_INCLUDES) $(VPX_CFLAGS)
DATACHANNEL_LIBS = $(LIBDATACHANNEL_LIB) $(VPX_LIBS) -lpthread

# Source files (libdatachannel-based streaming)
DATACHANNEL_SRCS = $(SERVER_DIR)/datachannel_webrtc.cpp

# Object files
DATACHANNEL_OBJS = $(BUILD_DIR)/datachannel_webrtc.o

# Targets
STATIC_LIB_DATACHANNEL = $(BUILD_DIR)/libdatachannelstreaming.a
TEST_DATACHANNEL = $(BUILD_DIR)/test_datachannel

# Default target
all: deps-check libdatachannel dirs $(STATIC_LIB_DATACHANNEL)
	@echo ""
	@echo "Build complete!"
	@echo "Static library: $(STATIC_LIB_DATACHANNEL)"
	@echo ""
	@echo "To use with Basilisk II:"
	@echo "  cd ../BasiliskII/src/Unix"
	@echo "  ./configure --enable-webstreaming"
	@echo "  make"

# Create build directory
dirs:
	@mkdir -p $(BUILD_DIR)

# Build libdatachannel
libdatachannel: $(LIBDATACHANNEL_LIB)

$(LIBDATACHANNEL_LIB):
	@echo "Building libdatachannel..."
	@mkdir -p $(LIBDATACHANNEL_BUILD)
	cd $(LIBDATACHANNEL_BUILD) && cmake .. \
		-DCMAKE_BUILD_TYPE=Release \
		-DNO_WEBSOCKET=OFF \
		-DNO_MEDIA=OFF \
		-DNO_EXAMPLES=ON \
		-DNO_TESTS=ON \
		-DUSE_GNUTLS=OFF \
		-DUSE_MBEDTLS=OFF \
		-DUSE_NICE=OFF \
		-DBUILD_SHARED_LIBS=OFF
	$(MAKE) -C $(LIBDATACHANNEL_BUILD) -j$$(nproc)
	@echo "libdatachannel built successfully"
	@echo "Fixing usrsctp symbol conflicts with slirp..."
	@cp $(USRSCTP_ORIG) $(USRSCTP_FIXED)
	@for sym in $(CONFLICTING_SYMBOLS); do \
		objcopy --redefine-sym $$sym=__usrsctp_$$sym $(USRSCTP_FIXED); \
	done
	@echo "Symbol conflicts fixed in $(USRSCTP_FIXED)"

# Static library for libdatachannel version
$(STATIC_LIB_DATACHANNEL): $(DATACHANNEL_OBJS)
	ar rcs $@ $^

# Compile datachannel source
$(BUILD_DIR)/datachannel_webrtc.o: $(SERVER_DIR)/datachannel_webrtc.cpp $(SERVER_DIR)/datachannel_webrtc.h $(LIBDATACHANNEL_LIB)
	$(CXX) $(CXXFLAGS) $(DATACHANNEL_CFLAGS) -c $< -o $@

# Test harness for datachannel
$(BUILD_DIR)/test_datachannel.o: $(SERVER_DIR)/test_datachannel.cpp $(SERVER_DIR)/datachannel_webrtc.h
	$(CXX) $(CXXFLAGS) $(DATACHANNEL_CFLAGS) -c $< -o $@

$(TEST_DATACHANNEL): $(DATACHANNEL_OBJS) $(BUILD_DIR)/test_datachannel.o
	$(CXX) -o $@ $^ $(DATACHANNEL_LIBS)

# Run test server
run: $(TEST_DATACHANNEL)
	./$(BUILD_DIR)/test_datachannel

# Serve client files (requires Python)
serve-client:
	@echo "Starting HTTP server for client files on port 8000..."
	@echo "Open http://localhost:8000/index_datachannel.html in your browser"
	cd $(CLIENT_DIR) && python3 -m http.server 8000

# Clean build files
clean:
	rm -rf $(BUILD_DIR)

# Clean everything including libdatachannel
distclean: clean
	rm -rf $(LIBDATACHANNEL_BUILD)

# Check dependencies
deps-check:
	@echo "Checking dependencies..."
	@which cmake >/dev/null 2>&1 || (echo "ERROR: cmake not found. Install with: sudo apt install cmake" && exit 1)
	@which pkg-config >/dev/null 2>&1 || (echo "ERROR: pkg-config not found. Install with: sudo apt install pkg-config" && exit 1)
	@pkg-config --exists vpx 2>/dev/null || (echo "ERROR: libvpx not found. Install with: sudo apt install libvpx-dev" && exit 1)
	@pkg-config --exists openssl 2>/dev/null || (echo "ERROR: openssl not found. Install with: sudo apt install libssl-dev" && exit 1)
	@echo "All dependencies found!"

# Install dependencies (Ubuntu/Debian)
deps:
	sudo apt-get install -y cmake pkg-config libvpx-dev libssl-dev

# Install library and headers for Basilisk II
install: $(STATIC_LIB_DATACHANNEL) $(LIBDATACHANNEL_LIB)
	@mkdir -p /usr/local/lib /usr/local/include/datachannel
	cp $(STATIC_LIB_DATACHANNEL) /usr/local/lib/
	cp $(LIBDATACHANNEL_LIB) /usr/local/lib/
	cp -r $(LIBDATACHANNEL_DIR)/include/rtc /usr/local/include/
	cp $(SERVER_DIR)/datachannel_webrtc.h /usr/local/include/datachannel/

# Help
help:
	@echo "Basilisk II Web Streaming Build System (libdatachannel)"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build everything (default)"
	@echo "  libdatachannel - Build libdatachannel library only"
	@echo "  run          - Build and run test server"
	@echo "  serve-client - Serve client files via HTTP on port 8000"
	@echo "  clean        - Remove build files"
	@echo "  distclean    - Remove all build files including libdatachannel"
	@echo "  deps         - Install system dependencies"
	@echo "  deps-check   - Check if dependencies are installed"
	@echo "  install      - Install libraries to /usr/local"
	@echo "  help         - Show this help"
	@echo ""
	@echo "Quick Start:"
	@echo "  1. Install deps: make deps"
	@echo "  2. Build: make"
	@echo "  3. Build Basilisk II:"
	@echo "     cd ../BasiliskII/src/Unix"
	@echo "     ./configure --enable-webstreaming"
	@echo "     make"
	@echo ""
	@echo "For testing standalone:"
	@echo "  1. make run          (in one terminal)"
	@echo "  2. make serve-client (in another terminal)"
	@echo "  3. Open http://localhost:8000/index_datachannel.html"

test_datachannel: dirs libdatachannel $(TEST_DATACHANNEL)

.PHONY: all dirs run serve-client clean distclean deps deps-check help libdatachannel test_datachannel install
