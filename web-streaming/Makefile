# Basilisk II Web Streaming Makefile

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -g -fPIC
LDFLAGS = -lwebsockets -lpthread

# GStreamer flags for WebRTC support
# Note: gstreamer-webrtc-1.0 is part of libgstreamer-plugins-bad1.0-dev
GST_CFLAGS = $(shell pkg-config --cflags gstreamer-1.0 gstreamer-app-1.0 gstreamer-webrtc-1.0 2>/dev/null)
GST_LIBS = $(shell pkg-config --libs gstreamer-1.0 gstreamer-app-1.0 gstreamer-webrtc-1.0 2>/dev/null)

# Directories
SERVER_DIR = server
CLIENT_DIR = client
BUILD_DIR = build

# Source files (WebSocket-based streaming)
SERVER_SRCS = $(SERVER_DIR)/websocket_server.cpp
INTEGRATION_SRCS = $(SERVER_DIR)/basilisk_integration.cpp
TEST_SERVER_SRCS = $(SERVER_DIR)/test_server.cpp

# Source files (WebRTC-based streaming)
GSTREAMER_SRCS = $(SERVER_DIR)/gstreamer_webrtc.cpp

# Object files
SERVER_OBJS = $(BUILD_DIR)/websocket_server.o
INTEGRATION_OBJS = $(BUILD_DIR)/basilisk_integration.o
TEST_SERVER_OBJS = $(BUILD_DIR)/test_server.o
GSTREAMER_OBJS = $(BUILD_DIR)/gstreamer_webrtc.o

# Targets
TEST_SERVER = $(BUILD_DIR)/test_server
TEST_GSTREAMER = $(BUILD_DIR)/test_gstreamer
STATIC_LIB = $(BUILD_DIR)/libwebstreaming.a
SHARED_LIB = $(BUILD_DIR)/libwebstreaming.so
STATIC_LIB_WEBRTC = $(BUILD_DIR)/libwebrtcstreaming.a

# Default target
all: dirs $(TEST_SERVER) $(STATIC_LIB)

# Create build directory
dirs:
	@mkdir -p $(BUILD_DIR)

# Test server (WebSocket)
$(TEST_SERVER): $(SERVER_OBJS) $(TEST_SERVER_OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS)

# Static library for linking with Basilisk II (WebSocket version)
$(STATIC_LIB): $(SERVER_OBJS) $(INTEGRATION_OBJS)
	ar rcs $@ $^

# Shared library (alternative)
$(SHARED_LIB): $(SERVER_OBJS) $(INTEGRATION_OBJS)
	$(CXX) -shared -o $@ $^ $(LDFLAGS)

# Static library for WebRTC version
$(STATIC_LIB_WEBRTC): $(GSTREAMER_OBJS)
	ar rcs $@ $^

# Compile server sources (WebSocket)
$(BUILD_DIR)/websocket_server.o: $(SERVER_DIR)/websocket_server.cpp $(SERVER_DIR)/websocket_server.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/basilisk_integration.o: $(SERVER_DIR)/basilisk_integration.cpp $(SERVER_DIR)/basilisk_integration.h $(SERVER_DIR)/websocket_server.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/test_server.o: $(SERVER_DIR)/test_server.cpp $(SERVER_DIR)/websocket_server.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Compile GStreamer WebRTC source
$(BUILD_DIR)/gstreamer_webrtc.o: $(SERVER_DIR)/gstreamer_webrtc.cpp $(SERVER_DIR)/gstreamer_webrtc.h
	$(CXX) $(CXXFLAGS) $(GST_CFLAGS) -c $< -o $@

# Test harness for GStreamer WebRTC
$(BUILD_DIR)/test_gstreamer.o: $(SERVER_DIR)/test_gstreamer.cpp $(SERVER_DIR)/gstreamer_webrtc.h
	$(CXX) $(CXXFLAGS) $(GST_CFLAGS) -c $< -o $@

$(TEST_GSTREAMER): $(GSTREAMER_OBJS) $(BUILD_DIR)/test_gstreamer.o
	$(CXX) -o $@ $^ $(GST_LIBS) -lpthread

# Run test server (WebSocket)
run: $(TEST_SERVER)
	./$(BUILD_DIR)/test_server -p 8090

# Run test server (WebRTC)
run-webrtc: $(TEST_GSTREAMER)
	./$(BUILD_DIR)/test_gstreamer

# Serve client files (requires Python)
serve-client:
	@echo "Starting HTTP server for client files on port 8000..."
	@echo "Open http://localhost:8000 in your browser"
	cd $(CLIENT_DIR) && python3 -m http.server 8000

# Clean build files
clean:
	rm -rf $(BUILD_DIR)

# Install library to system (for Basilisk II to link against)
install: $(STATIC_LIB) $(STATIC_LIB_WEBRTC)
	@mkdir -p /usr/local/lib /usr/local/include/webstreaming
	cp $(STATIC_LIB) /usr/local/lib/
	cp $(STATIC_LIB_WEBRTC) /usr/local/lib/
	cp $(SERVER_DIR)/basilisk_integration.h /usr/local/include/webstreaming/
	cp $(SERVER_DIR)/websocket_server.h /usr/local/include/webstreaming/
	cp $(SERVER_DIR)/gstreamer_webrtc.h /usr/local/include/webstreaming/

# Install dependencies (Ubuntu/Debian)
deps:
	sudo apt-get install -y libwebsockets-dev

# Install WebRTC dependencies (Ubuntu/Debian)
deps-webrtc:
	sudo apt-get install -y \
		gstreamer1.0-tools \
		gstreamer1.0-plugins-base \
		gstreamer1.0-plugins-good \
		gstreamer1.0-plugins-bad \
		libgstreamer1.0-dev \
		libgstreamer-plugins-base1.0-dev \
		libgstreamer-plugins-bad1.0-dev
	@echo ""
	@echo "NOTE: You also need gst-plugins-rs for webrtcsink:"
	@echo "  Ubuntu 24.04+: sudo apt install gstreamer1.0-plugins-rs"
	@echo "  Or build from: https://gitlab.freedesktop.org/gstreamer/gst-plugins-rs"

# Check if WebRTC dependencies are available
check-webrtc:
	@echo "Checking GStreamer..."
	@pkg-config --exists gstreamer-1.0 && echo "  gstreamer-1.0: OK" || echo "  gstreamer-1.0: MISSING"
	@pkg-config --exists gstreamer-app-1.0 && echo "  gstreamer-app-1.0: OK" || echo "  gstreamer-app-1.0: MISSING"
	@pkg-config --exists gstreamer-webrtc-1.0 && echo "  gstreamer-webrtc-1.0: OK" || echo "  gstreamer-webrtc-1.0: MISSING (install libgstreamer-plugins-bad1.0-dev)"
	@echo "Checking webrtcsink plugin..."
	@gst-inspect-1.0 webrtcsink >/dev/null 2>&1 && echo "  webrtcsink: OK" || echo "  webrtcsink: MISSING (install gst-plugins-rs)"

# Help
help:
	@echo "Basilisk II Web Streaming Build System"
	@echo ""
	@echo "WebSocket Streaming Targets:"
	@echo "  all          - Build WebSocket streaming (default)"
	@echo "  lib          - Build static library for Basilisk II integration"
	@echo "  run          - Build and run test server on port 8090"
	@echo "  serve-client - Serve client files via HTTP on port 8000"
	@echo ""
	@echo "WebRTC Streaming Targets:"
	@echo "  webrtc       - Build WebRTC streaming library"
	@echo "  test_gstreamer - Build WebRTC test harness"
	@echo "  run-webrtc   - Run WebRTC test server"
	@echo "  check-webrtc - Check WebRTC dependencies"
	@echo "  deps-webrtc  - Install WebRTC dependencies"
	@echo ""
	@echo "Common Targets:"
	@echo "  install      - Install libraries to /usr/local"
	@echo "  clean        - Remove build files"
	@echo "  deps         - Install WebSocket dependencies"
	@echo "  help         - Show this help"
	@echo ""
	@echo "Usage (WebSocket):"
	@echo "  1. Build: make"
	@echo "  2. Run test server: make run"
	@echo "  3. In another terminal: make serve-client"
	@echo "  4. Open http://localhost:8000 in browser"
	@echo ""
	@echo "Usage (WebRTC):"
	@echo "  1. Install deps: make deps-webrtc"
	@echo "  2. Check deps: make check-webrtc"
	@echo "  3. Build: make webrtc"
	@echo "  4. Run: make run-webrtc"
	@echo "  5. Open http://localhost:8000/index_webrtc.html in browser"
	@echo ""
	@echo "For Basilisk II integration:"
	@echo "  WebSocket: Link with -L$(BUILD_DIR) -lwebstreaming -lwebsockets"
	@echo "  WebRTC:    Link with -L$(BUILD_DIR) -lwebrtcstreaming $(GST_LIBS)"

lib: dirs $(STATIC_LIB)

webrtc: dirs $(STATIC_LIB_WEBRTC)

test_gstreamer: dirs $(TEST_GSTREAMER)

.PHONY: all dirs run run-webrtc serve-client clean deps deps-webrtc check-webrtc help lib webrtc test_gstreamer install
