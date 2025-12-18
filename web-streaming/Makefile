# Basilisk II Web Streaming Makefile

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -g -fPIC
LDFLAGS = -lwebsockets -lpthread

# Directories
SERVER_DIR = server
CLIENT_DIR = client
BUILD_DIR = build

# Source files
SERVER_SRCS = $(SERVER_DIR)/websocket_server.cpp
INTEGRATION_SRCS = $(SERVER_DIR)/basilisk_integration.cpp
TEST_SERVER_SRCS = $(SERVER_DIR)/test_server.cpp

# Object files
SERVER_OBJS = $(BUILD_DIR)/websocket_server.o
INTEGRATION_OBJS = $(BUILD_DIR)/basilisk_integration.o
TEST_SERVER_OBJS = $(BUILD_DIR)/test_server.o

# Targets
TEST_SERVER = $(BUILD_DIR)/test_server
STATIC_LIB = $(BUILD_DIR)/libwebstreaming.a
SHARED_LIB = $(BUILD_DIR)/libwebstreaming.so

# Default target
all: dirs $(TEST_SERVER) $(STATIC_LIB)

# Create build directory
dirs:
	@mkdir -p $(BUILD_DIR)

# Test server
$(TEST_SERVER): $(SERVER_OBJS) $(TEST_SERVER_OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS)

# Static library for linking with Basilisk II
$(STATIC_LIB): $(SERVER_OBJS) $(INTEGRATION_OBJS)
	ar rcs $@ $^

# Shared library (alternative)
$(SHARED_LIB): $(SERVER_OBJS) $(INTEGRATION_OBJS)
	$(CXX) -shared -o $@ $^ $(LDFLAGS)

# Compile server sources
$(BUILD_DIR)/websocket_server.o: $(SERVER_DIR)/websocket_server.cpp $(SERVER_DIR)/websocket_server.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/basilisk_integration.o: $(SERVER_DIR)/basilisk_integration.cpp $(SERVER_DIR)/basilisk_integration.h $(SERVER_DIR)/websocket_server.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/test_server.o: $(SERVER_DIR)/test_server.cpp $(SERVER_DIR)/websocket_server.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Run test server
run: $(TEST_SERVER)
	./$(BUILD_DIR)/test_server -p 8090

# Serve client files (requires Python)
serve-client:
	@echo "Starting HTTP server for client files on port 8000..."
	@echo "Open http://localhost:8000 in your browser"
	cd $(CLIENT_DIR) && python3 -m http.server 8000

# Clean build files
clean:
	rm -rf $(BUILD_DIR)

# Install library to system (for Basilisk II to link against)
install: $(STATIC_LIB)
	@mkdir -p /usr/local/lib /usr/local/include/webstreaming
	cp $(STATIC_LIB) /usr/local/lib/
	cp $(SERVER_DIR)/basilisk_integration.h /usr/local/include/webstreaming/
	cp $(SERVER_DIR)/websocket_server.h /usr/local/include/webstreaming/

# Install dependencies (Ubuntu/Debian)
deps:
	sudo apt-get install -y libwebsockets-dev

# Help
help:
	@echo "Basilisk II Web Streaming Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build everything (default)"
	@echo "  lib          - Build static library for Basilisk II integration"
	@echo "  run          - Build and run test server on port 8090"
	@echo "  serve-client - Serve client files via HTTP on port 8000"
	@echo "  install      - Install library to /usr/local"
	@echo "  clean        - Remove build files"
	@echo "  deps         - Install dependencies"
	@echo "  help         - Show this help"
	@echo ""
	@echo "Usage:"
	@echo "  1. Build: make"
	@echo "  2. Run test server: make run"
	@echo "  3. In another terminal: make serve-client"
	@echo "  4. Open http://localhost:8000 in browser"
	@echo ""
	@echo "For Basilisk II integration:"
	@echo "  1. make lib"
	@echo "  2. Link with -L$(BUILD_DIR) -lwebstreaming -lwebsockets"

lib: dirs $(STATIC_LIB)

.PHONY: all dirs run serve-client clean deps help lib install
