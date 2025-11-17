# #############################
# ##  Author: Roman Krajčík  ##
# ##  Login:  xkrajc26       ##
# #############################

CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -pedantic -O2
CPPFLAGS := -Iinclude
LDFLAGS := -lpcap -lcrypto -lpthread
TARGET := secret
SRC_DIR := src
OBJ_DIR := build
TEST_DIR := tests
TEST_BIN_DIR := $(OBJ_DIR)/tests
SRCS := $(wildcard $(SRC_DIR)/*.cpp)
OBJS := $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(SRCS))
TESTS := app_config_tests crypto_tests protocol_tests receiver_reassembly_tests sender_tests
TEST_TARGETS := $(addprefix $(TEST_BIN_DIR)/,$(TESTS))

.PHONY: all clean dirs tests testclean

all: dirs $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

dirs:
	@mkdir -p $(OBJ_DIR) $(TEST_BIN_DIR)

$(TEST_BIN_DIR):
	@mkdir -p $(TEST_BIN_DIR)

tests: dirs $(TEST_TARGETS)
	@set -e; \
	for test in $(TEST_TARGETS); do \
		echo "Running $$test"; \
		$$test; \
	done

testclean:
	rm -rf $(TEST_BIN_DIR)

clean: testclean
	rm -rf $(OBJ_DIR) $(TARGET)

$(TEST_BIN_DIR)/app_config_tests: $(TEST_DIR)/app_config_tests.cpp src/app_config.cpp src/protocol.cpp | $(TEST_BIN_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_BIN_DIR)/crypto_tests: $(TEST_DIR)/crypto_tests.cpp src/crypto.cpp | $(TEST_BIN_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_BIN_DIR)/protocol_tests: $(TEST_DIR)/protocol_tests.cpp src/protocol.cpp | $(TEST_BIN_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_BIN_DIR)/receiver_reassembly_tests: $(TEST_DIR)/receiver_reassembly_tests.cpp \
	src/receiver.cpp src/protocol.cpp src/crypto.cpp src/app_config.cpp | $(TEST_BIN_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_BIN_DIR)/sender_tests: $(TEST_DIR)/sender_tests.cpp \
	src/sender.cpp src/crypto.cpp src/protocol.cpp src/app_config.cpp | $(TEST_BIN_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)
