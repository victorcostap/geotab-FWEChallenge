# Makefile to save some time

BUILD_DIR:=build

.PHONY: release compile debug test clean

all: release

create_build:
	@mkdir -p $(BUILD_DIR)

compile: release

release: create_build
	@cd $(BUILD_DIR) && cmake ..
	@$(MAKE) -C $(BUILD_DIR) --no-print-directory

debug: create_build
	@cd $(BUILD_DIR) && cmake -DCMAKE_BUILD_TYPE=Debug ..
	@$(MAKE) -C $(BUILD_DIR) --no-print-directory

test: compile
	@cd $(BUILD_DIR) && ctest -V

clean:
	@rm -rf $(BUILD_DIR)
