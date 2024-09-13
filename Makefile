# Makefile to save some time

BUILD_DIR:=build

.PHONY: release debug clean

all: release

create_build:
	@mkdir -p $(BUILD_DIR)

release: create_build
	@cd $(BUILD_DIR); cmake ..;
	@$(MAKE) -C $(BUILD_DIR)

debug: create_build
	@cd $(BUILD_DIR); cmake -DCMAKE_BUILD_TYPE=Debug ..;
	@$(MAKE) -C $(BUILD_DIR)

clean:
	@rm -rf $(BUILD_DIR)
