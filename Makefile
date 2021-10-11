BUILD_DIR := ./build
OBJS_DIR := ./obj
SRC_DIRS := ./src
TEST_DIRS := ./tests

CC := gcc
AR := ar
SRCS_FILES := sumhash512.c fips202.c
SRCS := $(SRCS_FILES:%=$(SRC_DIRS)/%)
OBJS := $(SRCS:%=$(OBJS_DIR)/%.o)
DEP := $(OBJS:%.o=%.d)

INC_FLAGS := -I. -I../include

CFLAGS := $(INC_FLAGS) -Wall -Werror -O2 -MMD -MP
ARFLAGS := rcs

MKDIR_P := mkdir -p


PHONY: all
all: $(TEST_DIRS)/test.out $(BUILD_DIR)/libsumhash.a
	$(TEST_DIRS)/test.out

$(BUILD_DIR)/libsumhash.a: $(OBJS)
	$(MKDIR_P) $(BUILD_DIR)
	$(AR) $(ARFLAGS) $@  $(OBJS) 

$(TEST_DIRS)/test.out: $(BUILD_DIR)/libsumhash.a 
	$(MKDIR_P) $(TEST_DIRS)
	$(CC) $(CFLAGS) $(TEST_DIRS)/tests.c $< -o $@

-include $(DEP)

# c source
$(OBJS_DIR)/%.c.o: %.c
	$(MKDIR_P) $(dir $@)
	$(CC)  $(CFLAGS) -c $< -o $@

.PHONY: clean

clean:
	$(RM) -r $(BUILD_DIR) $(OBJS_DIR) $(TEST_DIRS)/*.out $(TEST_DIRS)/*.d



