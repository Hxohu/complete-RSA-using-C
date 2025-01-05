# 定义目标可执行文件
TARGET = RSA

# 定义源文件和头文件
SRCS = AES.c RSA.c
HEADERS = AES.h

# 定义编译器和编译选项
CC = gcc
CFLAGS = -Wall -O2

# 定义生成的对象文件
OBJS = $(SRCS:.c=.o)

# 默认目标：生成可执行文件
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

# 生成每个目标的规则
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# 清理目标
.PHONY: clean
clean:
	rm -f $(OBJS) $(TARGET)
