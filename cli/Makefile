TARGET := firewall
INCLUDES := -I. -I./include
SRCS = tools.c handle.c netlink.c kernel.c main.c
CC := gcc
OBJS = $(SRCS:.c=.o)

$(TARGET):$(OBJS)
	$(CC) -o $@ $^
	rm -rf $(SRCS:.c=.o)
%.o:%.c
	$(CC) $(INCLUDES) -o $@ -c $<

install:
	cp $(TARGET) ..

clean:
	rm -rf $(basename $(TARGET)) $(SRCS:.c=.o)