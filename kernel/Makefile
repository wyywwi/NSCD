MODULE_NAME	= firewall

SRC := tools.c modules/netlink.c modules/log.c modules/rule.c modules/connection.c modules/nat.c main.c mod.c

KDIR := /lib/modules/$(shell uname -r)/build

EXTRA_CFLAGS := -I$(src)/include -I$(src)/modules

$(MODULE_NAME)-objs = $(SRC:.c=.o)
obj-m := $(MODULE_NAME).o
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	insmod $(PWD)/$(MODULE_NAME).ko
	$(MAKE) clean

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) modules clean
	rm -rf modules.order
	rm -f *.symvers
