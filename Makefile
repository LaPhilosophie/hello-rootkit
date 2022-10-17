TARGET=rootkit
OBJ=$(TARGET).o 
MODULE=$(TARGET).ko
obj-m+=$(OBJ)

EXTRA_CFLAGS+=-g -O0
CURRENT_PATH:=$(shell pwd)
LINUX_KERNAL:=$(shell uname -r)
LINUX_KERNAL_PATH:=/lib/modules/$(LINUX_KERNAL)/build


all:rootkit

rootkit:
	make -j $(nrpoc)-C $(LINUX_KERNAL_PATH) M=$(CURRENT_PATH) modules
install:
# 安装模块
	@sudo insmod $(CURRENT_PATH)/$(MODULE)
uninstall:
# 卸载模块
	@sudo rmmod $(CURRENT_PATH)/$(MODULE)
# @modprobe -r $(TARGET)
# @install $(MODULE) /lib/modules/$(shell uname -r)/kernel/drivers/hid
# @depmod
# @modprobe $(TARGET)
clean:
	make -C $(LINUX_KERNAL_PATH) M=$(CURRENT_PATH) clean

.PHONY:all install clean rootkit