CONFIG_STACK_VALIDATION=

ccflags-y  := -I.

obj-m += hello.o
obj-m += add-tcp-options.o


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
