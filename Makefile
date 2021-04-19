CONFIG_STACK_VALIDATION=
obj-m += hello.o
obj-m += who-connect-me.o
obj-m += excited_virus.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
