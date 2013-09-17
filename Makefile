obj-m := sch_ccnsfq.o
sch_ccnsfq-objs := ccnsfq.o parser.o

MODNAME:= sch_ccnsfq
KDIR := /lib/modules/$(shell uname -r)
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KDIR)/build M=$(PWD) modules
install:
	mkdir -p $(KDIR)/kernel/net/sched
	cp $(MODNAME).ko $(MODNAME).o $(MODNAME).mod.c $(MODNAME).mod.o $(KDIR)/kernel/net/sched/
	depmod -a
uninstall:
	rm -f $(KDIR)/kernel/net/sched/$(MODNAME).ko

clean:
	$(MAKE) -C $(KDIR)/build M=$(PWD) clean

