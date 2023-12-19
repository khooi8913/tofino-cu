all:
	$(HOME)/tools/p4_build.sh ./p4src/hw/cu.p4 --with-tofino2

tf1:
	$(HOME)/tools/p4_build.sh ./p4src/hw/cu.p4 