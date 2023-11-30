# CUP4

Offloading CU processing to Tofino2.

## Setup

All commands should be executed from the project's root directory.

### Step 1: Compile and start the switch program
Compile the switch program and then start it.
```
make
bash start_cup4.sh
```

### Step 2: Initialize the switch configurations
```
bash ./control/setup_ports.sh
bash ./control/setup_arp.sh
```

### Step 3: Start the offloading script
By default, UL offloading is disabled. To enable it, set the last argument to "1".
```
sudo -E SDE_INSTALL=$SDE_INSTALL PYTHONPATH=$PYTHONPATH  python3 offload.py online enp4s0f0 0
```

## TODO
1. Implement HH monitoring algorithm.
2. Implement offloading with queue pausing to minimize reordering.
3. Implement and test unoffloading procedure (eBPF).

<!-- # tofino-cu
The Tofino was used to offload the CU GTP rewrite. The offload.py script is used to offload the rewrite process to the switch by adding the rewrite rules and configuring the reigsters through grpc controls. 
Steps to run the Tofino-2b--
1> Start the switchd with --arch tf2
2> Setup the ports using port_setup.sh
3> Run bfshell and add the rules in arp_setup to the bfrt cli
4> To enable timestamping for the off-loaded case run cdf/cdf.py
5> To offload to the switch run offload.py at the end  

## offload.py 
```
sudo -E SDE_INSTALL=$SDE_INSTALL PYTHONPATH=$PYTHONPATH  python3 offload.py online enp4s0f0 0
``````` -->