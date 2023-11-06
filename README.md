# tofino-cu
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
```````