## Stub code test

### Compile
```sh
make
```

### Test
_Note_: sr can be only run inside CS department network. So need to
ssh into lectura.
```sh
./sr -t 319
```

outputs:
```
Using VNS sr stub code revised 2010-01-21 (rev 0.23)
Loading routing table

Iface Mask Gateway Destination
0.0.0.0 172.29.10.105 0.0.0.0 eth0
172.29.10.96 0.0.0.0 255.255.255.248 eth1
172.29.10.112 0.0.0.0 255.255.255.248 eth2

Client shuoyang connecting to Server 171.67.71.18:3250
Requesting topology 319
Virtual Network Lab, connection open
/home/vnl/topo/319.sh: line 251: kill: (10881) - No such process
successfully authenticated as shuoyang
Router interfaces:
eth0 HWaddr32:0b:75:04:d5:71
     inet addr 172.29.10.104
eth1 HWaddr32:7b:76:17:39:5a
     inet addr 172.29.10.102
eth2 HWaddra2:c8:fc:c8:d3:6e
     inet addr 172.29.10.118
 <-- Ready to process packets -->
 *** -> Received packet of length 42
 *** -> Received packet of length 42
 *** -> Received packet of length 42
 *** -> Received packet of length 42
 *** -> Received packet of length 42
 *** -> Received packet of length 42
 *** -> Received packet of length 42
 *** -> Received packet of length 42
 *** -> Received packet of length 42
 *** -> Received packet of length 42
 *** -> Received packet of length 42
 *** -> Received packet of length 42
 *** -> Received packet of length 42
 *** -> Received packet of length 42
 *** -> Received packet of length 42
```

The received packet is caused by pinging eth0, just open another
terminal and ```ping 172.29.10.104```.
