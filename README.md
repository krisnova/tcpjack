# TCP Jack

Hijack established TCP connections.

Send data over existing TCP connections.
Perform analysis of routing topology using established TCP connections.

### Installing 

``` 
// TODO
```


### Example Hijacking a TCP connection

The following example shows how to hijack an existing TCP connection using the `-j` flag.
`tcpjack` will use `ptrace` to briefly interrupt the client with the specified inode.
During the interruption, `tcpjack` will steal the established connection's open file descriptor.
After the file descriptor has been copied, the process resumes normal processing.
The newly copied file descriptor is used to create a spoofed client over the same connection as the original.

```bash
# Terminal 1
ncat -l 9074

# Terminal 2 
ncat localhost 9074

# Terminal 3 
tcpjack -l | grep ncat 
  ncat   9321  72294 127.0.0.1:48434 ->  127.0.0.1:9074 
  ncat   9237  76747  127.0.0.1:9074 -> 127.0.0.1:48434 
echo "PAYLOAD" | sudo tcpjack -j 72294
```
