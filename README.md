memcachefile
========

A server for transferring files using memcache protocol, using key as file name, value as file content

Usage
========
```
./configure --enable-threads
make
./memcachefile -t 8     /* running with 8 workers in 8 different threads */
```
