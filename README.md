# linux_hfs
##### a http file server runs on linux. written in C++11 with linux raw socket.
##### compile with: 
###### g++ hfs.cpp -std=c++11 -l pthread -O3 -o hfs
##### usage: 
###### ./hfs 8039 /home/my_dir
##### this server is used to seek my raspberrypi device's file lists though web browser. 
##### this program uses multi-thread mode with a simple thread-pool, uses state machine to parse the http request, and can handle some signals.
