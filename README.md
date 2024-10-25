# linux_hfs
##### brief
###### a http file server runs on linux. written in C++11 with linux raw socket.
##### compile with
###### g++ hfs.cpp -std=c++11 -l pthread -O3 -o hfs
##### usage
###### ./hfs 8039 /home/my_dir
##### why I write this
###### this server is used to seek my raspberrypi device's file lists though web browser.
##### other things
###### this program uses multi-thread mode with a simple thread-pool, uses the tinyhttpd way to parse the http request, and deal with some signals. the file transport is based on transfer-encoding: chunked. this server supports multipart/form-data
![image](https://github.com/user-attachments/assets/59af40c7-d516-4783-92de-ca57da2b83a7)
