# linux_hfs
##### 2024-12-02
##### now I add a new file, based on multi-processing model.
#####
##### brief
###### a http file server runs on linux. written in C++11 with linux raw socket.
##### compile with
###### g++ hfs.cpp -std=c++11 -l pthread -O3 -o hfs
##### usage
###### ./hfs 8039 /home/my_dir
##### why I write this
###### this server is used to seek my raspberrypi device's file lists though web browser.
##### other things
###### this program uses multi-thread mode with a simple thread-pool, uses the tinyhttpd way to parse the http request, and deal with some signals. the file transport is based on transfer-encoding: chunked. this server supports multipart/form-data to upload your own file.
![image](https://github.com/user-attachments/assets/bb6a48df-d67b-48a4-9bf6-d58827d44891)

