# Wser - HTTP server 

the idea is to have an http server plug and play, no configurations need it, at least for development.  
the server uses NON-BLOCKING sockets and the events on the sockets file descriptor are monitored   
with EPOLL, which platform specific, Linux.

if you dont have root privileges the program will try  
to listen on port 8080, if you run wser with super user privileges it will listen  
to incoming connections to port 80. 

a message stating the port where the server is listening to will be displaied to  
## Base HTTP version supported
---
HTTP/1.1 is the default version.

