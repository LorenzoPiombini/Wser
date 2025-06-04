# Wser - HTTP server 

the idea is to have an http server plug and play, no configurations need it, at least for development.  
the server uses NON-BLOCKING sockets and the events on the sockets file descriptor are monitored   
with EPOLL, which is platform specific,so this version of Wser is for Linux only .

if you dont have root privileges the program will try  
to listen on port 8080, if you run wser with super user privileges it will listen  
to incoming connections to port 80.

a message stating the port where the server is listening to will be displaied to  the console.

based on your user permission wser will create a www directory, if yiu are root it will be at the '/' level whereas if you are running the program   
as a regular user the www directory will be placed on your home directory. 

to serve the website you have to put your .html .css .js images and so on inside the www directory. 

upon first execution wser will place a very basic index.html file inside ./www 
## Base HTTP version supported
---
HTTP/1.1 is the default version.



