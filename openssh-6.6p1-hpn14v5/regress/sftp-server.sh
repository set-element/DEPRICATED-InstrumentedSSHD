#!/bin/sh
exec /home/scottc/development/openssh-6.6p1/sftp-server -el debug3 -p realpath,stat,lstat 2>/home/scottc/development/openssh-6.6p1/regress/sftp-server.log
