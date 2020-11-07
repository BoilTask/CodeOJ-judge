#!/bin/bash
apt-get update
apt-get install -y subversion
/usr/sbin/useradd -m -u 1536 judge
cd /home/judge/

# svn co https://github.com/BoilTask/Codeoj-judge/src src
# svn co https://github.com/BoilTask/Codeoj-judge/etc etc

apt-get install -y make flex g++ clang libmysqlclient-dev libmysql++-dev openjdk-11-jdk fp-compiler

mkdir etc data log backup