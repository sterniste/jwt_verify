#!/bin/sh
rm -f *.o
x86_64-w64-mingw32-g++ -std=c++14 -g -I ../task-list/server/ext/prefix_w64-mingw32/include -c main.cc
x86_64-w64-mingw32-g++ -std=c++14 -g -I ../task-list/server/ext/prefix_w64-mingw32/include -c base64.cc
x86_64-w64-mingw32-g++ -std=c++14 -g -I ../task-list/server/ext/prefix_w64-mingw32/include -c msg_auth_code.cc
x86_64-w64-mingw32-g++ -std=c++14 -g -I ../task-list/server/ext/prefix_w64-mingw32/include -I. -c json_web_token.cc
x86_64-w64-mingw32-g++ -std=c++14 -g -o jwt_verify *.o -L ../task-list/server/ext/prefix_w64-mingw32/lib -lssl -lcrypto -lwsock32 -lws2_32 -lcrypt32
