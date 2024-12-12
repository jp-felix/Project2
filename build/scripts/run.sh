#!/bin/bash
if [ "$1" == "server" ]; then
    java -cp out main.java.handshake.SHPServer
elif [ "$1" == "client" ]; then
    java -cp out main.java.handshake.SHPClient "${@:2}"
else
    echo "Uso: ./run.sh [server|client] [args...]"
fi
