#!/bin/bash
# Compile all Java files in the src directory
find src -name "*.java" > sources.txt
javac -d out -sourcepath src @sources.txt
echo "Compilação concluída!"
