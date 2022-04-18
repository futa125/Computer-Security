#!/usr/bin/env bash

if ! command -v go &> /dev/null
then
    echo "Go not installed"
    exit
fi

[ -e main ] && rm main
[ -e login ] && rm login
[ -e usermanagement ] && rm usermanagement
[ -e passwords.db ] && rm passwords.db

go build ../cmd/login/login.go
go build ../cmd/usermanagement/usermanagement.go

./test.exp | sed 's/spawn //g'

[ -e main ] && rm main
[ -e login ] && rm login
[ -e usermanagement ] && rm usermanagement
[ -e passwords.db ] && rm passwords.db
