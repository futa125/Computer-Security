#!/usr/bin/env bash

init_output=$(./password_manager.py init mAsterPasswrd)
init_hash=$(echo "$init_output" | cut -d ":" -f2 | tr -d " ")
echo "$init_output"

put_output=$(./password_manager.py put mAsterPasswrd www.fer.hr neprobojnAsifrA "$init_hash")
put_hash=$(echo "$put_output" | cut -d ":" -f2 | tr -d " ")
echo "$put_output"

get_output=$(./password_manager.py get mAsterPasswrd www.fer.hr "$put_hash")
echo "$get_output"
