#!/usr/bin/env bash

[ -e main ] && rm main
[ -e login ] && rm login
[ -e usermanagement ] && rm usermanagement

go build ../cmd/login/main.go && mv main login
go build ../cmd/usermanagement/main.go && mv main usermanagement

[ -e passwords.db ] && rm passwords.db

/usr/bin/expect -c '
set password 12345678

puts "Initial password: $password\r"
puts "\r"
eval spawn ./usermanagement add ivan
expect "Password: "
send "$password\r";
expect "Repeat password: "
send "$password\r";
interact
puts "\r"

eval spawn ./login ivan
expect "Password: "
send "$password\r";
interact
puts "\r"

set new_password 87654321

puts "Old password: $password\r"
puts "New password: $new_password\r"
puts "\r"
eval spawn ./usermanagement passwd ivan
expect "Password: "
send "$new_password\r";
expect "Repeat password: "
send "$new_password\r";
interact
puts "\r"

eval spawn ./login ivan
expect "Password: "
send "$new_password\r";
interact
puts "\r"

eval spawn ./usermanagement forcepass ivan
interact
puts "\r"

set password 87654321
set new_password 12345678

puts "Old password: $password\r"
puts "New password: $new_password\r"
puts "\r"
eval spawn ./login ivan
expect "Password: "
send "$password\r";
set password 12345678
expect "New password: "
send "$password\r";
expect "Repeat new password: "
send "$password\r";
interact
puts "\r"

eval spawn ./usermanagement del ivan
interact
puts "\r"

eval spawn ./login ivan
expect "Password: "
send "new_password\r";
expect "Password: "
send "new_password\r";
expect "Password: "
send "new_password\r";
expect "Password: "
send \x03
puts "\r"
interact
'

[ -e main ] && rm main
[ -e login ] && rm login
[ -e usermanagement ] && rm usermanagement

[ -e passwords.db ] && rm passwords.db
