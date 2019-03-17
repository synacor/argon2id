#!/bin/bash

# argon2id - Go password hashing utility using Argon2
# Copyright (C) 2019 Synacor, Inc.
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

LICENSE=$(cat <<EOF
/*
argon2id - Go password hashing utility using Argon2
Copyright (C) 2019 Synacor, Inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
EOF
)

for file in $(find . \! -path './.git/*' -type f -name '*.go' | xargs ack -L 'GNU General Public License'); do 
    echo "updating $file..."
    tmpfile=$(mktemp) 
    ( echo "$LICENSE" ; echo ""; cat $file ) > $tmpfile
    mv $tmpfile $file
done
