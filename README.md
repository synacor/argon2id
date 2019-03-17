# argon2id - A utility for hashing passwords using argon2id

This library provides some additional functionality around [golang.org/x/crypto/argon2](https://godoc.org/golang.org/x/crypto/argon2) in order to provide a mechanism for serializing the hashed password with its salt and inputs and then a method for comparing a password against this serialized hash.

## Getting Started

```
$ go get -u github.com/synacor/argon2id
````

## Usage

```
// using sane defaults
hashedPassword, err := argon2id.DefaultHashPassword(password)
// $argon2id19$1,65536,4$366MYd8GMqu7TA1pkpzivA$CpSlS4AFCi9byh6RYPzzSMBF4ZPyKSYfT7ITzPQYLjE

// using custom input parameters
hashedPassword, err := argon2id.HashPassword(password, 1, 64*1024, 4, 32)

...

err := argon2id.Compare(hashedPassword, password)
if err == nil {
    // passwords match
} else {
    // passwords do not match
}
```

## Comamnd Line Tool

There's also a command line tool that can be installed:

```
$ go install github.com/synacor/argon2id/...
```

Then you can run it to generate hashes and compare hashes.

```
$ argon2id # user is prompted for password
# Password:<input password>
# $argon2id19$1,65536,4$5Z9wtvqXV8lL8J4YNSbmmQ$kn6Q3RZzopEcI1BreQHcVu8Jbc+Ob8XIgHEEnpieixY

$ argon2id -c '$argon2id19$1,65536,4$5Z9wtvqXV8lL8J4YNSbmmQ$kn6Q3RZzopEcI1BreQHcVu8Jbc+Ob8XIgHEEnpieixY'
# Password:<input password>
# OK - password matches hashed password

$ argon2id -c '$argon2id19$1,65536,4$5Z9wtvqXV8lL8J4YNSbmmQ$kn6Q3RZzopEcI1BreQHcVu8Jbc+Ob8XIgHEEnpieixY'
# Password:<input bad password>
# synacor/argon2id: hashedPassword is not the hash of the given password
```

For more information, see the help

```
$ argon2id -h
```
