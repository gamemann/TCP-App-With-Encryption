# TCP Application With Encryption
## Description
This application serves as a TCP client => server implementation and supports writing encrypted data. This application encrypts data from the client program (user-inputted data from `stdin`) and sends it to the server. The server then decrypts the data using the same key, tag, and nonce/IV generated from the client program and outputs the decrypted text.

Both the client and server take advantage of `Chacha20_poly1305`, a symmetric cipher. A shared key is used between the client and server. This key is located at `/etc/tcpserver/key.txt` by default. You may use the `/client/genkey.c` program to generate a key that is typically 32 bytes in size.

I wrote this application to practice Elixir and encryption. I plan to use a similar setup with my future Barricade Firewall [project](https://github.com/Barricade-FW).

## The Client
The client (`/client/client.c`) is written in C and uses a library named [Libsodium](https://libsodium.gitbook.io/doc/) for encryption and hashing.

### Command Line Options
* `--dst, -d` => The IP of the server (default is `"0.0.0.0"`).
* `--port, -p` => The port of the server (default is `3020`).
* `--key, -k` => The path to the shared key file (default is `"/etc/tcpserver/key.txt"`).

## The Server
The server (`/server/*`) is written in Elixir and uses the ErLang Crypto [module](https://erlang.org/doc/man/crypto.html) for decrypting data and hashing. The server utilizes GenServer.

### Configuration
You may configure additional settings in `/server/config/config.exs`. Here is a brief description of each:

* `ip` => The IP for the server to listen on (default is `{0, 0, 0, 0}`).
* `port` => The port for the server to listen on (default is `3020`).
* `keypath` => The path to the shared key file (default is `"/etc/tcpserver/key.txt"`).

**Note** - The `ip` setting must be a tuple containing four elements and each element represents an octet. An example is `{127, 0, 0, 1}`.

## Generating A Key
You may generate a key with the `/client/genkey.c` program.

### Command Line Options
* `--path, -p` => The path to save the file to (default is `"/etc/tcpserver/key.txt"`).

## Requirements
### Client
The client requires Libsodium to be installed on the system. Please read the installation instructions [here](https://libsodium.gitbook.io/doc/installation).

### Server
The server only requires ErLang and Elixir to be installed on the system. You shouldn't need to install anything else because we don't use any third-party dependencies. To be safe, you may execute the following:

```
cd server/
mix deps.get
```

**Note** - I installed ErLang, Elixir, and the server on a vanilla Ubuntu 20.04 VM and it ran the first time without any issues.

## Compiling
### Client and GenKey
You may use GCC to compile the client and genkey programs:

```
gcc -g client/client.c -o client -lsodium
gcc -g client/genkey.c -o genkey -lsodium
```

Please note you must link Libsodium which is done in the above via `-lsodium`.

## Running
### Client and GenKey
You can easily run the GenKey and Client programs via:

```
./genkey
...

./client
```

### Server
Running the server is simple. Please execute the following commands:

```
cd server/
iex -S mix
```

## Credits
* [Christian Deacon](https://www.linkedin.com/in/christian-deacon-902042186/) - Created application.
* [Dreae](https://github.com/Dreae/) - Helped me understand the `Chacha20_poly1305` cipher and encryption. He has been a HUGE help!