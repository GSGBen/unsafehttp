# unsafehttp

Minimal HTTP server implementation written in C, to practice C, \*nix socket programming,
C compilation.

## Building

Prereqs: standard gcc/buildtools things.

### Dev / testing

Has ASAN and other debugging/testing options enabled.

```sh
make build-dev
```

### Release / production

```sh
make build-rel
```

## Running

Builds and runs the dev version.

```sh
make run
# or to pass args
make run ARGS="args here passed to unsafehttp"
```

## Viewing HTTP request formats

If you use `print_buffer()` on received data, you can get a good overview of request structures using

```sh
make run | batcat --show-all --pager=never
```

Here are some examples when connecting with netcat, curl and Chrome:

![client request examples](doc/img/request_examples.png).