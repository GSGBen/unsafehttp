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