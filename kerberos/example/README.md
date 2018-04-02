# What it does

This application illustrates how to use the library ma-communication. It shows
a scenario where the application invokes the [Auth](https://github.com/dojot/auth) API.

# How to build

Make sure you have all needed tools to build. On ubuntu, that would mean having the following installed:
- build-essential
- autoconf
- libtool
- pkg-config
- libcurl

To install those (on ubuntu, tested on 16.04)

```sh
sudo apt-get install -y build-essential autoconf libtool libcurl4-openssl-dev pkg-config
```

Having those installed:

```sh
export PKG_CONFIG_PATH=<install path>/share/pkgconfig
./autogen.sh --prefix
make all
```

Notice that for this component to be built, `libaes` and `libma-communication` have to be installed already (most likely under `<install path>`).

The library `libjson-c` can be obteded [here](https://github.com/json-c/json-c).

# How to run

First, you need to register the application:
```sh
./register_application.sh
```

After it, just execute the application:
```sh
./src/exampleApp.run
```

