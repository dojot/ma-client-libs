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
./autogen.sh --prefix <install path>
make all install
```

Where <install path> is the path where you are keeping the installed binaries/headers of mutual authentication libs.
Notice that for this component to be built, `libaes` (available under `../libaes`) has to be installed already (most likely under `<install path>`).
