# How to build

Make sure you have all needed tools to build. On ubuntu, that would mean having the following installed:
- build-essential
- autoconf
- libtool

To install those (on ubuntu, tested on 16.04)

```sh
sudo apt-get install -y build-essential autoconf libtool
```

Having those installed:

```sh
./autogen.sh --prefix <install path>
make all install
```
where <install path> is the path where you want to install de library
