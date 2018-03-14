AUTOMAKE_OPTIONS = subdir-objects
lib@PACKAGE_NAME@_@PACKAGE_VERSION@_la_includedir = $(includedir)/@PACKAGE_NAME@-@PACKAGE_VERSION@

lib_LTLIBRARIES=lib@PACKAGE_NAME@-@PACKAGE_VERSION@.la

lib@PACKAGE_NAME@_@PACKAGE_VERSION@_la_SOURCES=\
CryptoAPI.c \
mac/ghash.c \
mode/ctr.c \
mode/ecb.c \
mode/gcm.c \
padding/nullpadding.c \
padding/pkcs7padding.c \
symmetric/aes.c \
util/cryptoutil.c \
util/secureutil.c

nobase_lib@PACKAGE_NAME@_@PACKAGE_VERSION@_la_include_HEADERS=\
CryptoAPI.h
