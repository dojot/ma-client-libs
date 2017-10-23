# Secure Key storage

The Application Key is received upon the application registration and grants access to the mutual authentication and crypto channel functions. After received, the key must be protected since it will be used to identify the application as legitimate. In order to do that, it is highly recomended that the application maintainer stores the key in an adequate way.

This guide presents solutions and good practices to obtain a secure key storage.

## OWASP recomendations

The [OWASP](https://www.owasp.org) is an organization focused in improving software security and have a [series of recomendations](https://www.owasp.org/index.php/Cryptographic_Storage_Cheat_Sheet) regarding cryptographic storage. In the case of key storage, some recomendations are:


> Rule - Store unencrypted keys away from the encrypted data
> If the keys are stored with the data then any compromise of the data will easily compromise the keys as well. Unencrypted keys should never reside on the same machine or cluster as the data.

> Rule - Protect keys in a key vault
> Keys should remain in a protected key vault at all times. In particular, ensure that there is a gap between the threat vectors that have direct access to the data and the threat vectors that have direct access to the keys. This implies that keys should not be stored on the application or web server (assuming that application attackers are part of the relevant threat model).

> Rule - Store a one-way and salted value of passwords
> Use PBKDF2, bcrypt or scrypt for password storage. For more information on password storage, please see the [Password Storage Cheat Sheet](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet).

## Password-Based Encryption

Password-based encryption allows the user to encrypt and decrypt data easily by just remembering a password. The algorithm performs operations with the password provided in order to derive a cryptographic key, which is then used to encrypt some data. In this case, the key derived will be used to encrypt the application key.

[PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) and [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) are the recommended algorithms to derive a key and encrypt/decrypt, respectively.

We provide an example of how this can be achieved using Python as the programing language. The example can be found in the [key_storage](./key_storage) directory.
