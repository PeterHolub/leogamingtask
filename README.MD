# LeoGaming Task Keys Tester
## Prerequisites
* **JDK >= 1.8.0_131**;
* **Apache Maven >= 3.5.2**
## Keys to Test
* src\main\resources\private.pem - private key from Task
* src\main\resources\private.pem - public key from Task
* src\main\resources\generatedFromPrivateKey.pem - public key generated by ssl from private Key from LeoGaming Task
* src\main\resources\randomPrivate.pem & randomPublic - key pair generated by ssl

## Run 
This program will test sigh validation

If signature created by Private key valid with decode by Public Key result = true

Run script for execution:
```
mvn compile
mvn exec:exec
```