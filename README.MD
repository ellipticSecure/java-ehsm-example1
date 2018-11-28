### This example demonstrates how to use the eHSM Hardware Security Module to do elliptic curve cryptography.

For updated documentation, see [the how-to](https://www.ellipticsecure.com/ehsm/how-to/2018/11/28/ehsm-java-ecc-example.html).
#### Prerequisites: an initialized eHSM with a user password set.

##### Note: edit ehsm.cfg to ensure that the path to the eHSM pkcs11 shared library is correct.

#### Test instructions
1. mvn package
2. java -jar target/ehsm-example-1-1.0-jar-with-dependencies.jar "user password"

