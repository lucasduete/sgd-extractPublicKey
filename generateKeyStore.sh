#!bin/sh

rm -f keystorage.rsa

keytool -genkeypair \
    -alias myRsaKeys \
    -keyalg RSA \
    -keysize 2048 \
    -dname "CN=Lucas Duete, OU=lucasduete, O=lucasduete, L=Juazeiro do Norte, ST=CE, C=BR" \
    -keypass 2049683517 \
    -validity 360 \
    -storetype JKS \
    -keystore keystorage.rsa \
    -storepass 2049683517
