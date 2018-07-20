package io.github.lucasduete.sgd.extractPublicKey;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class Main {

    private static final String ALIAS = "myRsaKeys";
    private static final String PASSWORD = "2049683517";
    private static final String KEYSTORAGE_NAME = "keystorage.rsa";

    public static void main(String[] args) throws Exception {
        System.out.printf("\n\n");
        PublicKey key = getPublicKey();

        savePublicKey(key);

        System.out.println("Verificação de integridade da chave exportada" + test());
    }

    private static PublicKey getPublicKey() throws Exception {
        return getKeyStore().getCertificate(ALIAS).getPublicKey();
    }


    private static KeyStore getKeyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");

        try (InputStream keyStoreData = new FileInputStream(KEYSTORAGE_NAME)) {
            keyStore.load(keyStoreData, PASSWORD.toCharArray());
        }

        return keyStore;
    }

    private static void savePublicKey(PublicKey key) throws Exception {
        try (OutputStream outputStream = new FileOutputStream("lucasduete.pub")) {
            outputStream.write(key.getEncoded());
        }

        System.out.println("Chave Salva");
    }

    private static boolean test() throws Exception {
        byte[] keyByte = Files.readAllBytes(Paths.get("lucasduete.pub"));

        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyByte));

        boolean keyEquals = publicKey.equals(getPublicKey());
        boolean bytesEquals = Arrays.equals(keyByte, getPublicKey().getEncoded());
        boolean keyEncodedEquals = Arrays.equals(publicKey.getEncoded(), getPublicKey().getEncoded());


        return keyEquals == bytesEquals == keyEncodedEquals;
    }
}
