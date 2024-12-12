package main.java.config;

import java.io.*;
import java.util.*;

public class CryptoConfigLoader {
    private static Properties properties = new Properties();

    public CryptoConfigLoader(String filePath) throws IOException {
        try (InputStream input = new FileInputStream(filePath)) {
            properties.load(input);
        }
    }

    public String getSymmetricKey() {
        return properties.getProperty("SymmetricKey");
    }

    public String getSymmetricMode() {
        return properties.getProperty("SymmetricMode");
    }

    public int getSymmetricKeySize() {
        return Integer.parseInt(properties.getProperty("SymmetricKeySize"));
    }

    public String getHMACAlgorithm() {
        return properties.getProperty("HMAC");
    }

    public String getECCCurve() {
        return properties.getProperty("ECCCurve");
    }

    public String getHashAlgorithm() {
        return properties.getProperty("HASH");
    }

    public String getEncryptionKey() {
        return properties.getProperty("EncryptionKey");
    }

    public String getIV() {
        return properties.getProperty("IV");
    }

}
