package main.java.handshake;

import java.io.*;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;

import main.java.config.CryptoConfigLoader;
import main.java.utils.FileHashUtility;

public class SHPClient {

    public static void main(String[] args) {
        if (args.length < 6) {
            System.out.println("Usage: SHPClient <host> <port> <userId> <password> <operation> <filePath>");
            return;
        }

        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String userId = args[2];
        String password = args[3];
        String operation = args[4];
        String fileName = args[5];

        try (Socket socket = new Socket(host, port)) {
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            String timestamp = Instant.now().toString(); // Current timestamp
            // String timestamp = "2024-12-12T07:51:56.779656500Z"; //for testing replay

            String configFilePath = "config/cryptoconfig.txt";
            byte[] keyBytes = loadKeyFromConfig(configFilePath);
            System.out.println("Loaded Key Bytes (Server): " + Arrays.toString(keyBytes));
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");

            System.out.println("[Client] Connected to server.");

            // Authentication
            out.writeUTF(userId);
            out.writeUTF(password);

            String authResponse = in.readUTF();
            System.out.println(authResponse);
            if (!authResponse.contains("successful")) {
                System.out.println("[Client] Authentication failed. Exiting...");
                return;
            }

            // Send operation & timestamp
            out.writeUTF(operation);
            out.writeUTF(timestamp);
            System.out.println("[Client] Sent timestamp: " + timestamp);

            out.flush();

            if (operation.equalsIgnoreCase("UPLOAD")) {
                File file = new File(fileName);
                if (!file.exists()) {
                    System.err.println("[Client] File does not exist: " + fileName);
                    return;
                }

                // send file name
                out.writeUTF(file.getName());
                System.out.println("[Client] Sending file: " + file.getName());

                // Initialize encryption cipher
                Cipher encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec gcmSpec = new GCMParameterSpec(128, hexToBytes(CryptoConfigLoader.getIV()));
                encryptionCipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

                // send file content
                try (CipherInputStream cis = new CipherInputStream(new FileInputStream(file), encryptionCipher)) {
                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    while ((bytesRead = cis.read(buffer)) != -1) {
                        out.write(buffer, 0, bytesRead);
                        System.out.println("[Client] Sent bytes: " + bytesRead);
                    }
                }
                System.out.println("[Client] Upload completed.");
            } else if (operation.equalsIgnoreCase("DOWNLOAD")) {
                System.out.println("[Client] Starting download for: " + fileName);
                out.writeUTF(fileName);

                String serverHash = in.readUTF();
                String serverResponse = in.readUTF();
                if (serverResponse.contains("File not found") || serverResponse.contains("Replay detected")) {
                    System.out.println(serverResponse);
                    return; // Exit the download operation
                }

                String saveFilePath = "files/download/" + fileName;

                // Initialize decryption cipher
                Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec gcmSpec = new GCMParameterSpec(128, hexToBytes(CryptoConfigLoader.getIV()));
                decryptionCipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

                // Receive the file from the server
                File downloadedFile = new File(saveFilePath);
                try (CipherOutputStream cos = new CipherOutputStream(new FileOutputStream(saveFilePath),
                        decryptionCipher);
                        DataInputStream dataInputStream = new DataInputStream(socket.getInputStream())) {

                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    System.out.println("[Client] Receiving file...");
                    while ((bytesRead = dataInputStream.read(buffer)) != -1) {
                        cos.write(buffer, 0, bytesRead);
                    }

                    System.out.println("[Client] File downloaded successfully: " + saveFilePath);
                    System.out.println("[Client] Received server hash: " + serverHash);

                    if (!serverHash.isEmpty()) {
                        String localHash = FileHashUtility.computeHash(downloadedFile.toPath());
                        System.out.println("[Client] Local hash: " + localHash);

                        if (localHash.equals(serverHash)) {
                            System.out.println("[Client] Hash verified successfully for: " + downloadedFile.getName());
                        } else {
                            throw new SecurityException("[Client] Hash mismatch! File integrity compromised.");
                        }
                    } else {
                        System.out.println("[Client] No hash provided by server.");
                    }
                } catch (IOException e) {
                    System.out.println("[Client] Error during download: " + e.getMessage());
                } catch (Exception e) {
                    System.out.println("[Client] Error during download: " + e.getMessage());
                }
            } else {
                System.out.println("[Client] Unsupported operation: " + operation);
            }
        } catch (IOException e) {
            System.err.println("[Client] Error: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("[Client] Error: " + e.getMessage());
        }
    }

    private static byte[] loadKeyFromConfig(String configFilePath) throws IOException {
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(configFilePath)) {
            props.load(fis);
        }
        String keyHex = props.getProperty("EncryptionKey");
        return hexToBytes(keyHex);
    }

    private static byte[] hexToBytes(String hex) {
        if (hex == null || hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Invalid hexadecimal string.");
        }

        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
