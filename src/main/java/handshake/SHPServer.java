package main.java.handshake;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import main.java.config.CryptoConfigLoader;
import main.java.filetransfer.FileUpload;
import main.java.users.UserDatabaseParser;
import main.java.utils.FileHashUtility;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;

public class SHPServer {

    private static final Set<String> processedTimestamps = new HashSet<>();
    private static UserDatabaseParser userDatabase;
    static String uploadDirectory = "files/upload";
    static String downloadDirectory = "files/download";

    // public SHPServer() throws Exception {
    // SHPServer.encryptionKey = new
    // SecretKeySpec(loadKeyFromConfig("config/cryptoconfig.txt"), "AES");
    // }

    public static void main(String[] args) {
        int port = 8080;

        File uploadDir = new File(uploadDirectory);
        if (!uploadDir.exists()) {
            uploadDir.mkdirs(); // Create the directory if it doesn't exist
            System.out.println("[Server] Created missing upload directory: " + uploadDir.getAbsolutePath());
        }

        File downloadDir = new File(downloadDirectory);
        if (!downloadDir.exists()) {
            downloadDir.mkdirs(); // Create the directory if it doesn't exist
            System.out.println("[Server] Created missing upload directory: " + downloadDir.getAbsolutePath());
        }

        try {
            userDatabase = new UserDatabaseParser("config/userdatabase.txt");
        } catch (IOException e) {
            System.out.println("[Server] Error loading user database: " + e.getMessage());
            return;
        }

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("[Server] SHP Server is running on port " + port);

            CryptoConfigLoader loader = new CryptoConfigLoader("config/cryptoconfig.txt");
            // Load the encryption key from the config file
            byte[] keyBytes = hexToBytes(loader.getEncryptionKey());
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
            // Load the IV from the config file
            byte[] ivBytes = hexToBytes(loader.getIV());

            System.out.println("[Server] Loaded Key Bytes: " + Arrays.toString(keyBytes));
            System.out.println("[Server] Loaded IV Bytes: " + Arrays.toString(ivBytes));

            while (true) {
                try (Socket clientSocket = serverSocket.accept()) {
                    DataInputStream in = new DataInputStream(clientSocket.getInputStream());
                    DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream());

                    System.out.println("[Server] Client connected: " + clientSocket.getRemoteSocketAddress());

                    // Authentication
                    String userId = in.readUTF();
                    String providedPassword = in.readUTF();
                    System.out.println("[Server] Received userID: " + userId);
                    String[] userData = userDatabase.getUserData(userId);

                    if (userData == null || !userData[0].equals(providedPassword)) {
                        System.out.println("[Server] Authentication failed for user: " + userId);
                        out.writeUTF("[Server] Authentication failed.");
                        clientSocket.close();
                        continue; // Allow new connections
                    }

                    System.out.println("[Server] Authentication successful for user: " + userId);
                    out.writeUTF("[Server] Authentication successful.");

                    // Process client operation (UPLOAD/DOWNLOAD)
                    String operation = in.readUTF();
                    String timestamp = in.readUTF();

                    System.out.println("[Server] Requested operation: " + operation);
                    System.out.println("[Server] Received timestamp: " + timestamp);

                    if (!isValidTimestamp(timestamp)) {
                        System.out.println("[Server] Replay or expired timestamp detected.");
                        out.writeUTF("[Server] Replay detected. Request rejected.");
                        continue;
                    }

                    processedTimestamps.add(timestamp);

                    if (operation.equalsIgnoreCase("UPLOAD")) {
                        System.out.println("[Server] Starting upload...");
                        // FileUpload upload = new FileUpload(clientSocket, uploadDirectory, keySpec,
                        // ivBytes);
                        // String uploadedFileName = upload.uploadFile();

                        String uploadedFileName = in.readUTF(); // Read the filename sent by the client
                        System.out.println("[Server] Receiving file: " + uploadedFileName);

                        Path filePath = Paths.get(uploadDirectory, uploadedFileName);

                        // Initialize the decryption cipher
                        Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
                        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, ivBytes);
                        decryptionCipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

                        try (CipherInputStream cis = new CipherInputStream(clientSocket.getInputStream(),
                                decryptionCipher);
                                FileOutputStream fos = new FileOutputStream(filePath.toString())) {
                            byte[] buffer = new byte[4096];
                            int bytesRead;
                            while ((bytesRead = cis.read(buffer)) != -1) {
                                fos.write(buffer, 0, bytesRead);
                            }
                            fos.flush();
                            System.out.println("[Server] Upload complete for: " + filePath);
                        }

                        // Compute and save hash of the uploaded file
                        String hashValue = FileHashUtility.computeHash(filePath);
                        Path hashFilePath = Paths.get(filePath.toString() + ".hash");
                        Files.writeString(hashFilePath, hashValue);

                        System.out.println("[Server] Hash computed and saved for: " + uploadedFileName);

                    } else if (operation.equalsIgnoreCase("DOWNLOAD")) {
                        System.out.println("[Server] Starting download...");

                        // Receive the requested file name from the client
                        String requestedFileName = in.readUTF();
                        System.out.println("[Server] Requested file: " + requestedFileName);

                        // Check if file exists
                        String fullFilePath = uploadDirectory + "/" + requestedFileName;
                        File file = new File(fullFilePath);
                        if (!file.exists() || file.isDirectory()) {
                            System.out.println("[Server] File not found: " + fullFilePath);
                            out.writeUTF("[Server] File not found: " + fullFilePath);
                            return;
                        }

                        // Sending the hash file in SHPServer.java
                        Path hashFilePath = Paths.get(uploadDirectory, requestedFileName + ".hash");
                        if (Files.exists(hashFilePath)) {
                            String hashValue = Files.readString(hashFilePath);
                            out.writeUTF(hashValue); // Send the hash to the client
                            System.out.println("[Server] Sent hash for file: " + requestedFileName);
                        } else {
                            out.writeUTF("");
                            System.out.println("[Server] No hash file found for: " + requestedFileName);
                        }

                        // Stream the file to the client
                        out.writeUTF("[Server] File found, preparing to send.");

                        // Initialize the encryption cipher
                        Cipher encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
                        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, ivBytes);
                        encryptionCipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

                        try (FileInputStream fis = new FileInputStream(file);
                                CipherOutputStream cos = new CipherOutputStream(clientSocket.getOutputStream(),
                                        encryptionCipher)) {
                            byte[] buffer = new byte[4096];
                            int bytesRead;
                            while ((bytesRead = fis.read(buffer)) != -1) {
                                cos.write(buffer, 0, bytesRead);
                            }
                            cos.flush();

                            System.out.println("[Server] File sent successfully: " + requestedFileName);
                        }
                    } else {
                        System.out.println("[Server] Invalid operation.");
                    }
                } catch (IOException e) {
                    System.err.println("[Server] Error handling client: " + e.getMessage());
                } catch (Exception e) {
                    System.err.println("[Server] Error handling client: " + e.getMessage());
                }
            }
        } catch (

        IOException e) {
            System.err.println("[Server] Server error: " + e.getMessage());
        }
    }

    private static boolean isValidTimestamp(String timestamp) {
        try {
            Instant received = Instant.parse(timestamp);
            Instant now = Instant.now();

            if (Duration.between(received, now).toMinutes() > 5 || processedTimestamps.contains(timestamp)) {
                return false;
            }
            return true;
        } catch (Exception e) {
            return false;
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
        // if (hex == null || hex.length() % 2 != 0) {
        // throw new IllegalArgumentException("Invalid hexadecimal string.");
        // }

        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

}
