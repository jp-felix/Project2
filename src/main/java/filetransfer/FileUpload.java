package main.java.filetransfer;

import java.io.*;
import java.net.Socket;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

public class FileUpload {
    private final Socket clientSocket;
    private final String uploadDirectory;
    private final Cipher encryptionCipher;
    private final byte[] iv;

    public FileUpload(Socket clientSocket, String uploadDirectory, Key encryptionKey, byte[] iv) throws Exception {
        this.clientSocket = clientSocket;
        this.uploadDirectory = uploadDirectory;
        this.iv = iv;

        // Initialize encryption cipher
        encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv); // 128-bit auth tag
        encryptionCipher.init(Cipher.ENCRYPT_MODE, encryptionKey, spec);

    }

    public String uploadFile() throws IOException {
        DataInputStream in = new DataInputStream(clientSocket.getInputStream());
        String fileName = in.readUTF(); // Nome do ficheiro enviado pelo cliente
        String filePath = uploadDirectory + "/" + fileName;

        if (fileName == null || fileName.trim().isEmpty()) {
            throw new IOException("[Server] Invalid file name received.");
        }

        File file = new File(uploadDirectory, fileName);

        if (!file.getParentFile().exists() && !file.getParentFile().mkdirs()) {
            throw new IOException("[Server] Could not create directory for upload: " + file.getParent());
        }

        System.out.println("[Server] Starting to save the file: " + file.getAbsolutePath());
        try (CipherOutputStream cos = new CipherOutputStream(new FileOutputStream(filePath), encryptionCipher)) {
            System.out.println("[Server] Receiving file...");
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                cos.write(buffer, 0, bytesRead);
            }
            System.out.println("[Server] Upload complete for: " + file.getAbsolutePath());
        } catch (Exception e) {
            System.err.println("[Server] Error saving file: " + e.getMessage());
            throw new IOException(e);
        }
        return fileName; // Return the uploaded filename
    }

    public byte[] getIv() {
        return iv;
    }
}
