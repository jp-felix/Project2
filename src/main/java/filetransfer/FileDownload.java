package main.java.filetransfer;

import java.io.*;
import java.net.Socket;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.GCMParameterSpec;
import java.security.Key;

public class FileDownload {
    private final Socket clientSocket;
    private final String downloadDirectory;
    private final Cipher decryptionCipher;

    public FileDownload(Socket clientSocket, String downloadDirectory, Key encryptionKey, byte[] iv) throws Exception {
        this.clientSocket = clientSocket;
        this.downloadDirectory = downloadDirectory;

        // Initialize decryption cipher
        decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv); // 128-bit auth tag
        decryptionCipher.init(Cipher.DECRYPT_MODE, encryptionKey, spec);
    }

    public void downloadFile(String fileName) throws IOException {
        File fileToDownload = new File(downloadDirectory, fileName);

        if (!fileToDownload.exists() || !fileToDownload.isFile()) {
            throw new FileNotFoundException("File not found: " + fileToDownload.getAbsolutePath());
        }

        try (DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream());
                CipherInputStream cis = new CipherInputStream(new FileInputStream(fileToDownload), decryptionCipher)) {

            out.writeUTF("START_DOWNLOAD");
            out.writeUTF(fileToDownload.getName());

            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = cis.read(buffer)) != -1) {
                out.write(buffer);
                out.flush();
            }
            System.out.println("[Server] File sent successfully: " + fileToDownload.getName());
        } catch (Exception e) {
            System.err.println("[Server] Error sending file: " + e.getMessage());
            throw new IOException(e);
        }
    }
}
