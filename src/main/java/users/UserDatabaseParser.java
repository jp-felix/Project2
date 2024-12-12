package main.java.users;

import java.io.*;
import java.util.*;

public class UserDatabaseParser {
    private Map<String, String[]> userDatabase = new HashMap<>();

    public UserDatabaseParser(String filePath) throws IOException {
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(":");
                userDatabase.put(parts[0], Arrays.copyOfRange(parts, 1, parts.length));
            }
        }
    }

    public String[] getUserData(String username) {
        return userDatabase.get(username);
    }
}
