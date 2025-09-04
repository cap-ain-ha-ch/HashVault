import java.sql.*;
import java.io.File;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import javax.crypto.SecretKey;
import java.util.List;

class DataBase {
    private Path dbDirPath = Paths.get(System.getProperty("user.home"), ".hashvault");
    private Path dbFilePath = dbDirPath.resolve("vault.db");
    private Connection conn;

    public static record Metadata(String hashedMaster, String loginSalt, String encryptionSalt) {}
    public static record CredentialRecord(int id, String site, String username, String password, String iv) {}
    public static record CredentialData(String site, String username, String password) {}

    public void connect() {
        File dbDir = dbDirPath.toFile();
        if (!dbDir.exists()) {
            if (!dbDir.mkdirs()) {
                System.err.println("Failed to create directory: " + dbDirPath);
            }
        }

        String url = "jdbc:sqlite:" + dbFilePath.toString();

        try {
            conn = DriverManager.getConnection(url);
        } catch (SQLException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    public boolean metaTableExists() {
        String sql = "SELECT name FROM sqlite_master WHERE type='table' AND name='Meta_table';";

        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            return rs.next();
        } catch (SQLException e) {
            return false;
        }
    }

    public void createMetaTable() {
        String sql = "CREATE TABLE IF NOT EXISTS Meta_table (" +
                     "hashed_master TEXT NOT NULL, " +
                     "login_salt TEXT NOT NULL, " +
                     "encryption_salt TEXT NOT NULL);";

        try (Statement stmt = conn.createStatement()) {
            stmt.executeUpdate(sql);
        } catch (SQLException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    public void createCredentialTable() {
        String sql = "CREATE TABLE IF NOT EXISTS Credential_table (" +
                     "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                     "data TEXT NOT NULL," +  // single encrypted data field
                     "iv TEXT NOT NULL);";    // iv for the encryption

        try (Statement stmt = conn.createStatement()) {
            stmt.executeUpdate(sql);
        } catch (SQLException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    public void insertMetaData(Metadata metadata) {
        String sql = "INSERT INTO Meta_table (hashed_master, login_salt, encryption_salt) VALUES (?, ?, ?)";

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, metadata.hashedMaster());
            pstmt.setString(2, metadata.loginSalt());
            pstmt.setString(3, metadata.encryptionSalt());
            pstmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    public Metadata getMetadata() {
        String sql = "SELECT hashed_master, login_salt, encryption_salt FROM Meta_table LIMIT 1";

        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            if (rs.next()) {
                return new Metadata(
                    rs.getString("hashed_master"),
                    rs.getString("login_salt"),
                    rs.getString("encryption_salt")
                );
            }
        } catch (SQLException e) {
            e.printStackTrace();
            System.exit(1);
        }
        return null;
    }

    public void insertEncryptedCredential(CredentialData credentialData, SecretKey key) {
        try {
            // Serialize all fields into one JSON string
            String combined = String.format("{\"site\":\"%s\",\"username\":\"%s\",\"password\":\"%s\"}",
                                            credentialData.site().replace("\"", "\\\""),
                                            credentialData.username().replace("\"", "\\\""),
                                            credentialData.password().replace("\"", "\\\""));

            byte[] ivBytes = Vault.generateIV();
            String ivBase64 = Base64.getEncoder().encodeToString(ivBytes);

            String encryptedData = Vault.encrypt(combined, key, ivBytes);

            String sql = "INSERT INTO Credential_table (data, iv) VALUES (?, ?)";

            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, encryptedData);
                pstmt.setString(2, ivBase64);
                pstmt.executeUpdate();
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    public  List<CredentialRecord> getAllDecryptedCredentials(SecretKey key) {
        List<CredentialRecord> credentials = new ArrayList<>();
        String sql = "SELECT * FROM Credential_table";

        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                int id = rs.getInt("id");
                String encryptedData = rs.getString("data");
                String ivBase64 = rs.getString("iv");

                byte[] iv = Base64.getDecoder().decode(ivBase64);
                String decryptedJson = Vault.decrypt(encryptedData, key, iv);

                String site = extractJsonValue(decryptedJson, "site");
                String username = extractJsonValue(decryptedJson, "username");
                String password = extractJsonValue(decryptedJson, "password");

                credentials.add(new CredentialRecord(id, site, username, password, ivBase64));
            }

        } catch (SQLException e) {
            e.printStackTrace();
            System.exit(1);
        }

        return credentials;
    }

    private String extractJsonValue(String json, String key) {
        String pattern = String.format("\"%s\":\"", key);
        int start = json.indexOf(pattern);
        if (start == -1) return "";
        start += pattern.length();
        int end = json.indexOf("\"", start);
        if (end == -1) return "";
        return json.substring(start, end).replace("\\\"", "\"");
    }

    public void close() {
        if (conn != null) {
            try {
                conn.close();
            } catch (SQLException e) {
                e.printStackTrace();
                System.exit(1);
            }
        }
    }
}
