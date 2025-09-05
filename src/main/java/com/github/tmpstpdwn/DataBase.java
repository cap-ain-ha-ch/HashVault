package com.github.tmpstpdwn;

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

    public void connect() throws Exception {
        File dbDir = dbDirPath.toFile();
        if (!dbDir.exists()) {
            if (!dbDir.mkdirs()) {
                System.err.println("Failed to create directory: " + dbDirPath);
            }
        }

        String url = "jdbc:sqlite:" + dbFilePath.toString();
        conn = DriverManager.getConnection(url);
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

    public void createTables() throws Exception {
        String sql1 = "CREATE TABLE IF NOT EXISTS Meta_table (" +
                     "hashed_master TEXT NOT NULL, " +
                     "login_salt TEXT NOT NULL, " +
                     "encryption_salt TEXT NOT NULL);";

        String sql2 = "CREATE TABLE IF NOT EXISTS Credential_table (" +
                     "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                     "data TEXT NOT NULL," +
                     "iv TEXT NOT NULL);";

        Statement stmt1 = conn.createStatement();
        Statement stmt2 = conn.createStatement();
        stmt1.executeUpdate(sql1);
        stmt2.executeUpdate(sql2);
    }

    public void insertMetadata(Metadata metadata) throws Exception {
        String sql = "INSERT INTO Meta_table (hashed_master, login_salt, encryption_salt) VALUES (?, ?, ?)";

        PreparedStatement pstmt = conn.prepareStatement(sql);
        pstmt.setString(1, metadata.hashedMaster());
        pstmt.setString(2, metadata.loginSalt());
        pstmt.setString(3, metadata.encryptionSalt());
        pstmt.executeUpdate();
    }

    public Metadata getMetadata() throws Exception {
        String sql = "SELECT hashed_master, login_salt, encryption_salt FROM Meta_table LIMIT 1";

        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        if (rs.next()) {
            return new Metadata(
                rs.getString("hashed_master"),
                rs.getString("login_salt"),
                rs.getString("encryption_salt")
            );
        }

        return null;
    }

    public void insertCredential(CredentialData credentialData, SecretKey key) throws Exception {
        // Serialize all fields into one JSON string
        String combined = String.format("{\"site\":\"%s\",\"username\":\"%s\",\"password\":\"%s\"}",
                                        credentialData.site().replace("\"", "\\\""),
                                        credentialData.username().replace("\"", "\\\""),
                                        credentialData.password().replace("\"", "\\\""));

        byte[] ivBytes = Vault.generateIV();
        String ivBase64 = Base64.getEncoder().encodeToString(ivBytes);

        String encryptedData = Vault.encrypt(combined, key, ivBytes);

        String sql = "INSERT INTO Credential_table (data, iv) VALUES (?, ?)";

        PreparedStatement pstmt = conn.prepareStatement(sql);
        pstmt.setString(1, encryptedData);
        pstmt.setString(2, ivBase64);
        pstmt.executeUpdate();
        System.out.println("Credentials added to the database successfully!");
    }

    public void updateCredential(CredentialRecord updatedRecord, SecretKey key) throws Exception {
        String sqlSelect = "SELECT data, iv FROM Credential_table WHERE id = ?";

        PreparedStatement selectStmt = conn.prepareStatement(sqlSelect);
        selectStmt.setInt(1, updatedRecord.id());

        ResultSet rs = selectStmt.executeQuery();
        if (!rs.next()) {
            System.out.println("Error: No credential found with id " + updatedRecord.id());
            return;
        }

        String encryptedData = rs.getString("data");
        String ivBase64 = rs.getString("iv");
        byte[] iv = Base64.getDecoder().decode(ivBase64);

        String decryptedJson = Vault.decrypt(encryptedData, key, iv);
        String currentSite = extractJsonValue(decryptedJson, "site");
        String currentUsername = extractJsonValue(decryptedJson, "username");
        String currentPassword = extractJsonValue(decryptedJson, "password");

        String newSite = updatedRecord.site().equals("_") ? currentSite : updatedRecord.site();
        String newUsername = updatedRecord.username().equals("_") ? currentUsername : updatedRecord.username();
        String newPassword = updatedRecord.password().equals("_") ? currentPassword : updatedRecord.password();

        String combined = String.format("{\"site\":\"%s\",\"username\":\"%s\",\"password\":\"%s\"}",
                                        newSite.replace("\"", "\\\""),
                                        newUsername.replace("\"", "\\\""),
                                        newPassword.replace("\"", "\\\""));

        byte[] newIv = Vault.generateIV();
        String newEncryptedData = Vault.encrypt(combined, key, newIv);
        String newIvBase64 = Base64.getEncoder().encodeToString(newIv);

        String sqlUpdate = "UPDATE Credential_table SET data = ?, iv = ? WHERE id = ?";

        PreparedStatement updateStmt = conn.prepareStatement(sqlUpdate);
        updateStmt.setString(1, newEncryptedData);
        updateStmt.setString(2, newIvBase64);
        updateStmt.setInt(3, updatedRecord.id());
        updateStmt.executeUpdate();
        System.out.println("Credential updated successfully.");

    }

    public  List<CredentialRecord> getAllCredentials(SecretKey key) throws Exception {
        List<CredentialRecord> credentials = new ArrayList<>();
        String sql = "SELECT * FROM Credential_table";

        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);

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

    public void close() throws Exception {
        if (conn != null) {
            conn.close();
        }
    }

}
