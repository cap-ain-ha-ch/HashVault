package com.github.tmpstpdwn;

import java.sql.*;
import java.io.File;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import javax.crypto.SecretKey;
import java.util.List;

// For ASCII TABLE.
import com.github.freva.asciitable.AsciiTable;
import com.github.freva.asciitable.Column;
import com.github.freva.asciitable.HorizontalAlign;

class DataBase {
    final private Path dbDirPath = Paths.get(System.getProperty("user.home"), ".hashvault");
    final private Path dbFilePath = dbDirPath.resolve("vault.db");
    private Connection conn;

    public static record Metadata(String hashedMaster, String loginSalt, String encryptionSalt) {}
    public static record CredentialRecord(int id, String target, String username, String password, String iv) {}
    public static record CredentialData(String target, String username, String password) {}

    public void connect() throws Exception {
        File dbDir = dbDirPath.toFile();
        if (!dbDir.exists()) {
            if (!dbDir.mkdirs()) {
                throw new Exception("Failed to create directory: " + dbDirPath);
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

    public void setMetadata(Metadata metadata) throws Exception {
        String checkSql = "SELECT COUNT(*) FROM Meta_table";
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(checkSql)) {
            rs.next();
            int count = rs.getInt(1);

            if (count == 0) {
                String insertSql = "INSERT INTO Meta_table (hashed_master, login_salt, encryption_salt) VALUES (?, ?, ?)";
                try (PreparedStatement pstmt = conn.prepareStatement(insertSql)) {
                    pstmt.setString(1, metadata.hashedMaster());
                    pstmt.setString(2, metadata.loginSalt());
                    pstmt.setString(3, metadata.encryptionSalt());
                    pstmt.executeUpdate();
                }
            } else {
                String updateSql = "UPDATE Meta_table SET hashed_master = ?, login_salt = ?, encryption_salt = ?";
                try (PreparedStatement pstmt = conn.prepareStatement(updateSql)) {
                    pstmt.setString(1, metadata.hashedMaster());
                    pstmt.setString(2, metadata.loginSalt());
                    pstmt.setString(3, metadata.encryptionSalt());
                    pstmt.executeUpdate();
                }
            }
        }
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

    private void insertCredential(CredentialData credentialData, SecretKey key) throws Exception {
        String combined = String.format("{\"target\":\"%s\",\"username\":\"%s\",\"password\":\"%s\"}",
                                        credentialData.target().replace("\"", "\\\""),
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
    }

    public String getPassword(CredentialData credentialData, SecretKey key) throws Exception {
        List<CredentialRecord> allCredentials = getAllCredentials(key);

        for (CredentialRecord record : allCredentials) {

            if (
            record.target().equals(credentialData.target()) &&
            record.username().equals(credentialData.username()))
            {
                return record.password();
            }
        }

        throw new Exception(
            "No credential found for target '" +
            credentialData.target() +
            "' and username '" +
            credentialData.username() +
            "'"
        );
    }

    public void insertCredentialUnique(CredentialData credentialData, SecretKey key) throws Exception {
        List<CredentialRecord> allCredentials = getAllCredentials(key);

        for (CredentialRecord record : allCredentials) {
            if (record.target().equals(credentialData.target()) && record.username().equals(credentialData.username())) {
                throw new Exception("Duplicate entry: target '" + record.target() + "' with username '" + record.username() + "' already exists.");
            }
        }

        insertCredential(credentialData, key);
    }

    public void updateCredential(CredentialRecord updatedRecord, SecretKey key) throws Exception {
        String sqlSelect = "SELECT data, iv FROM Credential_table WHERE id = ?";

        PreparedStatement selectStmt = conn.prepareStatement(sqlSelect);
        selectStmt.setInt(1, updatedRecord.id());

        ResultSet rs = selectStmt.executeQuery();
        if (!rs.next()) {
            throw new Exception("No credential found with id " + updatedRecord.id());
        }

        String encryptedData = rs.getString("data");
        String ivBase64 = rs.getString("iv");
        byte[] iv = Base64.getDecoder().decode(ivBase64);

        String decryptedJson = Vault.decrypt(encryptedData, key, iv);
        String currentTarget = extractJsonValue(decryptedJson, "target");
        String currentUsername = extractJsonValue(decryptedJson, "username");
        String currentPassword = extractJsonValue(decryptedJson, "password");

        String newTarget = updatedRecord.target().equals("_") ? currentTarget : updatedRecord.target();
        String newUsername = updatedRecord.username().equals("_") ? currentUsername : updatedRecord.username();
        String newPassword = updatedRecord.password().equals("_") ? currentPassword : updatedRecord.password();

        String combined = String.format("{\"target\":\"%s\",\"username\":\"%s\",\"password\":\"%s\"}",
                                        newTarget.replace("\"", "\\\""),
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

    }

    public void deleteCredential(int id, SecretKey key) throws Exception {
        String sql = "DELETE FROM Credential_table WHERE id = ?";
        PreparedStatement pstmt = conn.prepareStatement(sql);
        pstmt.setInt(1, id);

        int deleted = pstmt.executeUpdate();

        if (deleted == 0) {
            throw new Exception("No entry with id " + id + " found");
        }
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

            String target = extractJsonValue(decryptedJson, "target");
            String username = extractJsonValue(decryptedJson, "username");
            String password = extractJsonValue(decryptedJson, "password");

            credentials.add(new CredentialRecord(id, target, username, password, ivBase64));
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

    private void reEncryptCredential(CredentialRecord cred, SecretKey newKey) throws Exception {
        String combined = String.format("{\"target\":\"%s\",\"username\":\"%s\",\"password\":\"%s\"}",
                                        cred.target().replace("\"", "\\\""),
                                        cred.username().replace("\"", "\\\""),
                                        cred.password().replace("\"", "\\\""));

        byte[] newIv = Vault.generateIV();
        String newIvBase64 = Base64.getEncoder().encodeToString(newIv);
        String encryptedData = Vault.encrypt(combined, newKey, newIv);

        String sqlUpdate = "UPDATE Credential_table SET data = ?, iv = ? WHERE id = ?";
        PreparedStatement updateStmt = conn.prepareStatement(sqlUpdate);
        updateStmt.setString(1, encryptedData);
        updateStmt.setString(2, newIvBase64);
        updateStmt.setInt(3, cred.id());
        updateStmt.executeUpdate();
    }

    public void reEncryptDatabase(SecretKey oldKey, SecretKey newKey) throws Exception {
        List<CredentialRecord> credentials = getAllCredentials(oldKey);
        for (CredentialRecord cred : credentials) {
            reEncryptCredential(cred, newKey);
        }
    }

    public String printCredentialTable(SecretKey key) throws Exception {
        List<CredentialRecord> credentials = getAllCredentials(key);
        if (credentials.isEmpty()) {
            throw new Exception("Database empty");
        } else {
            String table = AsciiTable.getTable(credentials, List.of(
                new Column().header("ID").headerAlign(HorizontalAlign.CENTER).dataAlign(HorizontalAlign.CENTER).with(cred -> String.valueOf(cred.id())),
                new Column().header("Target").headerAlign(HorizontalAlign.CENTER).dataAlign(HorizontalAlign.CENTER).with(CredentialRecord::target),
                new Column().header("Username").headerAlign(HorizontalAlign.CENTER).dataAlign(HorizontalAlign.CENTER).with(CredentialRecord::username),
                new Column().header("Password").headerAlign(HorizontalAlign.CENTER).dataAlign(HorizontalAlign.CENTER).with(CredentialRecord::password)
            ));
            return table;
        }
    }

    public void close() throws Exception {
        if (conn != null) {
            conn.close();
        }
    }

}
