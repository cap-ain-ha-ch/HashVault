package com.github.tmpstpdwn;

import java.sql.*;

import java.io.File;
import java.nio.file.Paths;
import java.nio.file.Path;

import java.util.Base64;
import javax.crypto.SecretKey;

import java.util.List;
import java.util.ArrayList;

import org.json.JSONObject;

import com.github.freva.asciitable.AsciiTable;
import com.github.freva.asciitable.Column;
import com.github.freva.asciitable.HorizontalAlign;

class DataBase {

    // Records representing entries for metadata, credentialdata table.
    // used to pass entry data to and from functions in a more compact way.
    public static record Metadata(byte[] masterKey, byte[] loginSalt, byte[] encryptionSalt) {}
    public static record CredentialData(int id, String target, String username, String password) {}

    // Constructing path to the database file.
    final private Path dbDirPath = Paths.get(System.getProperty("user.home"), ".hashvault");
    final private Path dbFilePath = dbDirPath.resolve("vault.db");

    // object representing sql lite database connection.
    private Connection conn;

    /*
    CONNECT
    -------
    -> Establishes connection to the database using constructed path.
    -> If database file doesnt exist, it creates one and connects to it.
    */
    public void connect() throws Exception {
        // Creating directory which contains database file if it doesnt already exist.
        File dbDir = dbDirPath.toFile();
        if (!dbDir.exists()) {
            if (!dbDir.mkdirs()) {
                throw new Exception("Failed to create directory: " + dbDirPath);
            }
        }

        String url = "jdbc:sqlite:" + dbFilePath.toString();
        conn = DriverManager.getConnection(url);
    }

    /*
    METATABLEEXISTS
    ---------------
    -> Returns true if metatable table already exists, otherwise false.
    -> Absence of metatable signifies no master password has been set yet.
    */
    public boolean metaTableExists() {
        String sql = "SELECT name FROM sqlite_master WHERE type='table' AND name='meta_table';";

        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            return rs.next();
        } catch (SQLException e) {
            return false;
        }
    }

    /*
    CREATE_TABLES
    ------------
    -> Creates both metatable and crendential table if it doesnt already exist.
    -> This is used on user's first run prior to setting master password.
    -> So that all the tables required for the program is set up.
    */
    public void createTables() throws Exception {
        String metaTableSQL = """
            CREATE TABLE IF NOT EXISTS meta_table (
                master_key BLOB NOT NULL,
                login_salt BLOB NOT NULL,
                encryption_salt BLOB NOT NULL
            );
        """;

        String credentialTableSQL = """
            CREATE TABLE IF NOT EXISTS credential_table (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data BLOB NOT NULL
            );
        """;

        try (Statement stmt = conn.createStatement()) {
            stmt.executeUpdate(metaTableSQL);
            stmt.executeUpdate(credentialTableSQL);
        } catch (Exception e) {
            throw new Exception("Failed to create tables", e);
        }
    }

    /*
    SET_METADATA
    -----------
    -> Accepts a record of type MetaData containing data to be set in the metadata table.
    -> When used on an empty metatable, it inserts a new entry.
    -> Otherwise it updates the already existing entry leading to only one entry at anytime in the table.
    -> Metatable at anytime will only have one entry, which stores the current master_hash, login_salt and encryption_salt.
    */
    public void setMetadata(Metadata metadata) throws Exception {
        String checkSql = "SELECT COUNT(*) FROM meta_table";
        try (
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(checkSql)
        ) {
            // Checks whether the meta table is empty.
            rs.next();
            boolean isEmpty = rs.getInt(1) == 0;

            // If meta table is empty, set sql for insertion other wise updation.
            String sql = isEmpty
                ? "INSERT INTO meta_table (master_key, login_salt, encryption_salt) VALUES (?, ?, ?)"
                : "UPDATE meta_table SET master_key = ?, login_salt = ?, encryption_salt = ?";

            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setBytes(1, metadata.masterKey());
                pstmt.setBytes(2, metadata.loginSalt());
                pstmt.setBytes(3, metadata.encryptionSalt());
                pstmt.executeUpdate();
            }
        } catch (Exception e) {
            throw new Exception("Failed to modify meta table", e);
        }
    }

    /*
    GETMETADATA
    -----------
    -> Returns the one and only entry of metatable as a record of type MetaData.
    */
    public Metadata getMetadata() throws Exception {
        String sql = "SELECT master_key, login_salt, encryption_salt FROM meta_table LIMIT 1";

        try (
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql)
        ) {
            if (rs.next()) {
                return new Metadata(
                    rs.getBytes("master_key"),
                    rs.getBytes("login_salt"),
                    rs.getBytes("encryption_salt")
                );
            } else {
                return null;
            }
        } catch (Exception e) {
            throw new Exception("Failed to retrieve meta data", e);
        }
    }

    /*
    INSERTCREDENTIAL
    ----------------
    -> Accepts data to be inserted as a record of type CredentialData and a key to be used for encryption.
    -> Combines the credential data in to a json string. i.e "{target: github, username: abc, password: xyz}"
    -> Encrypts the json string using the provided key.
    -> Inserts the encrypted data into the credential table.
    */
    private void insertCredential(CredentialData credentialData, SecretKey key) throws Exception {
        String sql = "INSERT INTO credential_table (data) VALUES (?)";

        JSONObject newJson = new JSONObject();
        newJson.put("target", credentialData.target());
        newJson.put("username", credentialData.username());
        newJson.put("password", credentialData.password());

        String combined = newJson.toString();

        byte[] encryptedData = Vault.encrypt(combined, key);

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setBytes(1, encryptedData);
            pstmt.executeUpdate();
        } catch (Exception e) {
            throw new Exception("Failed to insert credential", e);
        }
    }

    /*
    INSERT_CREDENTIAL_UNIQUE
    ----------------------
    -> Insert a credential only if (target, username) combination doesnt already exist in the credential table.
    -> Uses 'void insertCredential(CredentialData credentialData, SecretKey key)' for insertion.
    */
    public void insertCredentialUnique(CredentialData credentialData, SecretKey key) throws Exception {
        List<CredentialData> credentials = getAllCredentials(key);

        for (CredentialData cred : credentials) {

            // Checking for uniqueness.
            if (
            cred.target().equals(credentialData.target()) &&
            cred.username().equals(credentialData.username()))
            {
                throw new Exception("Credential already exists");
            }
        }

        insertCredential(credentialData, key);
    }

    /*
    UPDATE_CREDENTIAL
    -----------------
    -> Accepts id for updation along with data to be updated with as a record of type CredentialData.
    -> Accepts key for decryption and encryption.
    -> Fetch the entry to be updated with the given id and decrypt it with key.
    -> The decrypted data is a json.
    -> A new json is constructed with values from the given CredentialData record.
    -> If the value is '_' then the new json uses previous value from the decrypted json.
    -> Once the new json is fully constructed, it is encrypted with the given key.
    -> This newly encrypted json is then used to update the entry from credential table corresponding to the given id. 
    */
    public void updateCredential(CredentialData updatedData, SecretKey key) throws Exception {
        String selectSql = "SELECT data FROM credential_table WHERE id = ?";
        String updateSql = "UPDATE credential_table SET data = ? WHERE id = ?";

        try (PreparedStatement selectStmt = conn.prepareStatement(selectSql)) {
            selectStmt.setInt(1, updatedData.id());

            try (ResultSet rs = selectStmt.executeQuery()) {
                if (!rs.next()) {
                    throw new Exception("No credential found with id " + updatedData.id());
                }

                byte[] encryptedData = rs.getBytes("data");
                String decryptedJson = Vault.decrypt(encryptedData, key);

                JSONObject json = new JSONObject(decryptedJson);

                String currentTarget = json.getString("target");
                String currentUsername = json.getString("username");
                String currentPassword = json.getString("password");

                String newTarget = "_".equals(updatedData.target()) ? currentTarget : updatedData.target();
                String newUsername = "_".equals(updatedData.username()) ? currentUsername : updatedData.username();
                String newPassword = "_".equals(updatedData.password()) ? currentPassword : updatedData.password();

                JSONObject newJson = new JSONObject();
                newJson.put("target", newTarget);
                newJson.put("username", newUsername);
                newJson.put("password", newPassword);

                byte[] newEncryptedData = Vault.encrypt(newJson.toString(), key);

                try (PreparedStatement updateStmt = conn.prepareStatement(updateSql)) {
                    updateStmt.setBytes(1, newEncryptedData);
                    updateStmt.setInt(2, updatedData.id());
                    updateStmt.executeUpdate();
                }
            }
        }
    }

    /*
    DELETE_CREDENTIAL
    -----------------
    -> Recieves id for entry to be deleted using a CredentialData record.
    -> Deletes entry corresponding to the given id from credential table if it exists.
    -> Otherwise throws an exception.
    */
    public void deleteCredential(CredentialData credentialData) throws Exception {
        String sql = "DELETE FROM credential_table WHERE id = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, credentialData.id());
            int deleted = pstmt.executeUpdate();

            if (deleted == 0) {
                throw new Exception("No entry with id " + credentialData.id() + " found");
            }
        }
    }

    /*
    GET_PASSWORD
    ------------
    -> Recieve (target, username) using a record of type CredentialData along with a key for decryption.
    -> Return the password as string for the (target, username) combination if it exists in credential table.
    -> Otherwise throw an exception.
    */
    public String getPassword(CredentialData credentialData, SecretKey key) throws Exception {
        List<CredentialData> allCredentials = getAllCredentials(key);

        for (CredentialData cred : allCredentials) {

            if (
            cred.target().equals(credentialData.target()) &&
            cred.username().equals(credentialData.username()))
            {
                return cred.password();
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

    /*
    REENCRYPT_DATABASE
    ------------------
    -> Recieves an oldkey with which the credential table is currently encrypted and a newkey with which the
       credential table is to be rencrypted. 
    -> First decrypt the whole credential table with oldkey.
    -> Then use 'void reEncryptCredential(CredentialData credentialData, SecretKey newKey)' to re encrypt the
       credential table one credential at a time with a loop
    */
    public void reEncryptDatabase(SecretKey oldKey, SecretKey newKey) throws Exception {
        List<CredentialData> credentials = getAllCredentials(oldKey);
        for (CredentialData cred : credentials) {
            reEncryptCredential(cred, newKey);
        }
    }

    /*
    GET_CREDENTIAL_TABLE
    --------------------
    -> Accepts a key to decrypt the credential table.
    -> Return a String representing ascii table for the credential table.
    */
    public String getCredentialTable(SecretKey key) throws Exception {
        List<CredentialData> credentials = getAllCredentials(key);

        if (credentials.isEmpty()) {
            throw new Exception("Database empty");
        }

        String table = AsciiTable.getTable(credentials, List.of(
            new Column().header("ID").headerAlign(HorizontalAlign.CENTER).dataAlign(HorizontalAlign.CENTER).with(cred -> String.valueOf(cred.id())),
            new Column().header("Target").headerAlign(HorizontalAlign.CENTER).dataAlign(HorizontalAlign.CENTER).with(CredentialData::target),
            new Column().header("Username").headerAlign(HorizontalAlign.CENTER).dataAlign(HorizontalAlign.CENTER).with(CredentialData::username),
            new Column().header("Password").headerAlign(HorizontalAlign.CENTER).dataAlign(HorizontalAlign.CENTER).with(CredentialData::password)
        ));

        return table;
    }

    /*
    CLOSE
    -----
    -> Close connection to database.
    */
    public void close() {
        if (conn != null) {
            try {
                conn.close();
            } catch (Exception e) {
                throw new RuntimeException("Failed to close DB connection", e);
            }
        }
    }

    /*
    GET_ALL_CREDENTIALS
    -------------------
    -> Accepts a key for credential table decryption.
    -> Constructs a List of decrpted credentials from credential table.
    -> Returns the constructed list.
    */
    private List<CredentialData> getAllCredentials(SecretKey key) throws Exception {
        List<CredentialData> credentials = new ArrayList<>();
        String sql = "SELECT * FROM credential_table";

        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                int id = rs.getInt("id");
                byte[] encryptedData = rs.getBytes("data");

                String decryptedJson = Vault.decrypt(encryptedData, key);

                JSONObject json = new JSONObject(decryptedJson);

                String target = json.getString("target");
                String username = json.getString("username");
                String password = json.getString("password");

                credentials.add(new CredentialData(id, target, username, password));
            }
        }

        return credentials;
    }

    /*
    RE_ENCRYPT_CREDENTIAL
    -----------------------
    -> Accepts data to be encrypted as a record of type CredentialData along with a new key for encryption.
    -> The data is encrypted using the new key and correspoding credential table entry is updated using the id.  
    */
    private void reEncryptCredential(CredentialData credentialData, SecretKey newKey) throws Exception {
        String sql = "UPDATE credential_table SET data = ? WHERE id = ?";

        JSONObject json = new JSONObject();
        json.put("target", credentialData.target());
        json.put("username", credentialData.username());
        json.put("password", credentialData.password());

        byte[] encryptedData = Vault.encrypt(json.toString(), newKey);

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setBytes(1, encryptedData);
            pstmt.setInt(2, credentialData.id());
            pstmt.executeUpdate();
        }
    }

}
