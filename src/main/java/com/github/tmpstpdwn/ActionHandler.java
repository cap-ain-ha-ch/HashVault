package com.github.tmpstpdwn;

import java.util.Scanner;
import javax.crypto.SecretKey;

public class ActionHandler {

    private static String tipsForGoodPassword = """
    Tips for a good password (Not enforced):
    
    - Use at least 12 characters
    - Include uppercase and lowercase letters
    - Add numbers and special symbols
    - Avoid common words or patterns
    """;

    public enum ActionType {
        ADD,
        LIST,
        UPDATE,
        GETPASS,
        DELETE,
        NEWPASS
    }

    public static void handleActions(ArgumentParser.ParsedArg<?> parsedArg, DataBase db, SecretKey key) throws Exception {
        switch (parsedArg.action()) {
            case ADD -> actionADD((DataBase.CredentialData) parsedArg.data(), db, key);
            case LIST -> actionLIST(db, key);
            case UPDATE -> actionUPDATE((DataBase.CredentialRecord) parsedArg.data(), db, key);
            case GETPASS -> actionGETPASS((DataBase.CredentialData) parsedArg.data(), db, key);
            case DELETE -> actionDELETE((Integer) parsedArg.data(), db, key);
            case NEWPASS -> actionNEWPASS(db, key);
        }
    }

    private static void actionADD(DataBase.CredentialData data, DataBase db, SecretKey key) throws Exception {
        db.insertCredentialUnique(data, key);
    }

    private static void actionLIST(DataBase db, SecretKey key) throws Exception {
        System.out.println(db.printCredentialTable(key));
    }

    private static void actionUPDATE(DataBase.CredentialRecord record, DataBase db, SecretKey key) throws Exception {
        db.updateCredential(record, key);
    }

    private static void actionGETPASS(DataBase.CredentialData data, DataBase db, SecretKey key) throws Exception {
        System.out.println(db.getPassword(data, key));
    }

    private static void actionDELETE(int id, DataBase db, SecretKey key) throws Exception {
        db.deleteCredential(id, key);
    }

    private static void actionNEWPASS(DataBase db, SecretKey oldKey) throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.println(tipsForGoodPassword);
        System.out.print("Enter a new master password: ");
        String master = scanner.nextLine();

        String loginSalt = Vault.generateSalt();
        String encryptionSalt = Vault.generateSalt();

        String hashedMaster = Vault.hashPassword(master, loginSalt);
        
        if (!db.metaTableExists()) {
            db.createTables();
        } else {
            SecretKey newKey = Vault.getAESKey(master, encryptionSalt);
            db.reEncryptDatabase(oldKey, newKey);
        }

        db.setMetadata(new DataBase.Metadata(hashedMaster, loginSalt, encryptionSalt));            
        System.out.println("\nNew master password set!");
    }
}
