package com.github.tmpstpdwn;

import java.io.Console;
import javax.crypto.SecretKey;

public class ActionHandler {

    private static String tipsForGoodPassword = """
    Tips for a good password (Not enforced):
    
    - Use at least 12 characters
    - Include uppercase and lowercase letters
    - Add numbers and special symbols
    - Avoid common words or patterns

    WARINING:

    In case if the master password is lost, there will
    be no way to decrypt the database!!!""";

    public enum ActionType {
        ADD,
        LIST,
        UPDATE,
        GETPASS,
        DELETE,
        NEWPASS
    }

    public static void handleActions(ArgumentParser.ParsedArg parsedArg, DataBase db, SecretKey key) throws Exception {
        switch (parsedArg.action()) {
            case ADD -> actionADD( parsedArg.data(), db, key);
            case LIST -> actionLIST(db, key);
            case UPDATE -> actionUPDATE(parsedArg.data(), db, key);
            case GETPASS -> actionGETPASS(parsedArg.data(), db, key);
            case DELETE -> actionDELETE(parsedArg.data(), db);
            case NEWPASS -> actionNEWPASS(db, key);
        }
    }

    private static void actionADD(DataBase.CredentialData data, DataBase db, SecretKey key) throws Exception {
        db.insertCredentialUnique(data, key);
    }

    private static void actionLIST(DataBase db, SecretKey key) throws Exception {
        System.out.println(db.getCredentialTable(key));
    }

    private static void actionUPDATE(DataBase.CredentialData data, DataBase db, SecretKey key) throws Exception {
        db.updateCredential(data, key);
    }

    private static void actionGETPASS(DataBase.CredentialData data, DataBase db, SecretKey key) throws Exception {
        System.out.println(db.getPassword(data, key));
    }

    private static void actionDELETE(DataBase.CredentialData data, DataBase db) throws Exception {
        db.deleteCredential(data);
    }

    private static void actionNEWPASS(DataBase db, SecretKey oldKey) throws Exception {
        System.out.println("\n" + tipsForGoodPassword + "\n");

        Console console = System.console();
        /*There might be cases where a terminal doesnt support the console features, when such cases are 
        encountered the below if statement would make sure the main program catches the exception and 
        terminates the program succesfully. Ex: VScode doesnt support console features and would return null
        for the above line of code, if that happens the if statement below ensures the error is properly handled
        terminating the program succesfully.*/
        if (console == null) {
            throw new Exception("No console available");
        }
        char[] passwordChars = console.readPassword("Enter a new master password: ");
        /*Here the typed password wouldnt be seen at the terminal, this is one of the features of console,
        the console package is imported solely for the said purpose*/
        String master = new String(passwordChars);

        byte[] loginSalt = Vault.generateBytes(Vault.BytesType.SALT_BYTES);
        byte[] encryptionSalt = Vault.generateBytes(Vault.BytesType.SALT_BYTES);

        byte[] masterKey = Vault.getKeyBytes(master, loginSalt);
        
        if (!db.metaTableExists()) {
            db.createTables();
        } else {
            SecretKey newKey = Vault.getAESKey(master, encryptionSalt);
            db.reEncryptDatabase(oldKey, newKey);
        }

        db.setMetadata(new DataBase.Metadata(masterKey, loginSalt, encryptionSalt));            
    }
}
