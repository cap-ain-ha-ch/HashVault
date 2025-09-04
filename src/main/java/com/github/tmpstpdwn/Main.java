package com.github.tmpstpdwn;

import javax.crypto.SecretKey;
import java.util.Scanner;
import java.util.ArrayList;
import java.util.List;

// For ASCII TABLE.
import com.github.freva.asciitable.AsciiTable;
import com.github.freva.asciitable.Column;
import com.github.freva.asciitable.HorizontalAlign;

enum ActionType {
    ADD,
    LIST
}

record ParsedInput(ActionType action, Object data) {}

public class Main {
    private static SecretKey AESKey;
    private static DataBase dataBase = new DataBase();
    private static Scanner scanner = new Scanner(System.in);
    private static ParsedInput parsedInput = null;

    public static void main(String[] args) {
        parseInput(args);

        dataBase.connect();

        initAuthentication();
        takeAction();

        scanner.close();
        dataBase.close();
    }

    private static void initAuthentication() {
        if (!dataBase.metaTableExists()) {
            register();
        } else {
            authenticate();
        }
    }

    private static void parseInput(String[] args) {
        int i = 0;
        while (i < args.length) {
            if (parsedInput != null) {
                System.out.println("Error: Excess positional arguments found!");
                System.exit(1);
            }

            if (args[i].equals("--add")) {
                i++;

                if (args.length - i < 3) {
                    System.out.println("Error: Not enough arguments for \'add\' action!");
                    System.exit(1);
                }

                DataBase.CredentialData data = new DataBase.CredentialData(
                    args[i], args[i+1], args[i+2]
                );

                parsedInput = new ParsedInput(ActionType.ADD, data);
                i += 3;

            } else if (args[i].equals("--list")) {
                parsedInput = new ParsedInput(ActionType.LIST, null);
                i++;
                
            } else {
                System.out.println("Error: Unknown action '" + args[i] + "' found!");
                System.exit(1);
            }
        }
    }

    private static void takeAction() {
        if (parsedInput == null) {
            System.out.println("Error: No action provided.");
            System.exit(1);
        }

        switch(parsedInput.action()) {
            case ADD -> {
                if (parsedInput.data() instanceof DataBase.CredentialData credentialData) {
                    String site = credentialData.site();
                    String username = credentialData.username();
                    String password = credentialData.password();
                    dataBase.insertEncryptedCredential(credentialData, AESKey);
                    System.out.println("Credentials added to the database successfully!");
                } else {
                    throw new IllegalArgumentException("Expected CredentialData for ADD action.");
                }
            }

            case LIST -> {
                List<DataBase.CredentialRecord> credentials = dataBase.getAllDecryptedCredentials(AESKey);
                if (credentials.isEmpty()) {
                    System.out.println("No credentials found.");
                } else {
                    String table = AsciiTable.getTable(credentials, List.of(
                        new Column().header("ID").headerAlign(HorizontalAlign.CENTER).dataAlign(HorizontalAlign.CENTER).with(cred -> String.valueOf(cred.id())),
                        new Column().header("Site").headerAlign(HorizontalAlign.CENTER).dataAlign(HorizontalAlign.CENTER).with(DataBase.CredentialRecord::site),
                        new Column().header("Username").headerAlign(HorizontalAlign.CENTER).dataAlign(HorizontalAlign.CENTER).with(DataBase.CredentialRecord::username),
                        new Column().header("Password").headerAlign(HorizontalAlign.CENTER).dataAlign(HorizontalAlign.CENTER).with(DataBase.CredentialRecord::password)
                    ));
                    System.out.println(table);
                }
            }
        }
    }
    
    private static void register() {
        dataBase.createMetaTable();
        dataBase.createCredentialTable();

        System.out.print("Enter a new master password: ");
        String master = scanner.nextLine();

        String loginSalt = Vault.generateSalt();
        String encryptionSalt = Vault.generateSalt();

        String hashedMaster = Vault.hashPassword(master, loginSalt);

        dataBase.insertMetaData(new DataBase.Metadata(hashedMaster, loginSalt, encryptionSalt));

        AESKey = Vault.getAESKey(master, encryptionSalt);
    }

    private static void authenticate() {
        System.out.print("Enter master password: ");
        String master = scanner.nextLine();

        DataBase.Metadata metadata = dataBase.getMetadata();
        String hashedMaster = Vault.hashPassword(master, metadata.loginSalt());

        if (!hashedMaster.equals(metadata.hashedMaster())) {
            System.out.println("Wrong password!");
            System.exit(1);
        }

        AESKey = Vault.getAESKey(master, metadata.encryptionSalt());
    }
}
