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
    LIST,
    UPDATE
}

record ParsedInput<T>(ActionType action, T data) {}

public class Main {
    private static SecretKey AESKey;
    private static DataBase dataBase = new DataBase();
    private static Scanner scanner = new Scanner(System.in);
    private static ParsedInput<?> parsedInput = null;

    private static String helpText = """

    Usage: hashvault <action> <args>

    <action> | <Args>

    --add    | target username password
    --list

    Note: This program only allows one action at a time.
                
    """;


    public static void main(String[] args) {

        try {

            parseInput(args);
            dataBase.connect();
            initAuthentication();
            takeAction();
            dataBase.close();

        } catch (Exception e) {
            System.out.println("Error: Unrecoverable!");
        }

        scanner.close();
    }

    private static void parseInput(String[] args) throws Exception {
        int i = 0;
        while (i < args.length) {

            if (parsedInput != null) {
                System.out.println("Error: Excess positional arguments found!");
                System.exit(1);
            }

            if (args[i].equals("--add")) {
                i = parseADD(args, i);
                i++;

            } else if (args[i].equals("--list")) {
                parsedInput = new ParsedInput<Void>(ActionType.LIST, null);
                i++;
                
            } else if (args[i].equals("--update")) {
                i = parseUPDATE(args, i);
                i++;
                
            } else {
                System.out.println("Error: Unknown action '" + args[i] + "' found!");
                System.exit(1);
            }
        }

        if (parsedInput == null) {
            System.out.print(helpText);
            System.exit(1);
        }
    }

    private static int parseADD(String[] args, int i) {
        if (args.length - i - 1 < 3) {
            System.out.println("Error: Not enough arguments for 'add' action!");
            System.exit(1);
        }

        DataBase.CredentialData data = new DataBase.CredentialData(
            args[i+1], args[i+2], args[i+3]
        );

        parsedInput = new ParsedInput<DataBase.CredentialData>(ActionType.ADD, data);

        return i + 3;
    }

    private static int parseUPDATE(String[] args, int i) throws Exception {
        if (args.length - i - 1 < 4) {
            System.out.println("Error: Not enough arguments for 'update' action!");
            System.exit(1);
        }

        int id = Integer.parseInt(args[i+1]);

        DataBase.CredentialRecord data = new DataBase.CredentialRecord(
            id, args[i+2], args[i+3], args[i + 4], null
        );

        parsedInput = new ParsedInput<DataBase.CredentialRecord>(ActionType.UPDATE, data);

        return i + 4;
    }

     private static void initAuthentication() throws Exception {
        if (!dataBase.metaTableExists()) {
            register();
        } else {
            authenticate();
        }
    }

    private static void register() throws Exception {
        dataBase.createTables();

        System.out.print("Enter a new master password: ");
        String master = scanner.nextLine();

        String loginSalt = Vault.generateSalt();
        String encryptionSalt = Vault.generateSalt();

        String hashedMaster = Vault.hashPassword(master, loginSalt);

        dataBase.insertMetadata(new DataBase.Metadata(hashedMaster, loginSalt, encryptionSalt));

        AESKey = Vault.getAESKey(master, encryptionSalt);
    }

    private static void authenticate() throws Exception {
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

    private static void takeAction() throws Exception {
        switch(parsedInput.action()) {
            case ADD -> actionADD();
            case LIST -> actionLIST();
            case UPDATE -> actionUPDATE();
        }
    }

    private static void actionADD() throws Exception {
        dataBase.insertCredential((DataBase.CredentialData) parsedInput.data(), AESKey);
    }

    private static void actionLIST() throws Exception {
        List<DataBase.CredentialRecord> credentials = dataBase.getAllCredentials(AESKey);
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

    private static void actionUPDATE() throws Exception {
        dataBase.updateCredential((DataBase.CredentialRecord) parsedInput.data(), AESKey);
    }
    
}
