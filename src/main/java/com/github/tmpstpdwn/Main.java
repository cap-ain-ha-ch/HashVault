package com.github.tmpstpdwn;

import javax.crypto.SecretKey;

public class Main {
    private static SecretKey AESKey;
    private static final ArgumentParser argParser = new ArgumentParser();
    private static final DataBase db = new DataBase();

    public static void main(String[] args) {
        System.out.println("\nHashVault\n---------\n");
        try {
            argParser.parseArgs(args);
            db.connect();
            if (!db.metaTableExists()) {
                ActionHandler.handleActions(new ArgumentParser.ParsedArg(ActionHandler.ActionType.NEWPASS, null), db, null);
            } else {
                AESKey = Authenticator.authenticate(db);
                ActionHandler.handleActions(argParser.getParsedArg(), db, AESKey);
            }
            db.close();
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage() + "\n");
            System.exit(1);
        }
        System.out.println("\n");
    }

}
