package com.github.tmpstpdwn;

import javax.crypto.SecretKey;

public class Main {
    private static final ArgumentParser argParser = new ArgumentParser();
    private static final DataBase db = new DataBase();

    public static void main(String[] args) {
        try {
            argParser.parseArgs(args);
            db.connect();
            run(db);
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage() + "!");
            System.exit(1);
        } finally {
            db.close();
        }
    }

    private static void run(DataBase db) throws Exception {
        if (!db.metaTableExists()) {
            ArgumentParser.ParsedArg launchNEWPASS =
            new ArgumentParser.ParsedArg(ActionHandler.ActionType.NEWPASS, null);
            ActionHandler.handleActions(launchNEWPASS, db, null);
        } else {
            SecretKey AESKey = Authenticator.authenticate(db);
            ActionHandler.handleActions(argParser.getParsedArg(), db, AESKey);
        }
    }

}
    