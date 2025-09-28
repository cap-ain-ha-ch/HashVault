package com.github.tmpstpdwn;

import javax.crypto.SecretKey;

public class Main {
    private static final ArgumentParser argParser = new ArgumentParser(); //a new instance of the ArgumentParser class is created, and the variable arg parser refers to it.
    private static final DataBase db = new DataBase();// a new instance of the Database class is created, variable db refers to the same.
    /*The main function accepts the argument from the user as a string format and stores it in args*/
    public static void main(String[] args) {
        try {
            argParser.parseArgs(args);// The argument from the user is passed to the parseArgs method inside the ArgumentParser class.
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
    