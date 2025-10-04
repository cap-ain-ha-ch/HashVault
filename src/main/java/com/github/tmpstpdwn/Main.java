package com.github.tmpstpdwn;

import javax.crypto.SecretKey;

public class Main {
    private static final ArgumentParser argParser = new ArgumentParser(); //a new instance of the ArgumentParser class is created, and the variable arg parser refers to it.
    private static final DataBase db = new DataBase();// a new instance of the Database class is created, variable db refers to the same.
    /*The main function accepts the argument from the user as a string format and stores it in args*/
    public static void main(String[] args) {
        try {
            argParser.parseArgs(args);// The argument from the user is passed to the parseArgs method inside the ArgumentParser class.
            db.connect();//Establishes connection to the database
            run(db);//Calls the below function.
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage() + "!");
            System.exit(1);
        } finally {
            db.close();
        }
    }

    private static void run(DataBase db) throws Exception {
        if (!db.metaTableExists()) {
            /*If metatable doesnt exist, 
            it means that the user is running the program for the first time, 
            and would run the program to set a new password as the master password*/
            ArgumentParser.ParsedArg launchNEWPASS =
            new ArgumentParser.ParsedArg(ActionHandler.ActionType.NEWPASS, null);
            /*The above line creates a new object referred as launchNEWPASS with a new record(structure) inside*/
            ActionHandler.handleActions(launchNEWPASS, db, null);
        } else {
            SecretKey AESKey = Authenticator.authenticate(db);
            ActionHandler.handleActions(argParser.getParsedArg(), db, AESKey);
        }
    }

}
    