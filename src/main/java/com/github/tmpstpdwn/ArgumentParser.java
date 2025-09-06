package com.github.tmpstpdwn;

import javax.crypto.SecretKey;

public class ArgumentParser {
    public static record ParsedArg<T>(ActionHandler.ActionType action, T data) {}

    private ParsedArg<?> parsedArg = null;

    private static final String helpText = """
    Usage: hashvault <action> <args>

    <action>   | <Args>
    -------------------
    --add      | target username password
    --list     | <NO ARGS>
    --update   | id target username password
    --get-pass | target username
    --delete   | id
    --new-pass | <NO ARGS>

    Note:
    
    -> This program only allows one action at a time.
    -> For update action '_' can be used to denote fields
       with no change.
       example: hashvault --update 1 _ _ new_password
    """;

    public ParsedArg<?> getParsedArg() {
        return parsedArg;
    }

    public void parseArgs(String[] args) throws Exception {
        int i = 0;
        while (i < args.length) {

            if (parsedArg != null) {
                throw new Exception("Excess positional arguments found");
            }

            switch (args[i]) {
                case "--add" -> { i = parseADD(args, i); i++; }
                case "--list" -> { parseLIST(); i++; }
                case "--update" -> { i = parseUPDATE(args, i); i++; }
                case "--get-pass" -> { i = parseGETPASS(args, i); i++; }
                case "--delete" -> { i = parseDELETE(args, i); i++; }
                case "--new-pass" -> { parseNEWPASS(); i++; } 
                default -> throw new Exception("Unknown action '" + args[i] + "' found");
            }
        }

        if (parsedArg == null) {
            throw new Exception(helpText);
        }
    }

    private int parseADD(String[] args, int i) throws Exception {
        if (args.length - i - 1 < 3) {
            throw new Exception("Not enough arguments for 'add' action");
        }

        DataBase.CredentialData data = new DataBase.CredentialData(
                args[i + 1], args[i + 2], args[i + 3]);

        parsedArg = new ParsedArg<>(ActionHandler.ActionType.ADD, data);
        return i + 3;
    }

    private void parseLIST() {
        parsedArg = new ParsedArg<>(ActionHandler.ActionType.LIST, null);
    }

    private int parseUPDATE(String[] args, int i) throws Exception {
        if (args.length - i - 1 < 4) {
            throw new Exception("Not enough arguments for 'update' action");
        }

        int id = Integer.parseInt(args[i + 1]);
        DataBase.CredentialRecord data = new DataBase.CredentialRecord(
                id, args[i + 2], args[i + 3], args[i + 4], null);

        parsedArg = new ParsedArg<>(ActionHandler.ActionType.UPDATE, data);
        return i + 4;
    }

    private int parseGETPASS(String[] args, int i) throws Exception {
        if (args.length - i - 1 < 2) {
            throw new Exception("Not enough arguments for 'get-pass' action");
        }

        DataBase.CredentialData data = new DataBase.CredentialData(args[i + 1], args[i + 2], null);
        parsedArg = new ParsedArg<>(ActionHandler.ActionType.GETPASS, data);
        return i + 2;
    }

    private int parseDELETE(String[] args, int i) throws Exception {
        if (args.length - i - 1 < 1) {
            throw new Exception("Not enough arguments for 'delete' action");
        }

        int data = Integer.parseInt(args[i + 1]);

        parsedArg = new ParsedArg<>(ActionHandler.ActionType.DELETE, data);
        return i + 1;
    }

    private void parseNEWPASS() {
        parsedArg = new ParsedArg<>(ActionHandler.ActionType.NEWPASS, null);
    }

}
