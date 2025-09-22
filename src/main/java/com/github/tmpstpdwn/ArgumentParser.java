package com.github.tmpstpdwn;

public class ArgumentParser {
    public static record ParsedArg(ActionHandler.ActionType action, DataBase.CredentialData data) {}

    private ParsedArg parsedArg = null;

    private static final String helpText = """
    Usage: HashVault <action> <args>

    <action>   | <args>
    -------------------
    --add      | target username password
    --update   | id target username password
    --delete   | id
    --list     | <NO ARGS>
    --getpass  | target username
    --newpass  | <NO ARGS>
    """;

    public ParsedArg getParsedArg() {
        return parsedArg;
    }

    public void parseArgs(String[] args) throws Exception {
        int i = 0;
        while (i < args.length) {

            if (parsedArg != null) {
                throw new Exception("Only one action is allowed per execution.");
            }

            switch (args[i]) {
                case "--add" -> { i = parseADD(args, i); i++; }
                case "--update" -> { i = parseUPDATE(args, i); i++; }
                case "--delete" -> { i = parseDELETE(args, i); i++; }
                case "--list" -> { parseLIST(); i++; }
                case "--getpass" -> { i = parseGETPASS(args, i); i++; }
                case "--newpass" -> { parseNEWPASS(); i++; } 
                case "--help" -> {
                    System.out.println(helpText);
                    System.exit(0);
                }
                default -> throw new Exception("Unknown action '" + args[i] + "' found");
            }
        }

        if (parsedArg == null) {
            throw new Exception(helpText);
        }
    }

    private int parseADD(String[] args, int i) throws Exception {
//i usagehere not understood
        if (args.length - i - 1 < 3) {
            throw new Exception("Not enough arguments for 'add' action");
        }

        DataBase.CredentialData data = new DataBase.CredentialData(
                0, args[i + 1], args[i + 2], args[i + 3]);

        parsedArg = new ParsedArg(ActionHandler.ActionType.ADD, data);
        return i + 3;
    }

    private void parseLIST() {
        parsedArg = new ParsedArg(ActionHandler.ActionType.LIST, null);
    }

    private int parseUPDATE(String[] args, int i) throws Exception {
        if (args.length - i - 1 < 4) {
            throw new Exception("Not enough arguments for 'update' action");
        }

        int id;
        try {
            id = Integer.parseInt(args[i + 1]);
        } catch (Exception e) {
            throw new Exception("Invalid input for id");    
        }
        
        DataBase.CredentialData data = new DataBase.CredentialData(
                id, args[i + 2], args[i + 3], args[i + 4]);

        parsedArg = new ParsedArg(ActionHandler.ActionType.UPDATE, data);
        return i + 4;
    }

    private int parseGETPASS(String[] args, int i) throws Exception {
        if (args.length - i - 1 < 2) {
            throw new Exception("Not enough arguments for 'getpass' action");
        }

        DataBase.CredentialData data = new DataBase.CredentialData(0, args[i + 1], args[i + 2], null);
        parsedArg = new ParsedArg(ActionHandler.ActionType.GETPASS, data);
        return i + 2;
    }

    private int parseDELETE(String[] args, int i) throws Exception {
        if (args.length - i - 1 < 1) {
            throw new Exception("Not enough arguments for 'delete' action");
        }

        DataBase.CredentialData data;
        try {
            int id = Integer.parseInt(args[i + 1]);
            data = new DataBase.CredentialData(id, null, null, null);
        } catch (Exception e) {
            throw new Exception("Invalid input for id");    
        }

        parsedArg = new ParsedArg(ActionHandler.ActionType.DELETE, data);
        return i + 1;
    }

    private void parseNEWPASS() {
        parsedArg = new ParsedArg(ActionHandler.ActionType.NEWPASS, null);
    }

}
