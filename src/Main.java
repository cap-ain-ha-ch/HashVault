import javax.crypto.SecretKey;
import java.util.Scanner;
import java.util.ArrayList;
import java.util.List;

enum ActionType {
    ADD,
    LIST
}

record ParsedInput(ActionType action, String[] data) {}

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
                if (args.length - i - 1 < 3) {
                    System.out.println("Error: Not enough arguments for \'add\' action!");
                    System.exit(1);
                }

                String site = args[++i];
                String username = args[++i];
                String password = args[++i];

                String[] data = {site, username, password};
                parsedInput = new ParsedInput(ActionType.ADD, data);
                i++;

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
                String site = parsedInput.data()[0];
                String username = parsedInput.data()[1];
                String password = parsedInput.data()[2];
                DataBase.CredentialData credentialData = new DataBase.CredentialData(
                    site, username, password
                );
                dataBase.insertEncryptedCredential(credentialData, AESKey);
                System.out.println("Credentials added to the database successfully!");
            }

            case LIST -> {
                List<DataBase.CredentialRecord> credentials = dataBase.getAllDecryptedCredentials(AESKey);

                if (credentials.isEmpty()) {
                    System.out.println("No credentials found.");
                } else {
                    System.out.printf("%-20s %-20s %-20s%n", "Site", "Username", "Password");
                    System.out.println("------------------------------------------------------------");

                    for (DataBase.CredentialRecord cred : credentials) {
                        System.out.printf(
                            "%-20s %-20s %-20s%n",
                            cred.site(),
                            cred.username(),
                            cred.password()
                        );
                    }
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
