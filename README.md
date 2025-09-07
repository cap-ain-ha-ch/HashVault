# HashVault

HashVault is a secure password manager written in Java that stores encrypted credentials in a local SQLite database. It allows you to add, update, delete, list, and retrieve passwords securely with AES encryption.

## Run

- Requires Java 17 or higher.
- You can build it with maven OR
- Get the fat jar package that includes all dependancies from releases.
- The fat jar can then be run with the java virtual machine (17+) by 

```
java -jar HashVault.jar
```

## Usage

hashvault \<action> \<args>

Action     | Arguments                   | Description
-----------|-----------------------------|-------------------------------
--new-pass | (none)                      | Setup master password for first time
--add      | target username password    | Add new credential (target + username must be unique)
--update   | id target username password | Update credential by id; use '_' to leave fields unchanged
--delete   | id                          | Delete credential by id
--list     | (none)                      | List all saved credentials
--get-pass | target username             | Retrieve password for target + username

## License

This project is licenced under MIT [LICENSE](LICENSE)
