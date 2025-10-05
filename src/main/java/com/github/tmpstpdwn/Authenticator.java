package com.github.tmpstpdwn;

import java.io.Console;
import javax.crypto.SecretKey;

import java.security.MessageDigest;

public class Authenticator {

    /*
    AUTHENTICATE
    ------------
    -> Recieves a handle to database connection.
    -> Reads input from user for master password.
    -> master_hash, login_salt, encryption_salt is fetched from meta_table.
    -> Hashes the user given master password with login_salt and crosschecks
       it with stored master_hash from metatable.
    -> If both are equal, then user given master password is valid which is then used with encryption salt
       from metatable to derive and return The AES key for encryption and decryption.
    -> If not equal, then throw an exception.  
    */
  
    public static SecretKey authenticate(DataBase dataBase) throws Exception {
      Console console = System.console();
      if (console == null) {
          throw new Exception("No console available");
      }

      // Read input.
      char[] passwordChars = console.readPassword("Enter the master password: ");
      String master = new String(passwordChars);

      // Fetching metadata.
      DataBase.Metadata metadata = dataBase.getMetadata();
      // Hashing user given master password with login_salt from metatable.
      byte[] masterKey = Vault.getKeyBytes(master, metadata.loginSalt());

      // Checking for equality between derived master hash and stored master hash. 
      if (!MessageDigest.isEqual(masterKey, metadata.masterKey())) {
          throw new Exception("Wrong password");
      }

      // Return AES KEY.
      return Vault.getAESKey(master, metadata.encryptionSalt());
    }
  
}
