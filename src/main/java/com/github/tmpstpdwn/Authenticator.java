package com.github.tmpstpdwn;

import java.io.Console;
import javax.crypto.SecretKey;

import java.security.MessageDigest;

public class Authenticator {

  public static SecretKey authenticate(DataBase dataBase) throws Exception {
      Console console = System.console();
      if (console == null) {
          throw new Exception("No console available");
      }
      char[] passwordChars = console.readPassword("Enter the master password: ");
      String master = new String(passwordChars);

      DataBase.Metadata metadata = dataBase.getMetadata();
      byte[] masterKey = Vault.getKeyBytes(master, metadata.loginSalt());

      if (!MessageDigest.isEqual(masterKey, metadata.masterKey())) {
          throw new Exception("Wrong password");
      }

      return Vault.getAESKey(master, metadata.encryptionSalt());
  }
  
}
