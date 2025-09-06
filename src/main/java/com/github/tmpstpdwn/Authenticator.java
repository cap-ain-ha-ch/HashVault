package com.github.tmpstpdwn;

import java.util.Scanner;
import javax.crypto.SecretKey;

public class Authenticator {

  public static SecretKey authenticate(DataBase dataBase) throws Exception {
      Scanner scanner = new Scanner(System.in);
      System.out.print("Enter master password: ");
      String master = scanner.nextLine();

      DataBase.Metadata metadata = dataBase.getMetadata();
      String hashedMaster = Vault.hashPassword(master, metadata.loginSalt());

      if (!hashedMaster.equals(metadata.hashedMaster())) {
          throw new Exception("Wrong password");
      }

      return Vault.getAESKey(master, metadata.encryptionSalt());
  }
  
}
