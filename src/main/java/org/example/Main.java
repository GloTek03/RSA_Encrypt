package org.example;

import javax.crypto.SecretKey;
import java.util.Base64;

public class Main {
    public static void main(String[] args) throws Exception{
        SecretKey key = DES.generateKey();
        System.out.print("Encrypt/Decrypt Key: ");
        System.out.println(encode(key.getEncoded()));
        System.out.println();

        String message = "Son Coder";

        DES des = new DES(key);
        String encryptedMassage = encode(des.encrypt(message));
        System.out.println("Encrypted Message: "+encryptedMassage);
        System.out.println("Decrypted Message: " + des.decypt(decoder(encryptedMassage)));
    }
    public static String encode(byte[] data){
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] decoder(String data){
        return Base64.getDecoder().decode(data);
    }
}