package org.example;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class Client {
    private SecretKey key;
    private int KEY_SIZE = 128;
    private int T_LEN = 128;
    private byte[] IV;
    public void initFromStrings(String secretKey, String IV){
        key = new SecretKeySpec(decode(secretKey),"AES");
        this.IV = decode(IV);
    }
    public String decrypt(String encryptedMessage) throws Exception{
        byte[] messageInBytes = decode(encryptedMessage);
        Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(T_LEN, IV);
        decryptionCipher.init(Cipher.DECRYPT_MODE,key,spec);
        byte[] decryptedBytes = decryptionCipher.doFinal(messageInBytes);
        return new String(decryptedBytes);
    }
    private String encode(byte[] data){
        return Base64.getEncoder().encodeToString(data);
    }
    /*hàm này được dùng để giải mã chuỗi Base64 trả về mảng byte gốc*/
    private byte[] decode(String data){
        return Base64.getDecoder().decode(data);
    }

    public static void main(String[] args) {
        try{
            Client client = new Client();
            client.initFromStrings("UHJXUN0mG/bvr4v6u3lQrA==","2+dLCJm2tKai12qL");
            String decryptedMessage = client.decrypt("JASFCE/BjLRJOIjg7UyUgNO8tjh71k5FGBnR");
            System.err.println(decryptedMessage);
        }catch (Exception e){}
    }
}
