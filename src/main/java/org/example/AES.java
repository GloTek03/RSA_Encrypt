package org.example;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AES {
    private SecretKey key;
    private int KEY_SIZE = 128;
    private int T_LEN = 128;
    private byte[] IV;
    public void  init() throws  Exception{
        //Khởi tạo KeyGenerator với kích thước khoá 128 bit
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(KEY_SIZE);
        //Tạo khoá bí mật
        key = generator.generateKey();
    }
    /*Phương thức này được tạo ra để có thể khởi tạo dựa theo 1 dạng
    secretKey sẵn có không phải khởi tạo lại từ đầu như được viết
    trong phương thức init()*/
    public void initFromStrings(String secretKey, String IV){
        key = new SecretKeySpec(decode(secretKey),"AES");
        this.IV = decode(IV);
    }
    /*phương thức này dùng để mã hoá message
    * sử dụng thuật toán AES với chế độ GGCM và không có padding
    * */
    public String encryptBefore(String message) throws Exception{
        byte[] messageInBytes = message.getBytes();
        Cipher encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encryptionCipher.init(Cipher.ENCRYPT_MODE,key);
        IV = encryptionCipher.getIV();
        byte[] encryptedBytes = encryptionCipher.doFinal(messageInBytes);
        return encode(encryptedBytes);
    }
    /*được update khi khởi tạo đối tượng GMCParameterSpec */
    public String encrypt(String message) throws Exception{
        byte[] messageInBytes = message.getBytes();
        Cipher encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(T_LEN,IV);
        encryptionCipher.init(Cipher.ENCRYPT_MODE,key,spec);
        byte[] encryptedBytes = encryptionCipher.doFinal(messageInBytes);
        return encode(encryptedBytes);
    }
    /*phương thức này dùng đề giải mã ecryptedMessage
    * sử dụng thuật toán AES/GCM/NoPadding */
    public String decrypt(String encryptedMessage) throws Exception{
        byte[] messageInBytes = decode(encryptedMessage);
        Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(T_LEN, IV);
        decryptionCipher.init(Cipher.DECRYPT_MODE,key,spec);
        byte[] decryptedBytes = decryptionCipher.doFinal(messageInBytes);
        return new String(decryptedBytes);
    }
    /*hàm này dùng để chuyển đổi mảng byte thành chuỗi mã hoá Base 64*/
    private String encode(byte[] data){
        return Base64.getEncoder().encodeToString(data);
    }
    /*hàm này được dùng để giải mã chuỗi Base64 trả về mảng byte gốc*/
    private byte[] decode(String data){
        return Base64.getDecoder().decode(data);
    }
    /*method này được viết ra để export Key sử dụng cho
    * method initFromString*/
     private  void exportKeys(){
         System.err.println("SecretKey :" + encode(key.getEncoded()));
         System.err.println("IV: " + encode(IV));
     }
    public static void main(String[] args) {
        try{
            AES aes = new AES();
            aes.initFromStrings("UHJXUN0mG/bvr4v6u3lQrA==","2+dLCJm2tKai12qL");
            String encryptedMessage = aes.encrypt("Hello World");
            //String decryptedMessage = aes.decrypt(encryptedMessage);

            System.err.println("Encrypted Message = " + encryptedMessage);
            //System.err.println("Decrypted Message = " + decryptedMessage);
            //aes.exportKeys();
        }catch (Exception ignore){}
    }
}
