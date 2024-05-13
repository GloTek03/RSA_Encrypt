package org.example;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class RSA {
    private PrivateKey privateKey;
    private PublicKey publicKey;
    public RSA(){
        try{
            //Tạo KeyPairGeneration cho RSA
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            //Khởi tạo KeyPairGenerator
            generator.initialize(1024);
            //Tạo cặp khoá
            KeyPair pair = generator.generateKeyPair();
            //Lấy khoá riêng và khoá công khai
            privateKey = pair.getPrivate();
            publicKey = pair.getPublic();
        }catch (Exception e){

        }
    }
    /*method này dùng để mã hoá đoạn message được truyền vào
    * với thuật toán RSA dùng chế độ ECB và phương pháp padding: PKCS1Padding
    * "RSA": Thuật toán mã hóa khóa công khai RSA.
    * "ECB": Chế độ mã hóa (Electronic Codebook), nhưng trong trường hợp của RSA,
    * chế độ này không được sử dụng vì RSA mã hóa từng khối một cách độc lập.
    * "PKCS1Padding": Phương pháp padding (đệm) được sử dụng khi dữ liệu không đủ
    * để điền đầy một khối.*/
    public String encrypt(String message) throws Exception{
        byte[] messageToBytes = message.getBytes();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        byte[] encryptedBytes = cipher.doFinal(messageToBytes);
        return encode(encryptedBytes);
    }
    private String encode(byte[] data){
        return Base64.getEncoder().encodeToString(data);
    }
    /*method này được dùng để giải mã message đã được mã hoá
    * với chế độ RSA/ECB/PCKCS1Padding(xem thêm giải thích
    *ở phần encrypt)*/
    public String decrypt(String encryptedMessage) throws Exception{
        byte[] encryptedBytes = decode(encryptedMessage);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
        return new String(decryptedMessage,"UTF8");
    }

    private byte[] decode(String data){
        return Base64.getDecoder().decode(data);
    }

    public static void main(String[] args) {
        RSA rsa = new RSA();
        try {
            String encryptedMessage = rsa.encrypt("Hello World");
            String decryptedMessage = rsa.decrypt(encryptedMessage);

            System.err.println("Encrypted:\n"+encryptedMessage);
            System.err.println("Decrypted:\n"+decryptedMessage);
        }catch (Exception e){

        }
    }
}
