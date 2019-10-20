package picenter.connector.driver;

import picenter.connector.common.common.utilities.ByteTools;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/**
 *
 * CryptTools Version
 *
 * @author rjojj
 */
public class CryptTools {

    public static final String VERSION = "1.0.02";

    static Map<String, Object> getRSAKeys() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        Map<String, Object> keys = new HashMap<String, Object>();
        keys.put("private", privateKey);
        keys.put("public", publicKey);
        return keys;
    }

    static byte[] getPublicKeyBytes(PublicKey publicKey) {
        byte[] keyBytes = publicKey.getEncoded();
        return keyBytes;
    }


    public static byte[] decryptRSAMsg(byte[] encryptedText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedText);
    }

    public static String encryptRSAMsg(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return new java.lang.String(cipher.doFinal(plainText.getBytes("UTF-8")), "UTF-8");
    }

    static byte[] aesDecrypt(SecretKey key, byte[] input) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(generateIV(key)));
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        CipherInputStream in = new CipherInputStream(new ByteArrayInputStream(input), cipher);
        byte[] b = new byte[100];
        int read;
        while ((read = in.read(b)) >= 0) {
            buffer.write(b, 0, read);
        }
        in.close();
        return buffer.toByteArray();
    }

    static byte[] aesEncrypt(SecretKey key, byte[] input) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(generateIV(key)));
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        CipherOutputStream out = new CipherOutputStream(buffer, cipher);
        out.write(input);
        out.flush();
        out.close();
        return buffer.toByteArray();
    }

    private static byte[] generateIV(SecretKey secretKey) throws Exception {
        byte[] sha = getSHA256(secretKey.getEncoded());
        for (int i = 0; i < 15; i++) {
            sha = getSHA256(secretKey.getEncoded(), sha);
        }
        return Arrays.copyOfRange(sha, 3, 19);
    }

    static SecretKey generateSecretKey(byte[] password) {
        try {
            final MessageDigest md = MessageDigest.getInstance("SHA-256");

            final byte[] digestOfPassword = md.digest(password);
            return new SecretKeySpec(digestOfPassword, "AES");
        } catch (Exception e) {
            return null;
        }
    }

    static SecretKey generateRandomSecretKey() {
        try {
            byte[] password = generateRandomBytes(1024 * 1024);
            final MessageDigest md = MessageDigest.getInstance("SHA-256");
            final byte[] digestOfPassword = md.digest(password);
            return new SecretKeySpec(digestOfPassword, "AES");
        } catch (Exception e) {
            return null;
        }
    }

    static byte[] serializeAESKey(SecretKey key) {
        return key.getEncoded();
    }

    static File serializeAESKey(SecretKey key, File out) throws Exception {
        byte[] temp = key.getEncoded();
        temp = Base64.getEncoder().encode(temp);
        if (!out.exists()) {
            out.createNewFile();
        }
        ByteTools.writeBytesToFile(out, temp);
        return out;
    }

    static SecretKey deserializeAESKey(byte[] bytes) {
        SecretKey key = new SecretKeySpec(bytes, 0, bytes.length, "AES");
        return key;
    }

    static SecretKey deserializeAESKey(File keyf) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(ByteTools.readBytesFromFile(keyf));
        return deserializeAESKey(bytes);
    }

    static byte[] getSHA256(String msg) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(msg.getBytes());
        byte[] byteData = md.digest();
        return byteData;
    }

    static byte[] getSHA256(byte[] msg) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(msg);
        byte[] byteData = md.digest();
        return byteData;
    }

    static byte[] getSHA256(byte[] msg, byte[] prev) throws Exception {
        BigInteger one = new BigInteger(msg);
        BigInteger two = new BigInteger(prev);
        one = one.add(two);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(one.toByteArray());
        byte[] byteData = md.digest();
        return byteData;
    }

    private static byte[] generateRandomBytes(int size) {
        byte[] bytes = new byte[size];
        Random random = new Random();
        for (int i = 0; i < size; i++) {
            bytes[i] = (byte) random.nextInt(125);
        }
        return bytes;
    }

    public static byte[] serializePubKey(PublicKey object) throws Exception{
        PublicKey key = (PublicKey)object;
        return key.getEncoded();
    }

    public static PublicKey deserializePubKey(byte[] bytes) throws Exception{
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(new X509EncodedKeySpec(bytes));
    }

    public static byte[] serializePrivKey(PrivateKey object) throws Exception{
        PrivateKey key = (PrivateKey)object;
        return key.getEncoded();
    }

    static PrivateKey deserializePrivKey(byte[] bytes) throws Exception{
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(new PKCS8EncodedKeySpec(bytes));
    }

    static byte[] serializeKeystore(Map<String, Object> keys) throws Exception{
        if(keys != null){
            Map<String, String> enckeys = new HashMap<>();
            PublicKey pubKey = (PublicKey)keys.get("public");
            PrivateKey privateKey = (PrivateKey)keys.get("private");
            enckeys.put("public", Base64.getEncoder().encodeToString(serializePubKey(pubKey)));
            enckeys.put("private", Base64.getEncoder().encodeToString(serializePrivKey(privateKey)));
            byte[] bytes = null;
            try {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                ObjectOutputStream out = null;
                out = new ObjectOutputStream(bos);
                out.writeObject(enckeys);
                out.close();
                bos.close();
                bytes = bos.toByteArray();
            } catch (Exception e) {
                return null;
            }
            return bytes;
        }else{
            return null;
        }
    }

    static Map<String, Object> deserializeKeystore(byte[] bytes) throws Exception{
        ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
        ObjectInputStream in = null;
        Map<String, String> o = null;
        try {
            in = new ObjectInputStream(bis);
            o = (Map<String, String>)in.readObject();
            in.close();
            bis.close();;
        } catch (Exception e) {
            return null;
        }
        if(o == null){
            return null;
        }
        Map<String, Object> keys = new HashMap<>();
        keys.put("public", deserializePubKey(Base64.getDecoder().decode(o.get("public"))));
        keys.put("private", deserializePrivKey(Base64.getDecoder().decode(o.get("private"))));
        return keys;
    }
}