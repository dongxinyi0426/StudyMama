package sg.com.studymama.util;

import org.apache.tomcat.util.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

public class AesEncryptUtil {
    private static final String KEY = "d7b85f6e214abcda";
    private static final String ALGORITHM_STR = "AES/ECB/PKCS5Padding";

    public static String base64Encode(byte[] bytes) {
        return Base64.encodeBase64String(bytes);
    }

    public static byte[] base64Decode(String base64Code) throws Exception {
        return Base64.decodeBase64(base64Code);
    }

    public static byte[] aesEncryptToBytes(String content, String encryptKey) throws Exception {
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);
        Cipher cipher = Cipher.getInstance(ALGORITHM_STR);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encryptKey.getBytes(), "AES"));
        return cipher.doFinal(content.getBytes(StandardCharsets.UTF_8));
    }

    public static String aesEncrypt(String content, String encryptKey) throws Exception {
        return base64Encode(aesEncryptToBytes(content, encryptKey));
    }

    public static String aesDecryptByBytes(byte[] encryptBytes, String decryptKey) throws Exception {
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);
        Cipher cipher = Cipher.getInstance(ALGORITHM_STR);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decryptKey.getBytes(), "AES"));
        byte[] decryptBytes = cipher.doFinal(encryptBytes);
        return new String(decryptBytes, StandardCharsets.UTF_8);
    }

    public static String aesDecrypt(String encryptStr, String decryptKey) throws Exception {

        return aesDecryptByBytes(base64Decode(encryptStr), decryptKey);
    }

//test

    public static void main(String[] args) throws Exception {
        String content = "SingleZhang2021";
        System.out.println("加密前：" + content);

        String encrypt = aesEncrypt(content, KEY);
        System.out.println(encrypt.length() + ":加密后：" + encrypt);

        String decrypt = aesDecrypt(encrypt, KEY);
        System.out.println("解密后：" + decrypt);
    }
}
//var key = CryptoJS.enc.Utf8.parse("abcdef0123456780");
////加密
//function Encrypt(word) {
//    var srcs = CryptoJS.enc.Utf8.parse(word);
//    var encrypted = CryptoJS.AES.encrypt(srcs, key, {
//        mode: CryptoJS.mode.ECB,
//        padding: CryptoJS.pad.Pkcs7
//    });
//    return encrypted.toString();
//}
////解密
//function Decrypt(word) {
//    var decrypt = CryptoJS.AES.decrypt(word, key, {
//        mode: CryptoJS.mode.ECB,
//        padding: CryptoJS.pad.Pkcs7
//    });
//    return CryptoJS.enc.Utf8.stringify(decrypt).toString();
//}
