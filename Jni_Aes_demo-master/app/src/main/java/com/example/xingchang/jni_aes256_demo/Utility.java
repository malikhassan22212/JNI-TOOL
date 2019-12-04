package com.example.xingchang.jni_aes256_demo;
import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Build;
import androidx.annotation.RequiresApi;
import android.util.Log;
import com.google.android.gms.common.util.ArrayUtils;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class Utility {
    private static String aesKeyInBase64 = "kPLU8FffncocYFNbrB6GpebhXiNAWNwcMAi51yuQEHU=";

    @RequiresApi(api = Build.VERSION_CODES.O)
    public static String Serialize(String clearTextContent) {
        byte[] clearTextData = new byte[0];
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            clearTextData = clearTextContent.getBytes(StandardCharsets.UTF_8);
        }

        // Encrypt by AES256
        byte[] encryptedData = AES256Encrypt(clearTextData, aesKeyInBase64);
        Log.d("AES256Encrypt", encryptedData.toString());

        // Add checksum
        byte[] encryptedDataWithChecksum = addSha256Checksum(encryptedData);

        // XOR
        for (int i = 0; i < encryptedDataWithChecksum.length; i++) {
            encryptedDataWithChecksum[i] = (byte) (encryptedDataWithChecksum[i] ^ 0x66);
        }

        return Base64.getEncoder().encodeToString(encryptedDataWithChecksum);

    }

    @SuppressLint("NewApi")
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public static String Deserialize(String encryptedContent) {
        byte[] encryptedData = new byte[0];

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            encryptedData = Base64.getDecoder().decode(encryptedContent);
        }

        //encryptedData = Base64.getUrlDecoder().decode(encryptedContent);
        // XOR
        for (int i = 0; i < encryptedData.length; i++) {
            encryptedData[i] = (byte) (encryptedData[i] ^ 0x66);
        }

        // Validate checksum by SHA256
        byte[] data = Arrays.copyOf(encryptedData, encryptedData.length - 32);
        byte[] checksum = Arrays.copyOfRange(encryptedData, encryptedData.length - 32, encryptedData.length);
        if (!validateSha256Checksum(data, checksum)) {
            return null;
        }

        // Decrypt by AES256
        byte[] clearTextData = AES256Decrypt(data, aesKeyInBase64);
        return new String(clearTextData, StandardCharsets.UTF_8);
    }

    public static boolean validateSha256Checksum(byte[] data, byte[] checksum) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] checksum2 = digest.digest(data);
            return Arrays.equals(checksum, checksum2);
        } catch (Exception e) {
            System.out.println("Error while validate checksum: " + e.toString());
            return false;
        }
    }

    public static byte[] addSha256Checksum(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] checksum = digest.digest(data);
            return ArrayUtils.concatByteArrays(data, checksum);
        } catch (Exception e) {
            System.out.println("Error while validate checksum: " + e.toString());
            return null;
        }
        }

    public static byte[] AES256Decrypt(byte[] encryptedData, String aesKeyInBase64) {
        try {
            byte[] iv = Arrays.copyOf(encryptedData, 16);
            IvParameterSpec ivspec = new IvParameterSpec(iv);
            byte[] aesKey = new byte[0];
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                aesKey = Base64.getDecoder().decode(aesKeyInBase64);
            }
            SecretKeySpec secretKey = new SecretKeySpec(aesKey, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);

            encryptedData = Arrays.copyOfRange(encryptedData, 16, encryptedData.length);
            byte[] clearTextData = cipher.doFinal(encryptedData);
            return clearTextData;
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
            return null;
        }
    }
    public static byte[] AES256Encrypt(byte[] clearTextData, String aesKeyInBase64) {
        try {
            SecureRandom sr = null;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                sr = SecureRandom.getInstanceStrong();
            }
            byte[] iv = new byte[16];
            sr.nextBytes(iv);
            IvParameterSpec ivspec = new IvParameterSpec(iv);
            byte[] aesKey = new byte[0];
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                aesKey = Base64.getDecoder().decode(aesKeyInBase64);
            }

            SecretKeySpec secretKey = new SecretKeySpec(aesKey, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            byte[] encryptedData = cipher.doFinal(clearTextData);
            encryptedData = ArrayUtils.concatByteArrays(iv, encryptedData);
            return encryptedData;
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
            return null;
        }
        }


    public static String getStringFromRes(Context context, int value) {
        return context.getResources().getString(value);
    }


}
