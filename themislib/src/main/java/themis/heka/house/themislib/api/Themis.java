package themis.heka.house.themislib.api;

import android.content.Context;
import android.content.SharedPreferences;
import android.support.annotation.NonNull;
import android.util.Base64;
import android.util.Log;

import org.libsodium.jni.Sodium;
import org.libsodium.jni.SodiumConstants;
import org.libsodium.jni.crypto.Random;
import org.libsodium.jni.keys.KeyPair;
import org.libsodium.jni.keys.SigningKey;
import org.libsodium.jni.keys.VerifyKey;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import themis.heka.house.themislib.ThemisActivity;
import themis.heka.house.themislib.model.secure.LocalEncryptedContent;
import themis.heka.house.themislib.model.secure.keys.local.LocalEncryptedKey;
import themis.heka.house.themislib.model.secure.keys.local.LocalEncryptionKey;
import themis.heka.house.themislib.model.secure.keys.shared.EphemeralKeys;
import themis.heka.house.themislib.model.secure.keys.shared.SigningKeys;

public class Themis {

    public static final int BASE64_SAFE_URL_FLAGS = Base64.DEFAULT;
    private static final String TAG = "Themis";
    private final SharedPreferences storage;
    public KeyStore mAndroidKeys = null;
    public LocalEncryptionKey deviceEncryption;
    private SigningKeys signingKeys;
    private Context mActive;

    public static String bytes2String(byte[] bytes) {
        return Base64.encodeToString(bytes, BASE64_SAFE_URL_FLAGS);
    }


    public void generate() {
        byte[] seed = new Random().randomBytes(SodiumConstants.SECRETKEY_BYTES);
        generate(seed);
    }

    /**
     * Generates all sodium keys with a byte[] as seed
     */
    private void generate(byte[] seed) {
        generateDeviceEncryptionKeyPair(seed);
        generateSigningKeyPair(seed);
    }

    /**
     * Generates all sodium keys with a byte[] as seed
     */
    public void generate(KeyPair encryptionKeyPair, SigningKey signingKey) {
        byte[] seed = new Random().randomBytes(SodiumConstants.SECRETKEY_BYTES);
        generateDeviceEncryptionKeyPair(seed);

        seed = new Random().randomBytes(SodiumConstants.SECRETKEY_BYTES);
        generateSigningKeyPair(seed);
    }

    /**
     * Generate Device Encryption Key Pair
     *
     * @param seed as the seed we generated on generate()
     */
    private void generateDeviceEncryptionKeyPair(byte[] seed) {
        Sodium.sodium_init();
        byte[] encryptionSecretKey = new byte[Sodium.crypto_secretbox_keybytes()];
        Sodium.randombytes_buf(encryptionSecretKey, Sodium.crypto_secretbox_keybytes());
        byte[][] encryptedSecret = androidEncrypt(encryptionSecretKey, mAndroidKeys);
        deviceEncryption = new LocalEncryptionKey(encryptedSecret[0], encryptedSecret[1], mAndroidKeys, storage);
    }

    /**
     * Generate Sign Key Pair
     *
     * @param seed as the seed we generated on generate()
     */
    private void generateSigningKeyPair(byte[] seed) {
        SigningKey signingKey = new SigningKey(seed);
        VerifyKey verifyKey = signingKey.getVerifyKey();
        byte[] verifyKeyArray = verifyKey.toBytes();
        byte[] signingKeyArray = signingKey.toBytes();
        signingKeys = new SigningKeys(getLocalEncryptedKey(signingKeyArray), getLocalEncryptedKey(verifyKeyArray), mAndroidKeys, storage, deviceEncryption);
    }

    /*
    * LocalEncryptedKey is an encrypted payload and associated nonce required for LocallySecuredKeys which have double encryption
    * */
    @NonNull
    private LocalEncryptedKey getLocalEncryptedKey(byte[] keyArray) {
        byte[] mac = new byte[Sodium.crypto_secretbox_macbytes()];
        byte[] nonce = new byte[SodiumConstants.XSALSA20_POLY1305_SECRETBOX_NONCEBYTES];
        Sodium.randombytes_buf(nonce, nonce.length);
        byte[] ciphertext = new byte[keyArray.length];

        Sodium.crypto_secretbox_detached(ciphertext, mac, keyArray, keyArray.length, nonce, deviceEncryption.retrievePubKeyBytes());
        byte[][] encryptedSign = androidEncrypt(ciphertext, mAndroidKeys);
        return new LocalEncryptedKey(nonce,encryptedSign[0],mac,encryptedSign[1], keyArray.length);
    }

    @NonNull
    private LocalEncryptedContent getLocalEncryptedContent(String content) {
        byte[] contented = new byte[0];
        byte[] mac = new byte[Sodium.crypto_secretbox_macbytes()];
        byte[] altmac = new byte[Sodium.crypto_secretbox_macbytes()];

        contented = content.getBytes();


        byte[] nonce = new byte[Sodium.crypto_secretbox_noncebytes()];

        Sodium.randombytes_buf(nonce, nonce.length);

        byte[] ciphertext = new byte[contented.length];

//        Sodium.crypto_auth(mac, contented,
//                content.length(), deviceEncryption.retrievePubKeyBytes());

        //first encrypt using device encryption pub key
        Sodium.crypto_secretbox_detached(ciphertext, mac, contented, contented.length, nonce, deviceEncryption.retrievePrivKeyBytes());


//        while (Sodium.crypto_auth_verify(mac, contented, contented.length, deviceEncryption.retrievePubKeyBytes()) < 0) {
//            Log.d(TAG,"mac problems trying again soon");
//            Log.d(TAG,"mac1 "+Base64.encodeToString(mac,Themis.BASE64_SAFE_URL_FLAGS));
//            try {
//                Thread.sleep(5000);
//            } catch (InterruptedException e) {
//                e.printStackTrace();
//            }
//            mac = new byte[Sodium.crypto_secretbox_macbytes()];
//            Sodium.crypto_secretbox_detached(ciphertext, mac, contented, contented.length, nonce, deviceEncryption.retrievePubKeyBytes());
//            Log.d(TAG,"mac2 "+Base64.encodeToString(mac,Themis.BASE64_SAFE_URL_FLAGS));
//        }


        //next encrypt using keystore
        byte[][] encryptedSign = androidEncrypt(ciphertext, mAndroidKeys);


        Log.d(TAG,"original "+content);
        Log.d(TAG,"android iv "+Base64.encodeToString(encryptedSign[0], Themis.BASE64_SAFE_URL_FLAGS));
        Log.d(TAG,"Sodium key "+Base64.encodeToString(deviceEncryption.retrievePubKeyBytes(), Themis.BASE64_SAFE_URL_FLAGS));
        Log.d(TAG,"Sodium encryption "+Base64.encodeToString(ciphertext, Themis.BASE64_SAFE_URL_FLAGS));
        Log.d(TAG,"nonce "+Base64.encodeToString(nonce, Themis.BASE64_SAFE_URL_FLAGS));
        Log.d(TAG,"mac "+Base64.encodeToString(mac, Themis.BASE64_SAFE_URL_FLAGS));
        Log.d(TAG,"altmac "+Base64.encodeToString(altmac, Themis.BASE64_SAFE_URL_FLAGS));
        Log.d(TAG,"Android encryption "+Base64.encodeToString(encryptedSign[1], Themis.BASE64_SAFE_URL_FLAGS));




        return new LocalEncryptedContent(nonce, encryptedSign[0], mac, altmac, encryptedSign[1], contented.length);
    }

    /**
     * Generate Ephemeral Encryption Key Pair
     *
     * @param seed as the seed we generated on generate()
     */
    public EphemeralKeys generateEphemeralEncryptionKeyPair(byte[] seed, String remoteKey) {
        KeyPair encryptionKeyPair = new KeyPair(seed);
        byte[] encryptionPublicKey = encryptionKeyPair.getPublicKey().toBytes();
        byte[] encryptionPrivateKey = encryptionKeyPair.getPrivateKey().toBytes();
        return new EphemeralKeys(getLocalEncryptedKey(encryptionPublicKey), getLocalEncryptedKey(encryptionPrivateKey), mAndroidKeys, storage, deviceEncryption, remoteKey);
    }

    public static byte[] getSharedSecret(byte[] mysecret, byte[] yourpublic) {
        byte[] result = new byte[mysecret.length];
        Sodium.crypto_scalarmult(result, mysecret, yourpublic);
        return result;
    }

    public static byte[] encrypt(byte[] message, byte[] nonce, byte[] key) {
        byte[] ciphertext = new byte[Sodium.crypto_secretbox_macbytes()+message.length];
        Sodium.crypto_secretbox_easy(ciphertext, message, message.length, nonce, key);
        return ciphertext;
    }

    public static byte[] decrypt(byte[] encrypted, byte[] nonce, byte[] mac, byte[] altmac, byte[] iv, byte[] key, int length, KeyStore androidKeys) {
        byte[] decrypted = new byte[length];

        //first unwrap keystore encryption
        byte[] decryptedSign = androidDecrypt(encrypted, iv, androidKeys);

        //next unwrap device encryption
        if (Sodium.crypto_secretbox_open_detached(decrypted, decryptedSign, mac, length, nonce, key) < 0) {
            Log.d(TAG,"secretbox open failed: mac");
            if (Sodium.crypto_secretbox_open_detached(decrypted, decryptedSign, altmac, length, nonce, key) < 0) {
                Log.d(TAG,"secretbox open failed: altmac");
            }
        }


        String decryptedString = new String(decrypted);
        Log.d(TAG,"Android encryption "+Base64.encodeToString(encrypted, Themis.BASE64_SAFE_URL_FLAGS));
        Log.d(TAG,"mac "+Base64.encodeToString(mac, Themis.BASE64_SAFE_URL_FLAGS));
        Log.d(TAG,"altmac "+Base64.encodeToString(altmac, Themis.BASE64_SAFE_URL_FLAGS));
        Log.d(TAG,"nonce "+Base64.encodeToString(nonce, Themis.BASE64_SAFE_URL_FLAGS));
        Log.d(TAG,"Sodium encryption "+Base64.encodeToString(decryptedSign, Themis.BASE64_SAFE_URL_FLAGS));
        Log.d(TAG,"Sodium key "+Base64.encodeToString(key, Themis.BASE64_SAFE_URL_FLAGS));
        Log.d(TAG,"android iv "+Base64.encodeToString(iv, Themis.BASE64_SAFE_URL_FLAGS));
        Log.d(TAG,"original "+decryptedString);


        return decrypted;
    }

    public static String convertToHex(byte[] data) {
        StringBuilder buf = new StringBuilder();
        for (byte b : data) {
            int halfbyte = (b >>> 4) & 0x0F;
            int two_halfs = 0;
            do {
                buf.append((0 <= halfbyte) && (halfbyte <= 9) ? (char) ('0' + halfbyte) : (char) ('a' + (halfbyte - 10)));
                halfbyte = b & 0x0F;
            } while (two_halfs++ < 1);
        }
        return buf.toString();
    }

    public static byte[][] androidEncrypt(byte[] to_enc, KeyStore androidKey) {
        byte[][] result  = new byte[2][0];
        try {
            KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) androidKey.getEntry(ThemisActivity.KEY_ALIAS,null);
            SecretKey key = entry.getSecretKey();
            Cipher c =  Cipher.getInstance("AES/CBC/PKCS7Padding");

            c.init(Cipher.ENCRYPT_MODE, key);
            result[0] = c.getIV();
            result[1] = c.doFinal(to_enc);
            return result;
        } catch (UnrecoverableEntryException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | KeyStoreException | NoSuchPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] androidDecrypt(byte[] to_dec, byte[] iv, KeyStore androidKey) {

        try {
            KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) androidKey.getEntry(ThemisActivity.KEY_ALIAS,null);
            SecretKey key = entry.getSecretKey();
            Cipher c =  Cipher.getInstance("AES/CBC/PKCS7Padding");

            c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            return c.doFinal(to_dec);
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | InvalidKeyException | UnrecoverableEntryException | BadPaddingException | KeyStoreException | NoSuchPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            return null;
        }
    }


    public Themis(ThemisActivity active, KeyStore keyStore) {
        mAndroidKeys = keyStore;
        storage = active.getPreferences(Context.MODE_PRIVATE);
        generate();
    }

    public LocalEncryptedContent encryptLocal(String toEnc) {
        return getLocalEncryptedContent(toEnc);
    }

    public String decryptLocal(LocalEncryptedContent toDec) {
        byte[] decrypted = decrypt(toDec.content, toDec.nonce, toDec.mac, toDec.altmac, toDec.iv, deviceEncryption.retrievePrivKeyBytes(),toDec.length, mAndroidKeys);
        String result = null;
        try {
            result = new String(decrypted, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        ;
        return result;
    }
}
