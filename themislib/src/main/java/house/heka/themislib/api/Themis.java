package house.heka.themislib.api;

import android.content.Context;
import android.content.SharedPreferences;
import android.support.annotation.NonNull;
import android.util.Base64;
import android.util.Log;

import org.libsodium.jni.Sodium;
import org.libsodium.jni.SodiumConstants;
import org.libsodium.jni.crypto.Box;
import org.libsodium.jni.crypto.Random;
import org.libsodium.jni.crypto.SecretBox;
import org.libsodium.jni.encoders.Hex;
import org.libsodium.jni.keys.KeyPair;
import org.libsodium.jni.keys.PrivateKey;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import house.heka.themislib.ThemisActivity;
import house.heka.themislib.model.secure.LocalEncryptedContent;
import house.heka.themislib.model.secure.RemoteEncryptedContent;
import house.heka.themislib.model.secure.keys.local.LocalEncryptionKey;

public class Themis {

    public static final int BASE64_FLAGS = Base64.DEFAULT;
    private static final String TAG = "Themis";
    private final SharedPreferences storage;
    public KeyStore mAndroidKeys = null;
    public LocalEncryptionKey deviceEncryption;

    private static byte[] decrypt(byte[] encrypted, byte[] nonce, byte[] iv, LocalEncryptionKey deviceEncryption, KeyStore androidKeys) {

        //first unwrap keystore encryption
        byte[] unwrapped = androidDecrypt(encrypted, iv, androidKeys);

        SecretBox crypto = new SecretBox(deviceEncryption.retrievePrivKeyBytes());

        //next unwrap device encryption
        byte[] decrypted = crypto.decrypt(nonce, unwrapped);


        String decryptedString = new String(decrypted);
        Log.d(TAG,"Android encryption "+Base64.encodeToString(encrypted, Themis.BASE64_FLAGS));
        Log.d(TAG,"nonce "+Base64.encodeToString(nonce, Themis.BASE64_FLAGS));
        Log.d(TAG,"Sodium encryption "+Base64.encodeToString(unwrapped, Themis.BASE64_FLAGS));
        Log.d(TAG,"Sodium key "+Base64.encodeToString(deviceEncryption.retrievePrivKeyBytes(), Themis.BASE64_FLAGS));
        Log.d(TAG,"android iv "+Base64.encodeToString(iv, Themis.BASE64_FLAGS));
        Log.d(TAG,"original "+decryptedString);


        return decrypted;
    }

    private static byte[] decryptRemoteContent(RemoteEncryptedContent rec, SharedPreferences storage, KeyStore androidKeys) {

        String encLocalPrivKey = storage.getString(rec.tag,"");
        String iv = storage.getString(rec.tag+"-iv","");

        //first unwrap keystore encryption
        byte[] localPrivKey = androidDecrypt(
                Base64.decode(encLocalPrivKey,Themis.BASE64_FLAGS),
                Base64.decode(iv,Themis.BASE64_FLAGS),
                androidKeys);


        //next unwrap device encryption
        Box crypto = new Box(rec.remote,localPrivKey);
        byte[] decrypted = crypto.decrypt(rec.nonce, rec.content);



        String decryptedString = new String(decrypted);
        Log.d(TAG,"nonce "+Base64.encodeToString(rec.nonce, Themis.BASE64_FLAGS));
        Log.d(TAG,"Sodium encryption "+Base64.encodeToString(rec.content, Themis.BASE64_FLAGS));
        Log.d(TAG,"Remote key "+Base64.encodeToString(rec.remote, Themis.BASE64_FLAGS));
        Log.d(TAG,"Local key "+Base64.encodeToString(localPrivKey, Themis.BASE64_FLAGS));
        Log.d(TAG,"original "+decryptedString);

        return decrypted;
    }

    public static boolean androidVerify(byte[] signed, byte[] toVerify, byte[] pubKey, KeyStore ks) {

        try {
            KeyStore.Entry entry = ks.getEntry(ThemisActivity.KEY_ALIAS_SIGN, null);
            if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
                Log.w(TAG, "Not an instance of a PrivateKeyEntry");
                return false;
            }
            Signature s = Signature.getInstance("SHA256withECDSA");
            PublicKey publicKey =
                    KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(pubKey));
            s.initVerify(publicKey);
            s.update(signed);
            return s.verify(toVerify);
        } catch (NoSuchAlgorithmException | UnrecoverableEntryException | SignatureException | KeyStoreException | InvalidKeyException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return false;
    }

    public static byte[] androidSign(byte[] toSign, KeyStore ks) {
        KeyStore.Entry entry = null;
        try {
            entry = ks.getEntry(ThemisActivity.KEY_ALIAS_SIGN, null);
            if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
                Log.w(TAG, "Not an instance of a PrivateKeyEntry");
                return null;
            }
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initSign(((KeyStore.PrivateKeyEntry) entry).getPrivateKey());
            s.update(toSign);
            return s.sign();

        } catch (NoSuchAlgorithmException | UnrecoverableEntryException | SignatureException | KeyStoreException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static byte[][] androidEncrypt(byte[] to_enc, KeyStore androidKey) {
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

    private void generate() {
        generateDeviceEncryption();
    }

    private void generateDeviceEncryption() {

        if (LocalEncryptionKey.isSecure(storage)) {
            deviceEncryption = LocalEncryptionKey.restoreKeys(storage,mAndroidKeys);
        } else {
            byte[] encryptionSecretKey = new Random().randomBytes(SodiumConstants.SECRETKEY_BYTES);

            //AES requires IV which is first element, content payload is second
            byte[][] encryptedSecret = androidEncrypt(encryptionSecretKey, mAndroidKeys);
            if (encryptedSecret != null && encryptedSecret.length > 1)
                deviceEncryption = new LocalEncryptionKey(encryptedSecret[0], encryptedSecret[1], mAndroidKeys, storage);
            else
                Log.e(TAG,"encryption failed");
        }
    }

    @NonNull
    private RemoteEncryptedContent getRemoteEncryptedContent(String content) {

        byte[] contented = content.getBytes();


        byte[] nonce = new Random().randomBytes(SodiumConstants.NONCE_BYTES);

        //first encrypt using device encryption pub key
        byte[] seed = new Random().randomBytes(SodiumConstants.SECRETKEY_BYTES);
        KeyPair remote = new KeyPair(seed);
        byte[] remotePubKey = remote.getPublicKey().toBytes();
        byte[] remotePrivKey = remote.getPrivateKey().toBytes();

        KeyPair local = new KeyPair(seed);
        byte[] localPubKey = local.getPublicKey().toBytes();
        byte[] localPrivKey = local.getPrivateKey().toBytes();


        Box crypto = new Box(remotePubKey, localPrivKey);

        byte[] ciphertext = crypto.encrypt(nonce,contented);

        String tag = Base64.encodeToString(localPubKey, Themis.BASE64_FLAGS);

        byte[][] encryptedKey = androidEncrypt(localPrivKey, mAndroidKeys);

        String encryptedKeyString = Base64.encodeToString(encryptedKey[1], Themis.BASE64_FLAGS);
        String ivString = Base64.encodeToString(encryptedKey[0], Themis.BASE64_FLAGS);

        storage.edit().putString(tag,encryptedKeyString).apply();
        storage.edit().putString(tag+"-iv",ivString).apply();

        Log.d(TAG,"original "+content);
        Log.d(TAG,"Remote key "+Base64.encodeToString(remotePubKey, Themis.BASE64_FLAGS));
        Log.d(TAG,"Local key "+Base64.encodeToString(localPrivKey, Themis.BASE64_FLAGS));
        Log.d(TAG,"Sodium encryption "+Base64.encodeToString(ciphertext, Themis.BASE64_FLAGS));
        Log.d(TAG,"nonce "+Base64.encodeToString(nonce, Themis.BASE64_FLAGS));

        return new RemoteEncryptedContent(nonce, ciphertext, contented.length, remotePubKey, tag);
    }

    @NonNull
    private LocalEncryptedContent getLocalEncryptedContent(String content) {

        byte[] contented = content.getBytes();

        byte[] nonce = new Random().randomBytes(SodiumConstants.NONCE_BYTES);

        //first encrypt using device encryption pub key
        SecretBox crypto = new SecretBox(deviceEncryption.retrievePrivKeyBytes());

        byte[] ciphertext = crypto.encrypt(nonce, contented);

        //next encrypt using keystore
        byte[][] encryptedSign = androidEncrypt(ciphertext, mAndroidKeys);

        return new LocalEncryptedContent(nonce, encryptedSign[0], encryptedSign[1], contented.length);
    }

    public void removeRECTag(String tag) {
        storage.edit().remove(tag).apply();
        storage.edit().remove(tag+"-iv").apply();
    }

    public LocalEncryptedContent encryptLocal(String toEnc) {
        return getLocalEncryptedContent(toEnc);
    }

    public String decryptLocal(LocalEncryptedContent toDec) {
        byte[] decrypted = decrypt(
                toDec.content,
                toDec.nonce,
                toDec.iv,
                deviceEncryption,
                mAndroidKeys);
        String result = null;
        try {
            result = new String(decrypted, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        ;
        return result;
    }

    public RemoteEncryptedContent encryptRemote(String toEnc) {
        return getRemoteEncryptedContent(toEnc);
    }

    public String decryptRemote(RemoteEncryptedContent toDec) {
        byte[] decrypted = decryptRemoteContent(toDec,storage,mAndroidKeys);
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
