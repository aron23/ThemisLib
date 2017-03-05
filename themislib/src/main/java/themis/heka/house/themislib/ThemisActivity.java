package themis.heka.house.themislib;

import android.os.Build;
import android.os.Bundle;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;

import org.libsodium.jni.Sodium;
import org.libsodium.jni.SodiumConstants;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Calendar;

import javax.crypto.KeyGenerator;
import javax.security.auth.x500.X500Principal;

import themis.heka.house.themislib.api.Themis;
import themis.heka.house.themislib.model.secure.LocalEncryptedContent;

/**
 * Created by Aron on 3/5/2017.
 */

public class ThemisActivity extends AppCompatActivity {

    private static final String AndroidKeyStore = "AndroidKeyStore";
    private static final String AES_MODE = "AES/GCM/NoPadding";
    public static String KEY_ALIAS = "themis";
    private KeyStore keyStore;
    private Themis themis;
    private String TAG = "ThemisActivity";
    protected String random;

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        try {
            keyStore = KeyStore.getInstance(AndroidKeyStore);
            keyStore.load(null);

            if (!keyStore.containsAlias(KEY_ALIAS)) {
                KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

                KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                        KEY_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);
                builder
                        .setKeySize(256)
                        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7);
                keyGenerator.init(builder.build());
                keyGenerator.generateKey();
                keyStore.getKey(KEY_ALIAS,null);
            }

            themis = new Themis(this,keyStore);



        } catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

    }

    public LocalEncryptedContent encryptForLocalUse(String toEnc) {
        return themis.encryptLocal(toEnc);
    }

    public String decryptForLocalUse(LocalEncryptedContent toDec) {
        return themis.decryptLocal(toDec);
    }

    protected byte[] getRandomBuffer() {
        byte[] contented = "howdy".getBytes();
        byte[] mac = new byte[Sodium.crypto_secretbox_macbytes()];
        byte[] nonce = new byte[SodiumConstants.XSALSA20_POLY1305_SECRETBOX_NONCEBYTES];
        Sodium.randombytes_buf(nonce, SodiumConstants.XSALSA20_POLY1305_SECRETBOX_NONCEBYTES);
        //return nonce;
        byte[] ciphertext = new byte[contented.length];
        Sodium.crypto_secretbox_detached(ciphertext, mac, contented, contented.length, nonce, themis.deviceEncryption.retrievePrivKeyBytes());
        byte[][] encrypted = Themis.androidEncrypt(ciphertext, themis.mAndroidKeys);
        return new LocalEncryptedContent(nonce, encrypted[0], mac,mac, encrypted[1], contented.length).content;
    }}
