package house.heka.themislib;

import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import javax.crypto.KeyGenerator;

import house.heka.themislib.api.Themis;
import house.heka.themislib.model.secure.LocalEncryptedContent;
import house.heka.themislib.model.secure.RemoteEncryptedContent;

public abstract class ThemisActivity extends AppCompatActivity {
    private static final String AndroidKeyStore = "AndroidKeyStore";
    public static String KEY_ALIAS = "themis";
    public static String KEY_ALIAS_SIGN = "themis_sign";
    private Themis themis;
    private String TAG = "ThemisActivity";
    public String verificationKey;

    //public void cleanREC();

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        initializeKeyStore();
    }

    private void initializeKeyStore() {
        //establish keystore and initate Themis
        //every bit of data that is stored gets encrypted via Android keystore
        //AES CBC PKCS7
        try {
            KeyStore keyStore = KeyStore.getInstance(AndroidKeyStore);
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
                keyStore.getKey(KEY_ALIAS_SIGN, null);

                KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
                kpg.initialize(new KeyGenParameterSpec.Builder(
                        KEY_ALIAS_SIGN,
                        KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                        .setDigests(KeyProperties.DIGEST_SHA256,
                                KeyProperties.DIGEST_SHA512)
                        .build());

                KeyPair kp = kpg.generateKeyPair();
                verificationKey = Base64.encodeToString(kp.getPublic().getEncoded(),Themis.BASE64_FLAGS);
            }

            themis = new Themis(this, keyStore);

        } catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | UnrecoverableKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    public LocalEncryptedContent encryptForLocalUse(String toEnc) {
        return themis.encryptLocal(toEnc);
    }

    public String decryptForLocalUse(LocalEncryptedContent toDec) {
        return themis.decryptLocal(toDec);
    }

    public RemoteEncryptedContent encryptForRemoteUse(String toEnc) {
        return themis.encryptRemote(toEnc);
    }

    public String decryptRemote(RemoteEncryptedContent toDec) {
        return themis.decryptRemote(toDec);
    }

    public byte[] sign(String toSign) {
        return Themis.androidSign(toSign.getBytes(), themis.mAndroidKeys);
    }

    public boolean verifyMySignature(String signed, byte[] sig) {

        try {
            final Key key = (PrivateKey) themis.mAndroidKeys.getKey(KEY_ALIAS_SIGN,null);
            final Certificate cert = themis.mAndroidKeys.getCertificate(KEY_ALIAS_SIGN);
            final PublicKey publicKey = cert.getPublicKey();
            return Themis.androidVerify(signed.getBytes(),sig,publicKey.getEncoded(),themis.mAndroidKeys);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }

        return false;
    }

    public boolean verifySignature(String signed, byte[] sig, byte[] pubKey) {

        return Themis.androidVerify(signed.getBytes(),sig,pubKey,themis.mAndroidKeys);
    }
}
