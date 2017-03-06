package themis.heka.house.themislib.model.secure.keys.shared;

import android.content.SharedPreferences;
import android.util.Base64;

import java.security.KeyStore;

import themis.heka.house.themislib.ThemisActivity;
import themis.heka.house.themislib.api.Themis;
import themis.heka.house.themislib.model.secure.keys.LocallySecuredkeys;
import themis.heka.house.themislib.model.secure.keys.local.LocalEncryptedKey;
import themis.heka.house.themislib.model.secure.keys.local.LocalEncryptionKey;

public class SigningKeys extends LocallySecuredkeys {

    private static String PUBLIC="";
    private static String PRIVATE="";

    private static String PUBLICMAC="";
    private static String PRIVATEMAC="";

    private static String PUBLICNONCE="";
    private static String PRIVATENONCE="";

    private static String PUBLICIV="";
    private static String PRIVATEIV="";

    private static String PUBLICLENGTH="";
    private static String PRIVATELENGTH="";

    public SigningKeys(
            LocalEncryptedKey verifyKey,
            LocalEncryptedKey signingKey,
            KeyStore androidKeys,
            SharedPreferences pref,
            LocalEncryptionKey enc) {
        super(verifyKey, signingKey, androidKeys, pref, enc);
        PUBLIC = "localVerifyKey";
        PRIVATE = "localSigningKey";

        PUBLICNONCE = "localVerifyKeyNonce";
        PRIVATENONCE = "localSigningKeyNonce";

        PUBLICLENGTH = "localVerifyKeyLength";
        PRIVATELENGTH = "localSigningKeyLength";
    }

    protected void storeKeys(String pub, String priv) {
        mPref.edit().putString(PUBLIC, pub).apply();
        mPref.edit().putString(PRIVATE, priv).apply();
    }


    public static boolean isSecure(SharedPreferences storage) {
        String encoded = storage.getString(PRIVATE,"");
        return encoded.length() > 0;
    }

    @Override
    protected String retrievePubKey() {
        byte[] iv = Base64.decode(mPref.getString(PUBLICIV,""), Themis.BASE64_FLAGS);
        byte[] mac = Base64.decode(mPref.getString(PUBLICMAC,""),Themis.BASE64_FLAGS);
        byte[] ciphered = Base64.decode(mPref.getString(PUBLIC,""),Themis.BASE64_FLAGS);
        byte[] localEnc = Themis.androidDecrypt(
                ciphered,
                iv,
                mAndroidKeys);
        return Base64.encodeToString(Themis.decrypt(localEnc, retrievePubNonce().getBytes(),mac, iv, ciphered, mPref.getInt(PUBLICLENGTH, 0), mAndroidKeys), Themis.BASE64_FLAGS);
    }

    @Override
    protected String retrievePrivKey() {
        byte[] iv = Base64.decode(mPref.getString(PRIVATEIV,""),Themis.BASE64_FLAGS);
        byte[] mac = Base64.decode(mPref.getString(PRIVATEMAC,""),Themis.BASE64_FLAGS);
        byte[] ciphered = Base64.decode(mPref.getString(PRIVATE,""),Themis.BASE64_FLAGS);
        byte[] localEnc = Themis.androidDecrypt(
                ciphered,
                iv,
                mAndroidKeys);
        return Base64.encodeToString(Themis.decrypt(localEnc, retrievePrivNonce().getBytes(),mac, iv, ciphered, mPref.getInt(PRIVATELENGTH, 0), mAndroidKeys), Themis.BASE64_FLAGS);
    }

    public static SigningKeys restoreKeys(SharedPreferences storage, KeyStore androidKeys, LocalEncryptionKey lec, Themis themis) {
        byte[] verifyKey = Base64.decode(storage.getString(PRIVATE,""),Themis.BASE64_FLAGS);
        byte[] verifyNonce = Base64.decode(storage.getString(PRIVATENONCE,""),Themis.BASE64_FLAGS);
        int verifyLength = storage.getInt(PRIVATELENGTH,0);
        byte[] verifyIV = Base64.decode(storage.getString(PRIVATEIV,""),Themis.BASE64_FLAGS);
        byte[] verifyMac = Base64.decode(storage.getString(PRIVATEMAC,""),Themis.BASE64_FLAGS);
        LocalEncryptedKey decryptedVerify = themis.decryptLocalEncryptionKey(
                verifyKey,
                verifyNonce,
                verifyLength,
                verifyIV,
                verifyMac);

        byte[] signingKey = Base64.decode(storage.getString(PRIVATE,""),Themis.BASE64_FLAGS);
        byte[] signingNonce = Base64.decode(storage.getString(PRIVATENONCE,""),Themis.BASE64_FLAGS);
        int signingLength = storage.getInt(PRIVATELENGTH,0);
        byte[] signingIV = Base64.decode(storage.getString(PRIVATEIV,""),Themis.BASE64_FLAGS);
        byte[] signingMac = Base64.decode(storage.getString(PRIVATEMAC,""),Themis.BASE64_FLAGS);
        LocalEncryptedKey decryptedSigning = themis.decryptLocalEncryptionKey(
                signingKey,
                signingNonce,
                signingLength,
                signingIV,
                signingMac);

        SigningKeys sk = new SigningKeys(decryptedVerify, decryptedSigning, androidKeys, storage,lec);
        return sk;
    }
}
