package themis.heka.house.themislib.model.secure.keys;

import android.content.SharedPreferences;
import android.util.Base64;

import java.security.KeyStore;

import themis.heka.house.themislib.api.Themis;
import themis.heka.house.themislib.model.secure.keys.local.LocalEncryptedKey;
import themis.heka.house.themislib.model.secure.keys.local.LocalEncryptionKey;



public abstract class LocallySecuredkeys extends ThemisKeys {
    final LocalEncryptionKey mEnc;

    protected String PUBLIC="";
    protected String PRIVATE="";


    protected String PUBLICMAC="";
    protected String PRIVATEMAC="";

    protected String PUBLICNONCE="";
    protected String PRIVATENONCE="";

    protected String PUBLICIV="";
    protected String PRIVATEIV="";

    protected String PUBLICLENGTH="";
    protected  String PRIVATELENGTH="";

    public LocallySecuredkeys(LocalEncryptedKey publicKey, LocalEncryptedKey privateKey, KeyStore androidKeys, SharedPreferences pref, LocalEncryptionKey enc) {
        super(publicKey.content, privateKey.content, androidKeys, pref);
        mEnc = enc;
        storeNonces(Base64.encodeToString(publicKey.nonce, Themis.BASE64_SAFE_URL_FLAGS), Base64.encodeToString(privateKey.nonce, Themis.BASE64_SAFE_URL_FLAGS));
        storeLength(publicKey.length, privateKey.length);
        storeIV(Base64.encodeToString(publicKey.iv, Themis.BASE64_SAFE_URL_FLAGS), Base64.encodeToString(privateKey.iv, Themis.BASE64_SAFE_URL_FLAGS));
        storeMac(Base64.encodeToString(publicKey.mac, Themis.BASE64_SAFE_URL_FLAGS), Base64.encodeToString(privateKey.mac, Themis.BASE64_SAFE_URL_FLAGS));
    }

    protected void storeMac(String pub, String priv) {
        mPref.edit().putString(PUBLICMAC, pub).apply();
        mPref.edit().putString(PRIVATEMAC, priv).apply();
    }
    protected void storeIV(String pub, String priv) {
        mPref.edit().putString(PUBLICIV, pub).apply();
        mPref.edit().putString(PRIVATEIV, priv).apply();
    }

    protected void storeLength(int publicKeyLength, int privateKeyLength) {
        mPref.edit().putInt(PUBLICLENGTH, publicKeyLength).apply();
        mPref.edit().putInt(PRIVATELENGTH, privateKeyLength).apply();
    }


    protected void storeNonces(String pub, String priv) {
        mPref.edit().putString(PUBLICNONCE, pub).apply();
        mPref.edit().putString(PRIVATENONCE, priv).apply();
    }


    protected void storeKeys(String pub, String priv) {
        mPref.edit().putString(PUBLIC, pub).apply();
        mPref.edit().putString(PRIVATE, priv).apply();
    }


    protected String retrievePubNonce() {
        return mPref.getString(PUBLICNONCE, "");
    }


    protected String retrievePrivNonce() {
        return mPref.getString(PRIVATENONCE, "");
    }

    @Override
    protected String retrievePubKey() {
        byte[] iv = Base64.decode(mPref.getString(PUBLICIV,""),Themis.BASE64_SAFE_URL_FLAGS);
        byte[] mac = Base64.decode(mPref.getString(PUBLICMAC,""),Themis.BASE64_SAFE_URL_FLAGS);
        byte[] ciphered = Base64.decode(mPref.getString(PUBLIC,""),Themis.BASE64_SAFE_URL_FLAGS);
        byte[] localEnc = Themis.androidDecrypt(
                ciphered,
                iv,
                mAndroidKeys);
        return Base64.encodeToString(Themis.decrypt(localEnc, retrievePubNonce().getBytes(),mac,mac, iv, ciphered, mPref.getInt(PUBLICLENGTH, 0), mAndroidKeys), Themis.BASE64_SAFE_URL_FLAGS);
    }

    @Override
    protected String retrievePrivKey() {
        byte[] iv = Base64.decode(mPref.getString(PRIVATEIV,""),Themis.BASE64_SAFE_URL_FLAGS);
        byte[] mac = Base64.decode(mPref.getString(PRIVATEMAC,""),Themis.BASE64_SAFE_URL_FLAGS);
        byte[] ciphered = Base64.decode(mPref.getString(PRIVATE,""),Themis.BASE64_SAFE_URL_FLAGS);
        byte[] localEnc = Themis.androidDecrypt(
                ciphered,
                iv,
                mAndroidKeys);
        return Base64.encodeToString(Themis.decrypt(localEnc, retrievePrivNonce().getBytes(),mac,mac, iv, ciphered, mPref.getInt(PRIVATELENGTH, 0), mAndroidKeys), Themis.BASE64_SAFE_URL_FLAGS);
    }

}