package themis.heka.house.themislib.model.secure.keys;

import android.content.SharedPreferences;
import android.util.Base64;

import java.security.KeyStore;

import themis.heka.house.themislib.api.Themis;
import themis.heka.house.themislib.model.secure.keys.local.LocalEncryptedKey;
import themis.heka.house.themislib.model.secure.keys.local.LocalEncryptionKey;



public abstract class LocallySecuredkeys extends ThemisKeys {
    final LocalEncryptionKey mEnc;

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
        storeNonces(Base64.encodeToString(publicKey.nonce, Themis.BASE64_FLAGS), Base64.encodeToString(privateKey.nonce, Themis.BASE64_FLAGS));
        storeLength(publicKey.length, privateKey.length);
        storeIV(Base64.encodeToString(publicKey.iv, Themis.BASE64_FLAGS), Base64.encodeToString(privateKey.iv, Themis.BASE64_FLAGS));
        storeMac(Base64.encodeToString(publicKey.mac, Themis.BASE64_FLAGS), Base64.encodeToString(privateKey.mac, Themis.BASE64_FLAGS));
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



    protected String retrievePubNonce() {
        return mPref.getString(PUBLICNONCE, "");
    }


    protected String retrievePrivNonce() {
        return mPref.getString(PRIVATENONCE, "");
    }



}