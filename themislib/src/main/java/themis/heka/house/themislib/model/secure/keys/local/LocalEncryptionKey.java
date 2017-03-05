package themis.heka.house.themislib.model.secure.keys.local;

import android.content.SharedPreferences;
import android.util.Base64;

import java.security.KeyStore;

import themis.heka.house.themislib.api.Themis;
import themis.heka.house.themislib.model.secure.keys.ThemisKeys;

public class LocalEncryptionKey extends ThemisKeys {

    public static String PUBLIC = "localKeyIV";
    public static String PRIVATE = "localSecretKey";
    private final byte[] iv;

    public LocalEncryptionKey(byte[] iv, byte[] secretKey, KeyStore androidKeys, SharedPreferences pref) {
        super(iv, secretKey, androidKeys, pref);
        this.iv = iv;
    }

    @Override
    protected void storeKeys(String pub, String priv) {
        mPref.edit().putString(PUBLIC, pub).apply();
        mPref.edit().putString(PRIVATE, priv).apply();
    }

    @Override
    public String retrievePubKey() {
        String encoded = mPref.getString(PUBLIC,"");
        return encoded;
    }

    @Override
    protected String retrievePrivKey() {
        String encoded = mPref.getString(PRIVATE,"");
        byte[] decrypted = Themis.androidDecrypt(Base64.decode(encoded.getBytes(), Themis.BASE64_SAFE_URL_FLAGS), iv, mAndroidKeys);
        return Base64.encodeToString(decrypted, Themis.BASE64_SAFE_URL_FLAGS);
    }

}
