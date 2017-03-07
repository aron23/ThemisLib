package house.heka.themislib.model.secure.keys.local;

import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import java.security.KeyStore;

import house.heka.themislib.api.Themis;
import house.heka.themislib.model.secure.keys.ThemisKeys;

public class LocalEncryptionKey extends ThemisKeys {

    private static final String TAG = "LocalEncryptionKey";
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
        Log.e(TAG, "do not use for encryption");
        return encoded;
    }

    @Override
    protected String retrievePrivKey() {
        String encoded = mPref.getString(PRIVATE,"");
        byte[] decrypted = Themis.androidDecrypt(Base64.decode(encoded.getBytes(), Themis.BASE64_FLAGS), iv, mAndroidKeys);
        return Base64.encodeToString(decrypted, Themis.BASE64_FLAGS);
    }

    public static boolean isSecure(SharedPreferences pref) {
        String encoded = pref.getString(PRIVATE,"");
        return encoded.length() > 0;
    }

    public static LocalEncryptionKey restoreKeys(SharedPreferences storage, KeyStore mAndroidKeys) {
        byte[] iv = Base64.decode(storage.getString(PUBLIC,""),Themis.BASE64_FLAGS);
        byte[] key = Base64.decode(storage.getString(PRIVATE,""),Themis.BASE64_FLAGS);
        //byte[] decrypted = Themis.androidDecrypt(key, iv, mAndroidKeys);
        LocalEncryptionKey lec = new LocalEncryptionKey(iv, key, mAndroidKeys, storage);
        return lec;
    }
}
