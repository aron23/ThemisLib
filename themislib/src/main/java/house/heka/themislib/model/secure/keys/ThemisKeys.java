package house.heka.themislib.model.secure.keys;

import android.content.SharedPreferences;
import android.util.Base64;

import java.security.KeyStore;

import house.heka.themislib.api.Themis;


public abstract class ThemisKeys {
    protected final SharedPreferences mPref;
    protected final KeyStore mAndroidKeys;

    public ThemisKeys(byte[] publicKey, byte[] privateKey, KeyStore androidKeys, SharedPreferences pref) {
        mPref = pref;
        storeKeys(Base64.encodeToString(publicKey, Themis.BASE64_FLAGS),Base64.encodeToString(privateKey, Themis.BASE64_FLAGS));
        mAndroidKeys = androidKeys;
    }

    protected abstract void storeKeys(String pub, String priv);

    protected abstract String retrievePubKey();

    protected abstract String retrievePrivKey();


    public byte[] retrievePrivKeyBytes() {
        return Base64.decode(retrievePrivKey(),Themis.BASE64_FLAGS);
    }

    public byte[] retrievePubKeyBytes() {
        return Base64.decode(retrievePubKey(),Themis.BASE64_FLAGS);
    }
}
