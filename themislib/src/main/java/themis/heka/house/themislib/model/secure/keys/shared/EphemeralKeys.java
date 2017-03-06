package themis.heka.house.themislib.model.secure.keys.shared;

import android.content.SharedPreferences;
import android.util.Base64;

import java.security.KeyStore;

import themis.heka.house.themislib.api.Themis;
import themis.heka.house.themislib.model.secure.keys.LocallySecuredkeys;
import themis.heka.house.themislib.model.secure.keys.local.LocalEncryptedKey;
import themis.heka.house.themislib.model.secure.keys.local.LocalEncryptionKey;

public class EphemeralKeys extends LocallySecuredkeys {
    private final String remoteKey;

    private String PUBLIC="";
    private String PRIVATE="";

    private String PUBLICMAC="";
    private String PRIVATEMAC="";

    private String PUBLICNONCE="";
    private String PRIVATENONCE="";

    private String PUBLICIV="";
    private String PRIVATEIV="";

    private String PUBLICLENGTH="";
    private String PRIVATELENGTH="";

    public EphemeralKeys(LocalEncryptedKey publicKey, LocalEncryptedKey privateKey, KeyStore androidKeys, SharedPreferences pref, LocalEncryptionKey enc, String remoteKey) {
        super(publicKey, privateKey, androidKeys, pref, enc);
        this.remoteKey = remoteKey;
        PUBLIC = remoteKey+"/ephemeralPubKey";
        PRIVATE = remoteKey+"/ephemeralPrivKey";

        PUBLICNONCE = remoteKey+"/ephemeralPubKeyNonce";
        PRIVATENONCE = remoteKey+"/ephemeralPrivKeyNonce";

        PUBLICLENGTH = remoteKey+"/ephemeralPubKeyLength";
        PRIVATELENGTH = remoteKey+"/ephemeralPrivKeyLength";
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


    protected void storeKeys(String pub, String priv) {
        mPref.edit().putString(PUBLIC, pub).apply();
        mPref.edit().putString(PRIVATE, priv).apply();
    }

}