package themis.heka.house.themislib.model.secure.keys.shared;

import android.content.SharedPreferences;

import java.security.KeyStore;

import themis.heka.house.themislib.model.secure.keys.LocallySecuredkeys;
import themis.heka.house.themislib.model.secure.keys.local.LocalEncryptedKey;
import themis.heka.house.themislib.model.secure.keys.local.LocalEncryptionKey;

public class EphemeralKeys extends LocallySecuredkeys {
    private final String remoteKey;

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




}