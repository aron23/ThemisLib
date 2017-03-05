package themis.heka.house.themislib.model.secure.keys.shared;

import android.content.SharedPreferences;

import java.security.KeyStore;

import themis.heka.house.themislib.model.secure.keys.LocallySecuredkeys;
import themis.heka.house.themislib.model.secure.keys.local.LocalEncryptedKey;
import themis.heka.house.themislib.model.secure.keys.local.LocalEncryptionKey;

public class SigningKeys extends LocallySecuredkeys {

    public SigningKeys(LocalEncryptedKey verifyKey, LocalEncryptedKey signingKey, KeyStore androidKeys, SharedPreferences pref, LocalEncryptionKey enc) {
        super(verifyKey, signingKey, androidKeys, pref, enc);
        PUBLIC = "localVerifyKey";
        PRIVATE = "localSigningKey";

        PUBLICNONCE = "localVerifyKeyNonce";
        PRIVATENONCE = "localSigningKeyNonce";

        PUBLICLENGTH = "localVerifyKeyLength";
        PRIVATELENGTH = "localSigningKeyLength";
    }


}
