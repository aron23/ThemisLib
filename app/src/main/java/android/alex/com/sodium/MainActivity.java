package android.alex.com.sodium;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import org.libsodium.jni.Sodium;
import org.libsodium.jni.SodiumConstants;
import org.libsodium.jni.crypto.Random;
import org.libsodium.jni.keys.KeyPair;
import org.libsodium.jni.keys.SigningKey;
import org.libsodium.jni.keys.VerifyKey;

import themis.heka.house.themislib.ThemisActivity;
import themis.heka.house.themislib.model.secure.LocalEncryptedContent;

public class MainActivity extends ThemisActivity {

    public static final int BASE64_SAFE_URL_FLAGS = Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP;

    private TextView seedView, publicKeyView, privateKeyView, signKeyView, verifyKeyView;
    private Button generateKeys;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        generateKeys = (Button) findViewById(R.id.button);
        generateKeys.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                generate();
            }
        });

    }

    public void generate() {
        publicKeyView = (TextView) findViewById(R.id.textViewPublic);
        privateKeyView = (TextView) findViewById(R.id.textViewPrivate);
        signKeyView = (TextView) findViewById(R.id.textViewSign);
        verifyKeyView = (TextView) findViewById(R.id.textViewVerify);

        String to_test = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Morbi et tempor est, ac rutrum nibh. Suspendisse quis viverra tellus. Nullam quam felis, lobortis ac neque sit amet, pharetra cursus ligula. Proin tincidunt purus ex, non placerat eros ullamcorper porta. Sed consequat luctus dapibus. Cras ac rhoncus turpis. Maecenas consequat felis purus, ac posuere dolor aliquam vitae. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos. Praesent turpis nunc, maximus et eros nec, fringilla finibus sapien.\n" +
                "\n" +
                "Vestibulum orci arcu, facilisis quis eleifend ut, placerat ac ligula. Mauris justo enim, sodales a cursus vel, maximus ut neque. Morbi.";

        LocalEncryptedContent lec = encryptForLocalUse(to_test);
        publicKeyView.setText(Base64.encodeToString(lec.content,BASE64_SAFE_URL_FLAGS));
        String decrypted = decryptForLocalUse(lec);
        privateKeyView.setText(decrypted);




    }


}
