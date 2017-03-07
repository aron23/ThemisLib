package house.heka.themislib.model.secure.keys.local;

/**
 * Created by Aron on 3/5/2017.
 */

public class LocalEncryptedKeyData {
    public byte[] mac;
    public byte[] nonce;
    public byte[] content;
    public byte[] iv;
    public int length;
    public LocalEncryptedKeyData(byte[] nonce, byte[] iv, byte[] mac, byte[] content, int length) {
        this.nonce = nonce;
        this.content = content;
        this.iv = iv;
        this.mac = mac;
        this.length = length;
    }
}
