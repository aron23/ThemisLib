package themis.heka.house.themislib.model.secure;

public class LocalEncryptedContent {
    public byte[] altmac;
    public byte[] mac;
    public byte[] iv;
    public byte[] nonce;
    public byte[] content;
    public int length;
    public LocalEncryptedContent(byte[] nonce, byte[] iv, byte[] mac, byte[] altmac, byte[] content, int length) {
        this.nonce = nonce;
        this.iv = iv;
        this.content = content;
        this.length = length;
        this.mac = mac;
        this.altmac = altmac;
    }
}

