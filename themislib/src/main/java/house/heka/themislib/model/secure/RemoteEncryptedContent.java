package house.heka.themislib.model.secure;

/**
 * Created by aron2 on 3/6/2017.
 */

public class RemoteEncryptedContent {
    public String tag;
    public byte[] nonce;
    public byte[] content;
    public byte[] remote;
    public int length;

    public RemoteEncryptedContent(byte[] nonce, byte[] content, int length, byte[] remoteKey, String tag) {
        this.nonce = nonce;
        this.content = content;
        this.length = length;
        this.remote = remoteKey;
        this.tag = tag;
    }
}
