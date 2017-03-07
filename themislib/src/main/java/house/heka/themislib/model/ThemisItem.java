package house.heka.themislib.model;

import android.content.Context;
import android.support.annotation.NonNull;

import house.heka.themislib.model.secure.RemoteEncryptedContent;

public abstract class ThemisItem implements Comparable<ThemisItem> {

    private final String mTag;
    protected Context mContext;

    public ThemisItem(String tag, Context c) {
        mTag = tag;
        mContext = c;
    }

    public ThemisItem(RemoteEncryptedContent rec, Context c) {
        mTag = rec.tag;
        mContext = c;
        consumeRemoteContent(rec);
    }

    protected abstract void consumeRemoteContent(RemoteEncryptedContent rec);

    protected abstract RemoteEncryptedContent createRemoteContent();

    @Override
    public int compareTo(@NonNull ThemisItem o) {
        return this.mTag.compareTo(o.mTag);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof ThemisItem && (this.mTag.equals(((ThemisItem) o).mTag));
    }
}
