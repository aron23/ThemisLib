package themis.heka.house.themislib.model;

import android.content.Context;

public abstract class ThemisItem implements Comparable<ThemisItem> {

    public Long themis_key;
    public String asteria_key = null;
    public String app_key;
    protected Context mContext;

    public ThemisItem(Context context) {
        mContext = context;
    }

    public abstract void initAsteria(ThemisItemManager mng);


    public void setAsteriaKey(String key) {
        asteria_key = key;
    }

    public void setAppKey(String key) {
        app_key = key;
    }


    public boolean hasAsteriaKey() {
        if (asteria_key != null)
            return !asteria_key.equals("INIT-REMOTE");
        return asteria_key != null;
    }

    @Override
    public int compareTo(ThemisItem o) {
        if (this.themis_key == o.themis_key) {
            return 0;
        } else if (this.themis_key < o.themis_key) {
            return -1;
        } else {
            return 1;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof ThemisItem)
            return (this.asteria_key == ((ThemisItem) o).asteria_key);
        else
            return false;
    }
}
