package house.heka.librarytest;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;

import house.heka.themislib.ThemisActivity;

public class MainActivity extends ThemisActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }
}
