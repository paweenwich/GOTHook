package me.noip.muminoi.myappnative;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.TextView;

import sg.vantagepoint.uncrackable2.CodeCheck;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Example of a call to a native method
        TextView tv = (TextView) findViewById(R.id.sample_text);
        tv.setText(stringFromJNI());
    }

    public void onClick(View v)
    {
        Log.d("KKK","OnClick");
        sg.vantagepoint.uncrackable2.MainActivity m = new sg.vantagepoint.uncrackable2.MainActivity();
        m.Init();
        Log.d("KKK","After Init");
        CodeCheck c = new CodeCheck();
        Log.d("KKK",""+ c.a("1213"));
    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();
    public native String stringFromJNI2();
}
