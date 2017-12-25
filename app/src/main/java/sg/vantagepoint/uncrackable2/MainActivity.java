package sg.vantagepoint.uncrackable2;

import android.app.Activity;

/**
 * Created by Administrator on 12/23/2017.
 */

public class MainActivity extends Activity {
    static {
        System.loadLibrary("foo");
    }
    private native void init();
    public void Init(){
        init();
    }

}
