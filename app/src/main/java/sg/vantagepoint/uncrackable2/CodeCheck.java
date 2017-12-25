package sg.vantagepoint.uncrackable2;

/**
 * Created by Administrator on 12/23/2017.
 */

public class CodeCheck {
    private native boolean bar(byte[] paramArrayOfByte);
    public boolean a(String paramString)
    {
        return bar(paramString.getBytes());
    }
}
