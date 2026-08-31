package a;

import android.app.Activity;
import android.os.Bundle;
import android.view.*;

public class a extends Activity {

    @Override protected void onCreate(Bundle s) {
        super.onCreate(s);
        Window w = getWindow();
        View v = w.getDecorView();
        v.setBackgroundColor(0xFFFF0000);
        v.setSystemUiVisibility(5894);
        w.addFlags(128);
        setBrightness(1f);
    }

    @Override public boolean onTouchEvent(MotionEvent e) {
        float b = e.getX() / getWindow().getDecorView().getWidth();
        setBrightness(b);
        return true;
    }

    void setBrightness(float b) {
        Window w = getWindow();
        WindowManager.LayoutParams p = w.getAttributes();
        p.screenBrightness = b < .01f ? .01f : b > 1f ? 1f : b;
        w.setAttributes(p);
    }
}
