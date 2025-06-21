FastJSON and Furious
===

HTB Challenge

We get one file. `app-release.apk`

## Initial Enumeration

If we look inside with `jadx-gui`, we can see there's a custom package. `hhhkb.ctf.fastjson_and_furious`

In there, we can find a `MainActivity`. Inside is this java code.

```java
public class MainActivity extends AppCompatActivity {
    public static String POSTFIX = "20240227";
    public static boolean succeed = false;

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(C1254R.layout.activity_main);
        Button button = (Button) findViewById(C1254R.id.submit);
        final EditText editText = (EditText) findViewById(C1254R.id.input);
        final TextView textView = (TextView) findViewById(C1254R.id.show_flag);
        button.setOnClickListener(new View.OnClickListener() { // from class: hhhkb.ctf.fastjson_and_furious.MainActivity.1
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                try {
                    System.out.println(JSON.parseObject(editText.getText().toString()));
                } catch (JSONException unused) {
                    textView.setText("That is not my Jason!");
                }
                String calcHash = MainActivity.this.calcHash(editText.getText().toString());
                if (calcHash.length() > 0) {
                    textView.setText("Flag is: " + calcHash);
                    System.out.println(calcHash);
                } else {
                    textView.setText("That is not my Jason!");
                }
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public String calcHash(String str) {
        String str2 = "";
        if (!succeed) {
            return "";
        }
        try {
            JSONObject parseObject = JSON.parseObject(str.replace("\":", POSTFIX + "\":"));
            if (parseObject.keySet().size() != 2) {
                return "";
            }
            for (Object obj : parseObject.keySet().stream().sorted().toArray()) {
                String str3 = (String) obj;
                str2 = str2 + str3 + parseObject.get(str3).toString();
            }
            try {
                MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                messageDigest.update(str2.toLowerCase().getBytes(), 0, str2.length());
                String bigInteger = new BigInteger(1, messageDigest.digest()).toString(16);
                while (bigInteger.length() < 32) {
                    bigInteger = "0" + bigInteger;
                }
                return "HTB{" + bigInteger + "}";
            } catch (NoSuchAlgorithmException unused) {
                return "Something is wrong, contact admin";
            }
        } catch (JSONException unused2) {
            return "";
        }
    }
}
```

So, the application will read in a string, try to convert it from a json string into a json object, then print it out. If it encounters an error, it will print "That is not my Jason!". If it works, the flag will be an MD5 hash of the input, wrapped in curly braces. But there's a variable that gets in the way. Its in the `calcHash` function where the problem lies.

``` java
    public static boolean succeed = false;
    ...
    public String calcHash(String str) {
        String str2 = "";
        if (!succeed) {
            return "";
        }
        try {
        ...
```

We need to somehow override the `succeed` variable. Also of note, there's a flag class.
```java
package hhhkb.ctf.fastjson_and_furious;

/* loaded from: classes2.dex */
public class Flag {
    public void setSuccess(boolean z) {
        MainActivity.succeed = z;
    }
}
```


The way we solve this conundrum is to use an exploit. CVE-2022-25845

## FastJSON Deserialization

Source for the explanation: https://jfrog.com/blog/cve-2022-25845-analyzing-the-fastjson-auto-type-bypass-rce-vulnerability/

By reading the article, we can see that we can make our own java object, and have it use any `set___` functions contained within. So we want to set `Succeeded`, which will change our Boolean in `MainActivity`. If we feed it this json object
```json
{"@type":"hhhkb.ctf.fastjson_and_furious.Flag","Success":true}
```

This will get us the flag!

However, hand writing it is a pain. here's a script that will get us the flag

```python
import hashlib


input_str = "[snip]"
md5_hash = hashlib.md5(input_str.lower().encode()).hexdigest()

# Ensure the hash is 32 characters long by padding with leading zeros if necessary
md5_hash = md5_hash.zfill(32)

flag = "HTB{" + md5_hash + "}"
print(flag)

```


https://www.hackthebox.com/achievement/challenge/158887/745