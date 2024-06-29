HTB Challenge

All we get is an `.apk`

Now, we can use `apktool` to extract the files, and `jadx-gui` to see the code.

If we look in resources
![[seethesharpflag_1.png]]

We can see that there is a DLL named `SeeTheSharpFlag.dll` and one for android. once we extract those with `apktool`, we run file, which returns something odd.

```
$ file com.companyname.seethesharpflag-x86/unknown/assemblies/SeeTheSharpFlag.dll 
com.companyname.seethesharpflag-x86/unknown/assemblies/SeeTheSharpFlag.dll: Sony PlayStation Audio
```

so, looking at the file, we can see the bytes `XALZ`, this means it was compressed by Xamarin. We can use this tool to decompress it.

https://github.com/NickstaDB/xamarin-decompress

If we decompress the dll, we can look inside. And if we look at the function `Button_Clicked()`, there looks to be something promising.

```
private void Button_Clicked(object sender, EventArgs e)
{
	byte[] array = Convert.FromBase64String("sj[snip]mno=");
	byte[] array2 = Convert.FromBase64String("6[snip]Q==");
	byte[] array3 = Convert.FromBase64String("D[snip]A==");
	using (AesManaged aesManaged = new AesManaged())
	{
		using (ICryptoTransform cryptoTransform = aesManaged.CreateDecryptor(array2, array3))
		{
			using (MemoryStream memoryStream = new MemoryStream(array))
			{
				using (CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, 0))
				{
					using (StreamReader streamReader = new StreamReader(cryptoStream))
					{
						if (streamReader.ReadToEnd() == this.SecretInput.Text)
						{
							this.SecretOutput.Text = "Congratz! You found the secret message";
						}
						else
						{
							this.SecretOutput.Text = "Sorry. Not correct password";
						}
					}
				}
			}
		}
	}
}
```

If we take this code, wholesale, and instead print out the string that comes from streamreader, we get this code below
```csharp
using (AesManaged aesManaged = new AesManaged())
{
    using (ICryptoTransform cryptoTransform = aesManaged.CreateDecryptor(array2, array3))
    {
        using (MemoryStream memoryStream = new MemoryStream(array))
        {
            using (CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, 0))
            {
                using (StreamReader streamReader = new StreamReader(cryptoStream))
                {
                    System.Console.Write(streamReader.ReadToEnd());
                }
            }
        }
    }
}
```

this gets us the flag!

https://www.hackthebox.com/achievement/challenge/158887/241