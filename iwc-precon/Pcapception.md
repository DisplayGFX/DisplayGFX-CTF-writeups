Pcapception
===
IWC Pre-DEFCON

By DisplayGFX

For this one, we are given a pcap, lets open it up and see whats inside

## `pushstartbutton.pcap`

There seems to be a TLS connection, and then there is HTTP traffic.

![pcapception_1.png](https://raw.githubusercontent.com/DisplayGFX/DisplayGFX-CTF-writeups/main/iwc-precon/img/pcapception_1.png)

Inside the tcp traffic, there is two exchanges. A POST request, and a response confirming an upload.

If you use wireshark, and click the post packet, going to `Mime Multipart...` -> `Encapsulated Multipart part`-> `Data` and right click and select `Export Packet Bytes...`, this gets you the data that was sent over the tons of previous packets beforehand.

Looking at the post request in wireshark, you can see it was named `takethis.pcap`, so lets look at this pcap.

## `takethis.pcap`

From this, we can see the traffic here was a bunch of POP packets. If we look at the TCP stream, we can read along with a bunch of emails that were sent. We can also see a username and password for the POP server. There are a bunch of saucy emails included as well.


![pcapception_2.png](https://raw.githubusercontent.com/DisplayGFX/DisplayGFX-CTF-writeups/main/iwc-precon/img/pcapception_2.png)

If we keep scrolling down...

![pcapception_3.png](https://raw.githubusercontent.com/DisplayGFX/DisplayGFX-CTF-writeups/main/iwc-precon/img/pcapception_3.png)

There's a stream of base64 encoded binary, and it looks like our next file. so lets follow the stream, and then saving the ascii output. then open the file in vscode.

In vscode, first delete the extraneous text and there is only base64 strings left, then move the cursor to the beginning of the line, hold `Ctrl`+`Shift`, and hold the down arrow to select every line. Then simply hit backspace. This will delete all of the new lines, leaving only the base64 string.

Then, feed this into `base64 -d > token.pcap`, and we are on to the next pcap.

## `token.pcap`

In this pcap, we can see `FTP` traffic. We can easily just use `File` -> `Export Objects` -> `FTP-DATA...` to extract the next file. `listen.zip`

However, the file is password protected, so lets look at the FTP communication. We can see in the FTP traffic, that the password for `navi` is also sent.

![pcapception_4.png](https://raw.githubusercontent.com/DisplayGFX/DisplayGFX-CTF-writeups/main/iwc-precon/img/pcapception_4.png)

Using this as the password gets into the zip file, we get `listen.pcap` in `tmp`. 

## `listen.pcap`

Another traffic capture, also of FTP. using the same trick as before, we can extract the `sslkeylog.log`. 

Inside the file, we can see the following.

```
SERVER_HANDSHAKE_TRAFFIC_SECRET c1e3acdda340cf51eb54a332ad60a3a4dc7aff05b8a90c3380dbdae0df2a7f5c ac62694979f6d904cc93faff2dffb763848da6a1bc7f646a9292523e46f594b284061bf8a300dc9257c796b76c181506
EXPORTER_SECRET c1e3acdda340cf51eb54a332ad60a3a4dc7aff05b8a90c3380dbdae0df2a7f5c 8b087bcf35039643386e376fbca27d4f8c3268c834f89e8e17781ab1642ac42ca4c0960bf15a3c35813c66d4281800cf
SERVER_TRAFFIC_SECRET_0 c1e3acdda340cf51eb54a332ad60a3a4dc7aff05b8a90c3380dbdae0df2a7f5c 0498e59c5901962edf1413b4d800d54f9ffc43fbb91a09c8c1f7bddc259f80c2bf4da600390fe234b841cdc584e935fc
CLIENT_HANDSHAKE_TRAFFIC_SECRET c1e3acdda340cf51eb54a332ad60a3a4dc7aff05b8a90c3380dbdae0df2a7f5c ed48bad19895a01490fc25f4129f3b193fa5c9e81f90eecec1f57aa571e9a1b993c5e38ec9dc376c2a3b2d169e51d1fe
CLIENT_TRAFFIC_SECRET_0 c1e3acdda340cf51eb54a332ad60a3a4dc7aff05b8a90c3380dbdae0df2a7f5c 4bb16dfad7959a803dcb27d21616550083e5ad77fd42bda2c14e26c8bbcba29fa416fa277e8effaa749ce74025a5a0d1
SERVER_HANDSHAKE_TRAFFIC_SECRET 9787f4f1848ea31ba518f38fe3754bf8d69db432c027592c321b4ce448f1ddd1 5ed1716e7135e68adac570349a17eb74ed67c3e548b9ef27d443612f9442bb2a2234f9f221136bcda0c1075a80f08a93
EXPORTER_SECRET 9787f4f1848ea31ba518f38fe3754bf8d69db432c027592c321b4ce448f1ddd1 d6ecfa03856e61713f2a53818a6c356845e475e7ac1c4a11238b327235b95d84831be808789f0c69025d6e1a01288625
SERVER_TRAFFIC_SECRET_0 9787f4f1848ea31ba518f38fe3754bf8d69db432c027592c321b4ce448f1ddd1 667408ded521f56e3c0c37abef017db228f5020aea2f07a7a4989813d5b15918d26811c734272bed632094b2f5f7da9e
CLIENT_HANDSHAKE_TRAFFIC_SECRET 9787f4f1848ea31ba518f38fe3754bf8d69db432c027592c321b4ce448f1ddd1 b924bb9cbf6e1c5a913f2e2d13a3621a0875bcb30060edb3fecee461ede547d214a44e369112f00ce85e8c03d80b6bc8
CLIENT_TRAFFIC_SECRET_0 9787f4f1848ea31ba518f38fe3754bf8d69db432c027592c321b4ce448f1ddd1 50a8ce09e3045bbbb94190a79f232c0169d68dd1d44373a59769808df5f8fa792638ff3ae09151e35243724fbfdf68f0
SERVER_HANDSHAKE_TRAFFIC_SECRET 43b6e36c8f4762e4e51d09755342e771c12575dae03ca4b429e65c9581f704a3 53e5b4875d58ee8acc441f8e79ad0af82294d8abad7e82b63c2c042e60b7626dffc26456536925204e6b2d2e612ce87f
EXPORTER_SECRET 43b6e36c8f4762e4e51d09755342e771c12575dae03ca4b429e65c9581f704a3 bd8660c35db7ecea2df7569fa97df54b962e0bb5742e4e621e75e2c99d2e26713fcd2e8c6114b6f8695b811b6629c7c1
SERVER_TRAFFIC_SECRET_0 43b6e36c8f4762e4e51d09755342e771c12575dae03ca4b429e65c9581f704a3 a2fed280de43d0c8b2e8db799ad8cd44e6cb319ae008d8c71973946b45b13919c940e5d7651f67e362c563f66e4dcf1b
CLIENT_HANDSHAKE_TRAFFIC_SECRET 43b6e36c8f4762e4e51d09755342e771c12575dae03ca4b429e65c9581f704a3 c9d39b60d6e2850b09d55f5173fa3d29c813cad9bfecad4aeda2908c351c31b271fea05d2ac04fc3fbf314ed6a45a2d7
CLIENT_TRAFFIC_SECRET_0 43b6e36c8f4762e4e51d09755342e771c12575dae03ca4b429e65c9581f704a3 435dd1113ee0c5d0ee09a524daceafa5ef56a9769e4d0a5569630a2e10b3f3d4b75cc38f25b4e9482b3c8e4a72bd298c
```

This seems like decryption keys for TLS. From this, we can set this as our TLS (Pre)-Master-Secret log filename. `File` -> `Protocols` -> `TLS`, and then select the file we just extracted.

From this, if we look at the pcap again, we can see the TLS traffic has been decrypted.

![pcapception_5.png](https://raw.githubusercontent.com/DisplayGFX/DisplayGFX-CTF-writeups/main/iwc-precon/img/pcapception_5.png)

We can once again extract the file via manual scraping

![pcapception_6.png](https://raw.githubusercontent.com/DisplayGFX/DisplayGFX-CTF-writeups/main/iwc-precon/img/pcapception_6.png)

If we look at the image, there doesnt seem to be anything out of the ordinary. Even running `binwalk` on the file doesnt result in anything suspect. But, using `exiftool`, we can see...

The flag!