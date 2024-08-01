Node Cafe
===

IWC Pre-DEFCON Challenge

By DisplayGFX

We get a link to a website.
## Initial Enumeration

If we look at the website, there are 3 pages. We can verify this by visiting `/wp-sitemap.xml`
```
URL	Last Modified
http://iwc2024.dyn.mctf.io/	
http://iwc2024.dyn.mctf.io/welcome-to-node-cafe-a-dream-brewed-into-reality/	2024-07-27T02:12:13+00:00
http://iwc2024.dyn.mctf.io/our-menu/	2024-07-30T22:58:32+00:00
```

However, this is a full fledged system, not just one port. so.... what if there are other ports on the website?

`nmap` can tell us all about it.

```
┌──(kali㉿kali)-[~]
└─$ nmap -sC -sV iwc2024.dyn.mctf.io -v
...
PORT     STATE    SERVICE      VERSION
22/tcp   open     ssh          OpenSSH 9.6p1 Ubuntu 3ubuntu13.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 8a:39:77:11:36:f6:a5:10:cf:e4:a8:4a:c9:e6:41:f4 (ECDSA)
|_  256 b8:5e:9e:30:d6:0f:ef:fb:ae:18:b4:b0:65:8a:c6:bf (ED25519)
80/tcp   open     http         nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-generator: WordPress 6.6.1
|_http-favicon: Unknown favicon MD5: 3F649DBB38FCD2E36B2C824B1721FDBE
|_http-title: Node Cafe &#8211; Where coffee and laptops meet.
| http-robots.txt: 1 disallowed entry
|_/wp-admin/
135/tcp  filtered msrpc
137/tcp  filtered netbios-ns
138/tcp  filtered netbios-dgm
139/tcp  filtered netbios-ssn
445/tcp  filtered microsoft-ds
8001/tcp open     http         Apache httpd 2.4.61 ((Debian))
|_http-title: Did not follow redirect to http://iwc2024.dyn.mctf.io/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.61 (Debian)
8080/tcp open     http-proxy
| fingerprint-strings:
|   FourOhFourRequest, GetRequest:
|     HTTP/1.0 404 Not Found
|     Content-Type: application/json; charset=utf-8
|     {"error":"resource does not exist","path":"$","code":"not-found"}
|   GenericLines:
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Request
|   HTTPOptions:
|     HTTP/1.0 500 Internal Server Error
|     {"error":"Internal Server Error","path":"$","code":"unexpected"}
|   RTSPRequest:
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|_    Request
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
| http-methods:
|_  Supported Methods: GET POST
8888/tcp open     http         Apache httpd 2.4.58 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.58 (Ubuntu)
```

so, 3 non-filtered, non-redirected ports. 80, 8888, and 8080

Lets see what port 8080 and 8888 returns.

port 8888:
```
[blank]
```

port 8080:
```json
{"error":"resource does not exist","path":"$","code":"not-found"}
```

## GraphQL

port 8080 jumps out as being some sort of database. After a bunch of requests and analyzing, you can discover that this is a GraphQL database. [This article from hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql) has some keywords you can use to brute force identification of the type of database.

For port 8080, if we send a request like so, this will identify all of the capabilities and such of the server.
```http
POST /v1/graphql HTTP/1.1
Host: iwc2024.dyn.mctf.io:8080
Accept: text/html
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 39

{"query":"{  __schema {types {name}}}"}
```

We get back a series of data entries
```json
{"data":{"__schema":{"types":[{"name":"Boolean"},{"name":"Int"},{"name":"Int_comparison_exp"},{"name":"String"},{"name":"String_comparison_exp"},{"name":"__Directive"},{"name":"__EnumValue"},{"name":"__Field"},{"name":"__InputValue"},{"name":"__Schema"},{"name":"__Type"},{"name":"__TypeKind"},{"name":"big_boss_notes"},{"name":"big_boss_notes_bool_exp"},{"name":"big_boss_notes_order_by"},{"name":"big_boss_notes_select_column"},{"name":"big_boss_notes_stream_cursor_input"},{"name":"big_boss_notes_stream_cursor_value_input"},{"name":"cursor_ordering"},{"name":"menu"},{"name":"menu_bool_exp"},{"name":"menu_order_by"},{"name":"menu_select_column"},{"name":"menu_stream_cursor_input"},{"name":"menu_stream_cursor_value_input"},{"name":"money"},{"name":"money_comparison_exp"},{"name":"order_by"},{"name":"query_root"},{"name":"subscription_root"},{"name":"timestamptz"},{"name":"timestamptz_comparison_exp"},{"name":"uuid"},{"name":"uuid_comparison_exp"}]}}}
```

`big_boss_notes` Jumps right out.

If we use [this article](https://medium.com/@osamaavvan/unauthenticated-graphql-introspection-and-api-calls-92f1d9d86bcf)'s json query in combination with the [GraphQL Voyager](https://graphql-kit.com/graphql-voyager/), this is another way of identifying that there is an area that has `big_boss_notes`. But how do we get these notes? Simple, we query for the entire section.
```json
{"query": "{ big_boss_notes { id note } }"}
```

```json
{"data":{"big_boss_notes":[

{"id":1,"note":"Closing notes:\\n1. Ensure all equipment is properly cleaned and turned off, including the espresso machine and grinders.\\n2. Secure the premises by checking all windows and doors are locked, setting the alarm system, and ensuring the cash register and safe are properly secured."},

{"id":2,"note":"Remember this key for the secret! M3-UKWB-145WUTWAT"}
]}}
```

Well, that's a peculiar note, lets keep this in mind while moving on.

## Wordpress

So, there are 3 pages. Here is what the site looks like below.

![nodecafe_1.png](https://raw.githubusercontent.com/DisplayGFX/DisplayGFX-CTF-writeups/main/iwc-precon/img/)

There seems to be some odd machine in the upper right corner. and a similar machine at the end of each page. Moving on, there is not much in terms of things visible to the visible eye. So, next, lets look at the source of the sites. Below is for `Our Menu`

```html
<script>
    async function fetchAndDisplayMenu() {
        const protocol = window.location.protocol;
        const host = window.location.host;

        const query = `
            query MenuItems {
                menu {
                    id
                    name
                    price
                }
            }
        `;

        const response = await fetch(`${protocol}//${host}:8080/v1/graphql`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ query })
        });

        const result = await response.json();

        if (result.errors) {
            document.getElementById('menu-table').innerText = 'Error: ' + result.errors[0].message;
            return;
        }

        const menu = result.data.menu;
        let table = '<table border="2" style="margin: 0 auto; border-collapse: collapse;"><tr><th style="padding: 12px;">Menu Item</th><th style="padding: 12px;">Price</th></tr>';

        menu.forEach(item => {
            table += `<tr><td style="padding: 12px;">${item.name}</td><td style="padding: 12px;">${item.price}</td></tr>`;
        });

        table += '</table>';
        document.getElementById('menu-table').innerHTML = table;
    }

    fetchAndDisplayMenu();
</script>
```

This would be another way of discerning that the database is using GraphQL

But, for the `About Us` page, there is something odd about the source code for this page.
```html
<p>Hello, coffee lovers! I’m thrilled to introduce you to Node Cafe, a passion project that’s been brewing in my heart for years. Nestled in the cozy corner of our vibrant neighborhood, Node Cafe isn’t just another coffee shop—it’s a community hub where technology and creativity meet over a cup of the finest brew.</p>
<p><strong>The Inspiration Behind Node Cafe</strong></p>
<p>As a tech enthusiast and a coffee aficionado, I envisioned a space where these two worlds intersect. The name “Node” reflects our tech roots, a nod to the idea of nodes connecting in a network—much like how we hope our cafe connects people. Here, you can sip on expertly crafted coffee while working on your latest project, attending a coding workshop, or simply enjoying a book.</p>
<p><strong>Our Coffee Philosophy</strong></p>
<p>At Node Cafe, we believe that every cup of coffee tells a story. We source our beans from sustainable farms, supporting fair trade practices and ensuring quality. Our baristas are more than just coffee makers; they’re artisans dedicated to crafting the perfect cup. Whether you’re a fan of a robust espresso or a smooth latte, we have something to delight your palate.</p>
<p><strong>A Space for Everyone</strong></p>
<p>Node Cafe is designed to be a welcoming space for everyone—from remote workers needing a cozy spot to the casual visitor looking for a relaxing environment. We offer free Wi-Fi, plenty of outlets, and comfortable seating, making it an ideal spot for productivity. Plus, our events calendar is packed with workshops, meetups, and live performances to inspire and entertain.</p>
<p><strong>Join Us on This Journey</strong></p>
<p>We’re more than just a coffee shop; we’re a community. We can’t wait to welcome you to Node Cafe and be a part of your daily routine. Come for the coffee, stay for the connections, and let’s create something amazing together.</p>
<p>Thank you for being a part of our journey. Here’s to great coffee and even better conversations!</p>
<p>With warmth and gratitude,</p>
<p>J. T. Query</p>
<p>Owner, Node Cafe</p>
<!-- To our legacy customers, you can visit the old customer portal page at /hello-loyal-customers/index.php -->
```

There's a page that even the sitemap doesn't list. Lets visit it.

![nodecafe_2.png](https://raw.githubusercontent.com/DisplayGFX/DisplayGFX-CTF-writeups/main/iwc-precon/img/nodecafe_2.png)

Well, this seems incredibly basic. Any penetration tester whos faced with a basic login will first try SQL injection.
```
Username:' OR 1=1 --
Password:' OR 1=1 --
```

We get
```
Welcome, ! Here's your encrypted activation secret: ROH{egohreyddibilakivvyrptfagabsunbu}
```

Well well, that seems like... almost a flag. hmm.

## Encryption

So, lets collect everything we know so far.
GraphQL has a note
```
{"id":2,"note":"Remember this key for the secret! M3-UKWB-145WUTWAT"}
```

The site leads to an `encrypted activation secret`
```
ROH{egohreyddibilakivvyrptfagabsunbu}
```

And, its encrypted. 

There is one piece missing from this, the encyrption algorithm. Well, there are hints throughout the wordpress site. Those images of an esoteric machine mentioned briefly earlier are actually called "Enigma Machines". And, if you interpret the `key` as Enigma machine instructions, they do make sense.

So, going to [this website](https://cryptii.com/pipes/enigma-machine) for an enigma decoder, we can set the machine as such.

- M3 - model for the enigma, so Enigma M3
- UKWB - Reflector for the enigma
- 145 - rotors to be set
- WUT - positions for each rotors mentioned above
- WAT - Rings for the same rotos.
And the plugboard is left alone.

Here is the configuration I used on the website

![nodecafe_3.png](https://raw.githubusercontent.com/DisplayGFX/DisplayGFX-CTF-writeups/main/iwc-precon/img/nodecafe_3.png)

And that gets the flag!