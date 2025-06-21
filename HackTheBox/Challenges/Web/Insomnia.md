HTB Challenge.

So, looking at the source provided we see in `entrypoint.sh` that there is a user called "administrator".

```sh
...
sqlite3 /var/www/html/Insomnia/database/insomnia.db <<'EOF'
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL
);
INSERT INTO users (username, password) VALUES ('administrator', LOWER(hex(randomblob(16))));
EOF
...
```

then, if we take a look at `Insomnia/app/ProfileController.php`, this page will fetch, and print the flag. However, it will only print if logged in as the administrator user.
```php
$token = (string) $_COOKIE["token"] ?? null;
$flag = file_get_contents(APPPATH . "/../flag.txt");
if (isset($token)) {
	$key = (string) getenv("JWT_SECRET");
	$jwt_decode = JWT::decode($token, new Key($key, "HS256"));
	$username = $jwt_decode->username;
	if ($username == "administrator") {
		return view("ProfilePage", [
			"username" => $username,
			"content" => $flag,
		]);
```

Our goal is to log in as the administrator. Looking at the login function with the `UserController.php`, we can see that the code will query will get a result based on a where clause specified by `$json_data`
```php
$query = $db->table("users")->getWhere($json_data, 1, 0);
$result = $query->getRowArray();
if (!$result) {
	return $this->respond("User not found", 404);
} else {
...
$response = [
		"message" => "Login Succesful",
		"token" => $token,
	];
```

And if we do a login with a user we made with the signup, we can see what the json data will look like.

```
{"username":"hello",
"password":"world"}
```


But here is the vulnerability: It does not check if password is present. So if you alter the request, and leave out the password, it will still log you in. To log in, all we need to send is...

```
{"username":"administrator"}
```

Thats it.

https://www.hackthebox.com/achievement/challenge/158887/610