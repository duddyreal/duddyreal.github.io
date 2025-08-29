---
layout: post
title:  "R3CTF - WEB - Silent Profit"
date:   2025-07-10 16:40:34 +0200
categories: web-writeup
---

## 1 - Reconnaissance

The challenge provided two services:
   * A PHP 8 container hosting a minimalistic PHP page
   * A Node.js container exposing an API endpoint that triggered a Puppeteer-based bot

   ```php
   <?php 
      show_source(__FILE__);
      unserialize($_GET['data']);
   ```

   ```js
   const express = require('express');
   const puppeteer = require('puppeteer');

   const app = express();
   app.use(express.urlencoded({ extended: false }));


   const flag = process.env['FLAG'] ?? 'flag{test_flag}';
   const PORT = process.env?.BOT_PORT || 31337;

   app.post('/report', async (req, res) => {
   const { url } = req.body;

   if (!url || !url.startsWith('http://challenge/')) {
      return res.status(400).send('Invalid URL');
   }

   try {
      console.log(`[+] Visiting: ${url}`);
      const browser = await puppeteer.launch({
         headless: 'new',
         args: [
         '--no-sandbox',
         '--disable-setuid-sandbox',
         ]
      });

      await browser.setCookie({ name: 'flag', value: flag, domain: 'challenge' });
      const page = await browser.newPage();
      await page.goto(url, { waitUntil: 'networkidle2', timeout: 5000 });
      await page.waitForNetworkIdle({timeout: 5000})
      await browser.close();
      res.send('URL visited by bot!');
   } catch (err) {
      console.error(`[!] Error visiting URL:`, err);
      res.status(500).send('Bot error visiting URL');
   }
   });

   app.get('/', (req, res) => {
   res.send(`
      <h2>XSS Bot</h2>
      <form method="POST" action="/report">
         <input type="text" name="url" value="http://challenge/?data=..." style="width: 500px;" />
         <button type="submit">Submit</button>
      </form>
   `);
   });

   app.listen(PORT, () => {
   console.log(`XSS bot running at port ${PORT}`);
   });
   ```
   At first glance, this looked like a classic XSS + bot with cookies challenge (which, to be fair, it kind of is 😅).
   However, there's an unusual twist: on the PHP page, we can spot an `unserialize` call — but interestingly, its result is never actually used anywhere in the code.
   Even more puzzling, there are no user-land gadget classes available that we could leverage for a typical PHP Object Injection exploit.

   The reason I'm focusing on this `unserialize` is because it seems to be the only viable entry point. The idea is to somehow trigger an XSS through unsafe deserialization, and from there, exfiltrate the flag stored in the bot's cookies.

   But these two seemingly innocent lines of code force us to dig deeper — it’s not as straightforward as it first appears. Exploiting this deserialization requires a bit of creativity and a closer look at how the application handles serialized input.

## 2 - Analysis

   One possible workaround could have been to skip the PHP layer entirely and send a request directly to the bot’s webhook, hoping to exfiltrate the cookie.
   However, this approach quickly runs into two major blockers:

   * The bot enforces that the visited URL must be hosted on the http://challenge domain
   * The cookie is set with a domain restriction:

   ```js
   await browser.setCookie({ name: 'flag', value: flag, domain: 'challenge' });
   ```
   This means the flag cookie will only be sent to pages on the challenge domain, effectively preventing any cross-origin exfiltration attempts.

   So, at this point, we don’t have any user-land gadgets available, and the result of the unserialize call is never used.
   This means we can’t rely on most of the classic PHP magic methods like `__toString()`,` __wakeup()`, or` __call()` to trigger anything useful.
   Only a very limited set of magic methods — like `__destruct()` — could potentially be triggered, but they’re not helpful in this specific context.

   So... how do we move forward?

   After thinking about it for a while, I had an idea:
   What if, instead of looking for usable gadgets, I focused on breaking the deserialization process itself?

   Maybe I could inject a payload into a place where it causes an error during unserialize, and somehow leverage that error path to trigger an XSS.

## 3 - Exploitation

   I started experimenting with different payloads that could break the unserialize process.
   One idea was to leverage built-in PHP classes like Exception, which are known to be deserializable, and inject a crafted payload inside them.

   For example, I tried something like this:

   `E:25:"<script>alert(1)</script>";`

   This indeed caused a warning during the deserialization, and I noticed that my payload was actually injected somewhere in the output — which confirmed that the input was processed and reflected.

   However, despite the payload appearing in the response, nothing was being triggered — the JavaScript didn't execute.

   This suggested that the injection point was not inside a context that allowed for XSS, or that there were some sanitization mechanisms or rendering quirks preventing execution.

   At this point, I had to face my worst nightmare:
   diving into how Zend — the PHP engine — actually works, especially when it comes to error handling during deserialization.

   It became clear that if I wanted to exploit the unserialize vulnerability, I needed to understand how PHP internally throws and renders exceptions, and how that could potentially lead to an XSS primitive if certain conditions were met.

   After digging into the [PHP source code](https://github.com/php/php-src), I discovered that PHP handles errors in two distinct ways:

   The first is via the `php_error_docref()` function, which — after following the entire call chain — eventually calls an internal HTML escaping routine, specifically `escape_html()`.
   This ensures that any user-controlled content is properly sanitized before being rendered in the browser.

   The second path is through the lower-level `zend_error()` function.
   Unlike the previous one, this cannot perform HTML escaping, simply because it serves as the core internal error handler within Zend.
   For operational and architectural reasons, it must remain platform-agnostic — supporting not just HTML output, but also CLI, logs, and other environments.

   This subtle difference opened the door to a potential XSS:
   If I could trigger an error that passed through zend_error() directly, any injected HTML would be rendered unescaped, possibly giving me a viable vector.

   Continuing to dig through the PHP 8.4 source code (which was the version used in the challenge), I discovered something very interesting.

   Starting from PHP 8.2, the dynamic creation of class properties has been officially deprecated.
   While reviewing the source under:

   `ext/standard/var_unserializer.re:649`

   ```C
   zend_error(E_DEPRECATED, "Creation of dynamic property %s::$%s is deprecated",
           ZSTR_VAL(obj->ce->name), zend_get_unmangled_property_name(Z_STR_P(&key)));
   ```

   Bingo!

   This means that if we unserialize an object and inject a dynamic property into a class that doesn't define it, PHP will internally call zend_error() — exactly the path that doesn't escape HTML.

   So now we have everything we need:
   We can create a custom class, inject a dynamic property with our XSS payload, and let the unserialize call throw a deprecated warning — which will reflect the payload without escaping it.

   Time to build that class and grab the flag!

## 4 – Making a payload

```php
$js = '</b>&lt;script&gt;alert(1)&lt;/script&gt;<b';

$payload = sprintf(
    'O:13:"PDOException":1:{s:%d:"%s";N;}',
    strlen($js),
    $js
);
echo urlencode($payload);
```

Make the payload and get you're flag!
