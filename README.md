## ABOUT JAES
This self-made encryption algorithm.
You can not trust him. A lot of bugs, do not use it!

## Platforms
* CSharp
* NodeJs

## Scheme
![scheme_img](http://i.imgur.com/qzWAGPj.png)

## Example
### NodeJs
``` js
var salt = 'secret_string';

var alice = new JAES256(salt);
var bob = new JAES256(salt);

var crypt = alice.objectEncrypt('shared_key', {test:'This IS My Text',hello:5});

console.log(bob.objectDecrypt('shared_key', crypt));
```
### CSharp
```cs
var salt = "secret_string";
var jaes = new JAES256(salt);

var encrypt = jaes.Encrypt("This IS My DATA", "shared_key");
var decrypt = jaes.Decrypt(encrypt, "shared_key");

Console.WriteLine(decrypt);
```

## Used parts
* T1.CoreUtils (CSharp)
* CryptSharp (CSharp)

## CREDITS
Credits on the code should go to the authors of T1.CoreUtils, CryptSharp and Andrew Mensky
(see links below | later add).