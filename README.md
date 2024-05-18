# How to use
```c
  CKeyGen gen;
  AddressSet res = gen.GenerateFromString("test");

  string privKey = res.PrivateKey; //9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08
  string wif = res.WIF; //"L2ZovMyTxxQVJmMtfQemgVcB5YmiEDapDwsvX6RqvuWibgUNRiHz"
  string adr1 = res.Addresses[0]; //"19eA3hUfKRt7aZymavdQFXg5EZ6KCVKxr8"
  string adr3 = res.Addresses[1]; //"3PEaV1m4nGi3yTKnzzmqjFTkxzrcFpier5"
  string adrBc = res.Addresses[2]; //"bc1qtmrl9526rusw4dnavrcfal72tz6ram5lqzutru"

```


### Related projects

[AndreyKozhevnikov/net-bitcoin-address-generator](https://github.com/AndreyKozhevnikov/net-bitcoin-address-generator)  (generate Bitcoin public addresses with .NET)  
[AndreyKozhevnikov/c-bitcoin-address-generator](https://github.com/AndreyKozhevnikov/c-bitcoin-address-generator) (generate Bitcoin public addresses with C++)  
[AndreyKozhevnikov/Bitcoin-Address-Generator](https://github.com/AndreyKozhevnikov/Bitcoin-Address-Generator) (generate Bitcoin public addresses with Python)  
[AndreyKozhevnikov/plainSec256k1Net](https://github.com/AndreyKozhevnikov/plainSec256k1Net) (.NET code to calculate a public key from a private key (arrange of bytes) with the  secp256k1 elliptic curve)  

### Tips (btc)

bc1q7uas0hqke0cdp43rnh6u43d2yclhzqzkjav9cj


