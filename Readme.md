# vault-hsm-init

a tool to create the AES crypto key and the HMAC key outside of the HSM (using the HSMs random generator) and inject it
into the HSM.

While breaking the nonexportability security of HSM generated keys, it gives you a desaster recovery possiblitiy and
a way to change HSM vendors by being able to recreate the same keys.

Usage is simple:
`vault-hsm-init --slotNo=0 --slotPasswd=secret --module "C:\Program Files\SafeNet\LunaClient\cryptoki.dll" --name=vault-secrets` will 
create a json file `vault-secrets.json` and create the entries `vault-secrets` and `vault-secrets_hmac` in the slot 0 
of the HSM. The output looks like this:
```
2021/03/21 19:05:53 initialized PKCS11 library
2021/03/21 19:05:54 opened PKCS11 session to slot 0
2021/03/21 19:05:54 login successful to PKCS11
2021/03/21 19:05:54 No file "vault-secrets" found, retrying with "vault-secrets.json"
2021/03/21 19:05:54 no json file found, generating new values
2021/03/21 19:05:54 HSM Entries are unused
2021/03/21 19:05:54 Wrapping key created
2021/03/21 19:05:54 Encrypted AES Key
2021/03/21 19:05:55 Wrote AESKey 'vault-secrets' to PKCS11.
2021/03/21 19:05:55 Wrote HMACKey 'vault-secrets_hmac' to PKCS11.
2021/03/21 19:05:55 Write backup file 'vault-secrets.json'
2021/03/21 19:05:55 PKCS11 Stanza for your vault config.hcl:
entropy "seal" {
  mode = "augmentation"
}

seal "pkcs11" {
  lib = "c:\Program Files\SafeNet\LunaClient\cryptoki.dll"
  slot = "0"
  pin = "secret"
  key_label = "vault-secrets"
  hmac_key_label = "vault-secrets_hmac"
}
```

If you need to recreate those entries, simply run the tool again, with the `vault-secrets.json`-File in the working directory.

The tool will not overwrite any existing entries in the HSM with the CKA_LABEL specified.


on Windows you need TDM-GCC (https://jmeubank.github.io/tdm-gcc/download/) to compile
