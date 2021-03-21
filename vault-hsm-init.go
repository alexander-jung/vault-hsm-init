package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/miekg/pkcs11"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
)

type Entry struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func main() {
	entryName := flag.String("name", "vault", "the name of your hsm entries. e.g.: 'vault' will produce an entry 'vault' as AES entry and an entry 'vault_hmac' as HMAC entry.\nIf a json file with this name (or with <name>.json) exists, the entries are taken from there.\nThe result is output to a file <name>.json.")
	p11ModulePath := flag.String("module", "c:\\Program Files\\SafeNet\\LunaClient\\cryptoki.dll", "the path to your pkcs11 library")
	slotNo := flag.Uint("slotNo", 0, "the slot number to work with")
	slotPasswd := flag.String("slotPasswd", "", "the PIN/password for this slot")
	flag.Parse()
	// open pkcs11 connection
	p := pkcs11.New(*p11ModulePath)
	err := p.Initialize()
	if err != nil {
		panic(err)
	}
	log.Print("initialized PKCS11 library")

	defer p.Destroy()
	defer p.Finalize()

	session, err := p.OpenSession(*slotNo, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		panic(err)
	}
	defer p.CloseSession(session)
	log.Printf("opened PKCS11 session to slot %d", *slotNo)

	err = p.Login(session, pkcs11.CKU_USER, *slotPasswd)
	if err != nil {
		panic(err)
	}
	defer p.Logout(session)
	log.Print("login successful to PKCS11")

	var hsmEntries []Entry
	var fileRead = false
	// try to read existing file
	jsonFile, err := os.OpenFile(*entryName, os.O_RDONLY, 0444)
	if err != nil { // try again with .json extension
		log.Printf("No file \"%s\" found, retrying with \"%s.json\"", *entryName, *entryName)
		jsonFile, err = os.OpenFile((*entryName)+".json", os.O_RDONLY, 0444)
	}
	if err == nil {
		log.Print("found JSON file, reading it")
		byteValue, err := ioutil.ReadAll(jsonFile)
		if err != nil {
			panic(err)
		}
		err = json.Unmarshal(byteValue, &hsmEntries)
		if err != nil {
			panic(err)
		}
		if len(hsmEntries) != 2 {
			log.Printf("json file needs exactly two entries in an array. Example:\n[\n    {\n        \"name\": \"%s\",\n        \"value\": \"rZ8yXVS4VXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXvBFc=\"\n    },\n    {\n        \"name\": \"%s_hmac\",\n        \"value\": \"dsrXaXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXpWZU=\"\n    }\n]", *entryName, *entryName)
			os.Exit(-1)
		}
		fileRead = true
	} else {
		// generate new values from PKCS11 Random
		log.Print("no json file found, generating new values")
		bytes, err := p.GenerateRandom(session, 32)
		if err != nil {
			panic(err)
		}
		encoded := base64.StdEncoding.EncodeToString(bytes)
		hsmEntries = append(hsmEntries, Entry{Name: *entryName, Value: encoded})
		// generate new values from PKCS11 Random
		bytes, err = p.GenerateRandom(session, 32)
		if err != nil {
			panic(err)
		}
		encoded = base64.StdEncoding.EncodeToString(bytes)
		hsmEntries = append(hsmEntries, Entry{Name: (*entryName) + "_hmac", Value: encoded})
	}

	// check if tokens exist already
	for i := 0; i < len(hsmEntries); i++ {
		template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, hsmEntries[i].Name)}
		err = p.FindObjectsInit(session, template)
		if err != nil {
			panic(err)
		}
		obj, _, err := p.FindObjects(session, 2)
		if err != nil {
			panic(err)
		}
		err = p.FindObjectsFinal(session)
		if err != nil {
			panic(err)
		}
		if obj != nil && len(obj) > 0 {
			log.Printf("Object with CKA_LABEL '%s' exists already in the HSM slot %d", hsmEntries[i].Name, *slotNo)
			os.Exit(-1)
		}
	}
	log.Printf("HSM Entries are unused")
	// now write
	// first create a wrapping key
	wrappingTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "Temp Wrapping AES Key"),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
	}
	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}

	wrappingKeyHandle, err := p.GenerateKey(session, mechanism, wrappingTemplate)
	if err != nil {
		panic(err)
	}
	log.Print("Wrapping key created")
	defer p.DestroyObject(session, wrappingKeyHandle)

	aesBytes, err := base64.StdEncoding.DecodeString(hsmEntries[0].Value)
	if err != nil {
		panic(err)
	}
	mechanism = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, []byte("InitialVectorAES"))}
	err = p.EncryptInit(session, mechanism, wrappingKeyHandle)
	if err != nil {
		panic(err)
	}
	aesCrypted, err := p.Encrypt(session, aesBytes)
	if err != nil {
		panic(err)
	}
	log.Print("Encrypted AES Key")

	// templates from https://www.vaultproject.io/docs/configuration/seal/pkcs11#cka_key_type-1
	aesTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, hsmEntries[0].Name),
		pkcs11.NewAttribute(pkcs11.CKA_ID, uint(rand.Uint32())),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
	}
	_, err = p.UnwrapKey(session, mechanism, wrappingKeyHandle, aesCrypted, aesTemplate)
	if err != nil {
		panic(err)
	}

	log.Printf("Wrote AESKey '%s' to PKCS11.", hsmEntries[0].Name)

	hmacBytes, err := base64.StdEncoding.DecodeString(hsmEntries[1].Value)
	if err != nil {
		panic(err)
	}
	hmacCrypted, err := p.Encrypt(session, hmacBytes)
	if err != nil {
		panic(err)
	}

	hmacTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, hsmEntries[1].Name),
		pkcs11.NewAttribute(pkcs11.CKA_ID, uint(rand.Uint32())),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
	}

	_, err = p.UnwrapKey(session, mechanism, wrappingKeyHandle, hmacCrypted, hmacTemplate)
	if err != nil {
		panic(err)
	}

	log.Printf("Wrote HMACKey '%s' to PKCS11.", hsmEntries[1].Name)

	// write out backup file
	if !fileRead {
		jsonData, err := json.MarshalIndent(hsmEntries, "", "    ")
		if err != nil {
			panic(err)
		}
		err = ioutil.WriteFile((*entryName)+".json", jsonData, 0644)
		if err != nil {
			log.Printf("Cannot write backup to %s.json, last resort: prin out here:", *entryName)
			log.Println(string(jsonData))
			os.Exit(-1)
		} else {
			log.Printf("Write backup file '%s.json'", *entryName)
		}
	} else {
		log.Print("not overwriting input json")
	}
	log.Printf("PKCS11 Stanza for your vault config.hcl:")
	fmt.Printf("entropy \"seal\" {\n  mode = \"augmentation\"\n}\n\nseal \"pkcs11\" {\n  lib = \"%s\"\n  slot = \"%d\""+
		"\n  pin = \"%s\""+
		"\n  key_label = \"%s\""+
		"\n  hmac_key_label = \"%s\""+
		"\n}\n", *p11ModulePath, *slotNo, *slotPasswd, hsmEntries[0].Name, hsmEntries[1].Name)
}
