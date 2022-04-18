# SRS LAB2

## Upute za prevođenje
* Preduvjet: instaliran programski jezik Go s minimalnom verzijom 1.18
* Kompajliranje koda pomoću
  * `go build cmd/login/login.go `
  * `go build cmd/usermanagement/usermanagement.go`
  * `go build cmd/cracker/cracker.go`

## Upute za pokretanje
* Preduvjet: instaliran programski jezik Go s minimalnom verzijom 1.18
* Testna skripta
  * `cd test && ./test.sh`
* Pokretanje koda
  * `go run cmd/login/login.go <user>`
  * `go run cmd/usermanagement/usermanagement.go (add|passwd|forcepass|del) <user>`
  * `go run cmd/cracker/cracker.go --password=<password_to_crack>`  
  `--passwords-file=<path_to_passwords_file> [--threads=<number_of_threads>]`  
  `[--argon-memory=<memory_in_bytes>] [--argon-iterations=<iterations>]`  
  `[--argon-paralellism=<parallelism>] [--argon-salt-length=<salt_length_in_bytes>]`  
  `[--argon-key-length=<key_length_in_bytes>]`  

## Opis sustava
* Spremanje podataka
  * Svi podaci se spremaju u SQLite bazu podataka
  * Baza se automatski kreira tijekom pokretanja u trenutnom direktoriju
  * Opis `passwords` tablice:
    ```
    cid  name            type  notnull  dflt_value  pk
    ---  --------------  ----  -------  ----------  --
    0    username        TEXT  0                    1
    1    hashedPassword  TEXT  1                    0
    2    resetPassword   INT   1                    0
    ```
* Password Hashing
  * Za hashing koristi se argon2id algoritam s parametrima definiranima u  
  [RFC 9106](https://www.rfc-editor.org/info/rfc9106) LOW MEMORY profilu
  * Tijekom usporedbe hasheva koristi se funkcija s konstantnim vremenom usporedbe
* Password Strength
  * Za provjeru jačine lozinke koristi se Dropboxov [zxcvbn](https://github.com/dropbox/zxcvbn)  
  algoritam koji svakoj lozinki daje ocjenu jačine od 0 do 4
* Misc.
  * Tijekom resetiranja lozinki radi se provjera je li nova lozinka jednaka staroj
  * Korisniku je dopušteno da maksimalno 3 puta unese krivu lozinku tijekom prijave

## Implementirane zaštite
* Korištena kriptografska funkcija sažetka (argon2id)
* Generiran novi salt tijekom dodavanja novog korisnika, promjene lozinke ili  
promjene parametara hashinga
* Postavljanje minimalne jačine lozinki (zxcvbn ocjena veća ili jednaka 3)
* Lozinke nisu vidljive tijekom upisa
* Prevencija vremenskih napada (timing attack) tijekom usporedbe hasheva korištenjem  
[funkcije s konstantnim vremenom usporedbe](https://pkg.go.dev/crypto/subtle#ConstantTimeCompare)

## Neimplementirane zaštite
* Korištenje peppera tijekom hashinga lozinki
  * Argon2id algoritam je dovoljno otporan na bruteforce napade čak i ako napadač dobi pristup  
  korištenom saltu pod uvjetom da je korištena dovoljno jaka lozinka
* Hashing ili enkripcija korisničkih imena
  * Ako napadač dobi pristup datoteci može vidjeti popis svih korisnika
  * Ovisno o svrhi sustava ovo može, ali i ne mora biti prihvatljivo
    * npr. u slučaju društvene mreže je prihvatljivo
