<span style="color:red"><b>Before using the script use the command: pip install cryptography</b></span>


# Implementarea redusă a unui protocol tip Signal
## Schimb de chei + Double Ratchet

---

# A. Schimbul de chei (Handshake – X3DH simplificat)

Protocolul folosește o versiune simplificată a **X3DH (Extended Triple Diffie-Hellman)** pentru a stabili un secret comun inițial între doi utilizatori (Alice și Bob), chiar dacă aceștia nu sunt online simultan.

---

## Chei utilizator

Fiecare utilizator deține:

### Identity Key (IK)
- cheie pe termen lung
- identifică utilizatorul
- folosită pentru autentificare

### Signed PreKey (SPK)
- cheie pe termen mediu
- semnată cu Identity Key
- permite inițierea sesiunilor offline

### One-Time PreKey (OPK)
- cheie de unică folosință (opțional)
- oferă forward secrecy suplimentar

---

## Bundle public

Bob publică pe server: Bundle_Bob = { IK_B, SPK_B, OPK_B? }

Alice descarcă acest bundle pentru inițierea sesiunii.

---

## Pașii handshake-ului

### 1. Generare cheie ephemeral

Alice generează: EK_A
---

### 2. Calcul Diffie–Hellman

Se calculează:

DH1 = DH(IK_A, SPK_B)
DH2 = DH(EK_A, IK_B)
DH3 = DH(EK_A, SPK_B)
DH4 = DH(EK_A, OPK_B) (dacă există)

### 3. Derivare secret inițial

Se concatenează: IKM = DH1 || DH2 || DH3 || DH4

Se aplică HKDF:

---

## Rezultat

Se obține:

- Root Key (RK)
- chei inițiale pentru sesiune

---

## Proprietăți de securitate

- autentificare
- forward secrecy
- suport pentru mesaje offline
- protecție la compromiterea cheilor pe termen lung

---

---

# B. Double Ratchet (Actualizare continuă a cheilor)

După stabilirea Root Key, comunicarea folosește algoritmul **Double Ratchet**, care generează o cheie nouă pentru fiecare mesaj.

Scop: fiecare mesaj este criptat cu o cheie diferită.

---

## Starea internă (State)

Fiecare participant menține:

RK – Root Key
CKs – Chain Key sending
CKr – Chain Key receiving
DHs – cheie DH privată curentă
DHr – cheie DH publică a peer-ului
Ns – număr mesaje trimise
Nr – număr mesaje primite
PN – lungimea lanțului anterior
skipped – chei pentru mesaje out-of-order

---

## Trimiterea unui mesaj

### Derivare cheie mesaj

MK = HMAC(CKs, "mk")
CKs = HMAC(CKs, "ck")

---

### Criptare

ciphertext = AEAD_Encrypt(MK, plaintext)

---

### Header transmis

{ DHs_pub, PN, Ns }

---

## Primirea unui mesaj

### Fără schimbare DH

CKr, MK = KDF_CK(CKr)
plaintext = AEAD_Decrypt(MK)

---

## DH Ratchet Step (la schimbarea cheii DH)

Când se primește un mesaj cu un nou DH public:

### 1. Actualizare lanț primire

RK, CKr = KDF_RK(RK, DH(DHs_priv, DHr_pub_nou))

### 2. Generare cheie DH nouă

DHs_priv_nou = generate()

### 3. Actualizare lanț trimitere

RK, CKs = KDF_RK(RK, DH(DHs_priv_nou, DHr_pub_nou))

---

## Proprietăți de securitate

- forward secrecy
- post-compromise security
- chei unice per mesaj
- rezistență la interceptare
- suport pentru mesaje out-of-order

---

