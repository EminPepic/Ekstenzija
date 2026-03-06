# Swagger Tester

**Swagger Tester** je alat za automatsko testiranje API endpointa koji kombinuje **Chrome ekstenziju** i **Node.js backend servis** deployan na Render.

Korisnik unosi **Swagger / OpenAPI URL**, bira endpoint i dobija **sigurnosni i performance izvještaj**.

# Svrha projekta

Alat omogućava brzo **sigurnosno profilisanje API endpointa** direktno iz Swagger/OpenAPI dokumentacije bez ručnog sastavljanja zahtjeva.

Automatski:

* učitava API definiciju
* prikazuje dostupne endpoint-e i metode
* pokreće sigurnosne testove
* radi osnovni performance test
* generiše strukturisan izvještaj

# Kako aplikacija radi

1. Korisnik unosi **Swagger/OpenAPI URL** u Chrome ekstenziju
2. Ekstenzija parsira dokument i prikazuje endpoint-e
3. Korisnik bira **endpoint i HTTP metodu**
4. Podaci se šalju backend servisu
5. Backend pokreće sigurnosne i performance testove
6. Generiše se **kompletan report** koji ekstenzija prikazuje
   
# Sigurnosni testovi

Testiraju se najčešće API ranjivosti:

* SQL Injection
* XSS
* Command Injection
* Path Traversal
* SSRF probe
* NoSQL Injection
* Template Injection
* CRLF/Header Injection
* Overlong i stress payload-i

Payload-i se prilagođavaju tipu parametara:

* query
* path
* JSON body
* form-data

# Logika procjene rezultata

Rezultati se procjenjuju analizom:

* HTTP statusa
* sadržaja odgovora
* poređenja sa baseline odgovorom
* refleksije payload-a
* SQL error markera
* promjena u odgovoru
* anomalija u vremenu odziva

Status testa može biti:

* **Passed** – payload je blokiran ili bezbjedno obrađen
* **Failed** – indikatori ranjivosti
* **Inconclusive** – rezultat nije jasan

# Izvještaj sadrži

* ukupan broj testova
* Passed / Failed / Inconclusive rezultate
* security score i risk level
* detaljne nalaze po testu
* performance metrike (latency, requests/sec, errors)
* automatski generisan zaključak i preporuke

# Struktura projekta

swagger-plugin/
Chrome ekstenzija (UI i pokretanje testova)

Node-backend/
Express servis za izvršavanje testova

render.yaml
Render deploy konfiguracija
```

# Backend deployment

Backend servis:

https://swagger-tester-backend.onrender.com

Health check:

https://swagger-tester-backend.onrender.com/health

Pokretanje testiranja:
```
POST /run-test
```
*automatsko testiranje API sigurnosti i performansi**.
