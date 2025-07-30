# Router Dataplane

In cadrul proiectului am implementat dataplane-ul unui router, realizand procesul
sau de dirijare a pachetelor, dar si partea de control a acestora.

## Cerinte indeplinite:

* Procesul de dirijare - Am implementat transmiterea unui pachet de tip IPv4, urmand pasii din enunt si ghidandu-ma dupa laboratorul 4 unde am invatat acest proces. Astfel, am folosit o tabela de rutare, cu scopul de a determina cea mai buna cale pentru fiecare pachet, iar odata ce aceasta era gasita, pachetele erau trimise mai departe

* Longest Prefix Match(LPM) eficient - Pentru a eficientiza cautarea celei mai bune rute in tabela de rutare, am implementat o structura de tip Trie pentru a stoca adresele IP. Pentru a vedea cum ar trebui gandita logica acestui Trie am cautat pe internet si am gasit un site care m-a ajutat sa inteleg mai bine (https://vinesmsuic.github.io/notes-networkingIP-L3/). Astfel, am adaugat fiecare prefix din tabela in Trie, verificand de fiecare data daca bitul curent e 0 sau 1, pentru a vedea in ce nod voi voi merge mai departe (stanga pentru bitii de 0, dreapta pentru bitii de 1). Odata ce ajungeam la finalul prefixului, adaugam in nod intrarea din tabela. Iar pentru etapa de cautare, am parcurs fiecare prefix si am verificat daca se potriveste cu adresa de destinatie a pachetului, gasind astfel pana la final cea mai buna potrivire.

* Protocolul ARP - Am implementat protocolul ARP, folosind pasii mentionati in cerinta pentru ca acesta sa populeze tabela dinamic. Atfel, atunci cand o adresa nu are o intrare valida in tabela, se va face o cerere ARP, care va fi trimisa mai departe prin interfata. Atunci cand se primeste un ARP reply se creeaza o noua intrare in tabela, continand noile informatii si se vor cauta in coada pachetelor, pachetele care pot fi trimise prin intrarea noastra (restul pachetelor vor fi repuse in coada pentru a fi folosite mai tarziu). Cand se primeste un ARP request, se va intoarce un ARP reply, in cazurile in care adresa MAC a pachetului este egala cu cea a interfetei care a primit cererea.

* Protocolul ICMP - Am implementat protocolul ICMP urmand pasii din cerinta. Astfel, in situatiile in care destinatia este routerul, trimit un mesaj ICMP de tipul "Echo reply", iar atunci cand nu se gaseste ruta pana la destinatie trimit un mesaj "Destination unreachable" sau "Time exceeded" pentru situatiile in care pachetul este aruncat din cauza expirarii campului TTL.