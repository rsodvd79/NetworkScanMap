# NetworkScanMap

Applicazione desktop **Rust + eframe/egui** per scoprire apparati IPv4, rappresentare
una topologia, salvare mappe e monitorare la raggiungibilita. Nessuna dipendenza da
Nmap, shell, Npcap o libpcap. Usare esclusivamente su reti per cui si dispone
dell'autorizzazione.

## Build e avvio

Installare Rust stable, un compilatore/linker nativo e le librerie grafiche del
sistema. Su Linux sono richieste le librerie di sviluppo X11/Wayland/EGL e
xkbcommon (vedere `.github/workflows/ci.yml`). Le finestre file su Linux usano
il portale desktop XDG; occorre un servizio `xdg-desktop-portal` funzionante.

```sh
cargo build --release --locked
cargo run --release --locked
```

Il binario e in `target/release/network-scan-map` (`.exe` su Windows).
Non e un installer firmato. Per una dimostrazione con 500 apparati sintetici,
senza scansioni automatiche:

```sh
cargo run --release --locked -- --demo
```

`--network-info` stampa interfacce, route e vicini locali e termina.
`--smoke-test` apre la finestra e la chiude dopo alcuni frame, senza scansioni.

## Utilizzo

1. Inserire subnet CIDR, per esempio `192.168.1.0/24`, separate da spazi, virgole o
   righe. All'avvio viene proposta la subnet IPv4 locale, preferendo
   l'interfaccia della route predefinita, senza scansioni automatiche.
   Valori gia inseriti o caricati non vengono sovrascritti.
   Il contesto distingue mappe di reti differenti con IP sovrapposti.
   La selezione interfaccia filtra evidenze locali; le sonde seguono le route OS.
2. Impostare sonde/limiti; avviare **Scansiona / aggiorna mappa**. Nessuna scansione
   parte all'avvio. La GUI resta utilizzabile; **Annulla** conserva risultati
   parziali senza cancellare la mappa precedente.
3. Per la topologia configurare community **SNMPv2c in sola lettura**, comune
   alle subnet oppure specifica per IP. Gli IP specifici devono appartenere alle
   subnet di scansione. Dispositivi che rispondono solo a SNMP possono essere
   scoperti quando hanno un profilo configurato.
4. Trascinare nodi; usare rotella per zoom e trascinare lo sfondo per pan.
   Selezionare un nodo per dettagli, nome, note e collegamenti manuali.
   La rimozione di un apparato richiede conferma; permette anche di risolvere
   identita obsolete dopo un riuso DHCP. IP condivisi/ambigui non vengono
   monitorati come se identificassero un unico apparato.
   **Ridisponi** cambia esplicitamente il layout; le scansioni conservano le
   coordinate esistenti.
5. **Salva / Apri** usano JSON versionato, con impostazioni, coordinate,
   osservazioni, collegamenti ed eventi. Le community restano solo in memoria
   e devono essere reinserite dopo il caricamento. La scrittura usa un file
   temporaneo e sostituzione atomica; gli errori di caricamento non sostituiscono
   la mappa corrente.
6. Abilitare **Monitoraggio attivo** per gli apparati nel contesto selezionato
   e nelle subnet autorizzate, oppure inseriti manualmente. Il monitoraggio
   si sospende durante una scansione e riprende dopo; termina chiudendo l'app.
   I dettagli dell'apparato mostrano la latenza dell'ultima risposta ICMP, TCP
   o SNMP; durante il monitoraggio si aggiorna appena arriva una risposta.
   Un esito senza risposta valida rimuove la latenza corrente.

Valori iniziali: 4096 indirizzi distinti, 32 worker, timeout 1000 ms, porte
TCP 22/80/443, monitoraggio ogni 30 secondi, soglia di 3 cicli negativi.
Il timeout e per fase ICMP/TCP/SNMP; la durata totale del ciclo dipende da
apparati, sonde e interrogazioni topologiche. Non si accodano cicli sovrapposti.
Il registro mantiene gli ultimi 10000 eventi, con timestamp Unix in secondi.

## Interpretazione corretta

- **Blu continuo**: adiacenza pubblicata in LLDP-MIB, con porte e fonte.
- **Giallo tratteggiato**: relazione dedotta da FDB o route; non prova un
  collegamento fisico diretto. I raggruppamenti subnet sono esclusivamente logici.
- **Viola**: collegamento manuale. Le scansioni non lo rimuovono.
- **Grigio / storico**: evidenza precedente non aggiornata.
- Stato **raggiungibile**, **in verifica**, **non raggiungibile**, **sconosciuto**
  indicato anche testualmente. Una risposta ripristina raggiungibile; tre cicli
  negativi indicano non raggiungibile. **Non significa certamente spento**:
  firewall e ACL possono bloccare le sonde.

ICMP puo essere limitato dal sistema operativo: non viene richiesta elevazione
automatica, e TCP resta il fallback. Una connessione TCP rifiutata e una risposta,
non un timeout. Un host che filtra ogni sonda puo essere invisibile.
MAC e vicini locali sono arricchimento, non prova di presenza; non viene
attribuito agli host remoti il MAC del gateway.
Per i MAC unicast universali l'app mostra il prefisso e, quando riconosciuto,
un produttore OUI probabile da un elenco integrato parziale. Segnala inoltre
indirizzi multicast/broadcast e MAC localmente amministrati, spesso randomizzati;
per questi ultimi non presume un produttore.

### MAC su macOS 27

macOS 27 limita deliberatamente la lettura delle informazioni di topologia:
una query ARP puo restituire un elenco vuoto senza errore e le API route possono
restituire il segnaposto `02:00:00:00:00:00` al posto dei MAC reali.
L'app segnala questo limite e scarta il segnaposto. I MAC disponibili vengono
mostrati anche sui nodi del diagramma e nei tooltip, oltre che nei dettagli.

Apple indica la capability **Network Topology Observation**, con entitlement
`com.apple.developer.networking.topology-observation`. E un entitlement ristretto:
deve essere autorizzato da un **provisioning profile** e incluso nella firma
dell'applicazione. In Xcode 27 si abilita dalle capability del target macOS.
Il file `macos/NetworkScanMap.entitlements` contiene la chiave da includere
in una build firmata/provisionata correttamente.

Il normale binario `cargo build` e una firma ad hoc non forniscono questa
autorizzazione. Non vengono usati privilegi elevati o comandi esterni per
aggirare la protezione. La versione autorizzata va collaudata con un profilo
Apple Developer valido, non disponibile nell'ambiente di sviluppo corrente.

Riferimento Apple DTS:
https://developer.apple.com/forums/thread/841958

SNMPv2c **non cifra la community**: usare solo reti di gestione fidate.
Non si eseguono SET, tentativi con community predefinite o discovery oltre i
range configurati. Le tabelle LLDP richiedono switch gestiti e accesso alle MIB;
FDB e VLAN non garantiscono la posizione fisica degli host. Vicini senza IP
possono essere rappresentati, ma non monitorati. La mappa e inevitabilmente
parziale su apparati non gestiti o senza credenziali.

## Verifiche

```sh
cargo fmt --all -- --check
cargo test --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo build --release --locked
```

I test usano loopback e fixture sintetiche: nessuna scansione LAN nei test.
La CI e predisposta per macOS, Windows e Linux. Una matrice CI non sostituisce
prove su switch reali o delle API native con le politiche di rete locali.

Non inclusi: IPv6, SNMPv3, CDP, cattura ARP attiva, servizio in background,
notifiche desktop, scansione completa porte/OS, grafici di banda.
Il piano originale e in `PLAN.md`.

### Stato delle verifiche locali

Su macOS: test automatici (loopback ICMP/TCP, agente SNMP simulato, persistenza,
merge, monitoraggio e canvas), formatter, Clippy e build release superati.
Avvio/chiusura GUI reale verificati con `--smoke-test --demo` (500 nodi).
Interfacce e route lette tramite API native, senza sonde LAN.
I binding Windows e fixture dei parser Linux sono stati controllati, ma
**Windows/Linux a runtime e switch reali non sono stati verificati** in questo
ambiente. La CI verra eseguita quando il progetto sara pubblicato su GitHub.
