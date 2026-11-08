# NetworkScanMap - Piano di implementazione

## Obiettivo

Creare un'applicazione desktop in Rust + eframe/egui per macOS, Windows e Linux che scopra apparati in una o piu subnet IPv4, ricostruisca dove possibile i collegamenti, visualizzi una mappa interattiva, la salvi/ricarichi/aggiorni e monitori la raggiungibilita degli apparati.

## Stato iniziale verificato durante la pianificazione

- `/Users/daviderosa/Programmazione/NetworkScanMap` e una cartella vuota, senza sorgenti, manifest, test o repository Git.
- Sul Mac sono disponibili `cargo` e `rustc`. Nmap e installato, ma NON sara utilizzato.
- Nessun file del progetto e stato modificato durante la pianificazione.
- La compilazione e il funzionamento sugli altri sistemi devono essere verificati sui rispettivi ambienti: il solo Mac non basta.

## Decisioni confermate

- Applicazione desktop nativa per macOS, Windows e Linux; interfaccia iniziale in italiano.
- Discovery implementato in Rust senza Nmap, comandi di shell o driver di cattura obbligatori.
- ICMP tramite API/socket del sistema, fallback con connessioni TCP e lettura delle tabelle vicini per MAC/IP.
- Topologia fisica tramite informazioni LLDP esposte via SNMP e tabelle bridge/FDB; fallback logico per subnet/gateway.
- SNMPv2c in sola lettura. Community inserite esplicitamente, mantenute solo in memoria; niente tentativi con credenziali predefinite.
- File JSON versionato con apparati, collegamenti, coordinate, impostazioni ed eventi recenti. Nessuna credenziale nei file o nei log.
- Nodi trascinabili, nomi e note modificabili, collegamenti manuali conservati nelle successive scansioni.
- Monitoraggio solo mentre l'applicazione e aperta; stato nel diagramma e registro eventi. Nessuna scansione automatica all'avvio.
- Valori iniziali configurabili: massimo 4096 indirizzi distinti per scansione, intervallo monitoraggio 30 secondi, timeout sonda 1 secondo, non raggiungibile dopo 3 cicli negativi consecutivi.
- Vista unica con gruppi per subnet, disposizione automatica iniziale, zoom/pan, ricerca e dettagli. Obiettivo di usabilita: 500 apparati visualizzati, non un tetto rigido agli apparati salvati.
- Registro limitato agli ultimi 10000 eventi.
- Esclusi dalla prima versione: IPv6, SNMPv3, CDP proprietario, cattura ARP attiva, agenti remoti, servizio in background, notifiche desktop, scansione completa porte/OS, grafici di banda e installer firmati.

## Limiti da rappresentare correttamente

- Una mancata risposta non dimostra che un apparato sia spento: usare gli stati "raggiungibile", "in verifica", "non raggiungibile" e "sconosciuto".
- ICMP puo essere vietato e TCP puo essere filtrato. Segnalare metodi disponibili e copertura parziale, senza promettere discovery completo.
- Le tabelle vicini sono locali all'interfaccia/LAN: per reti instradate il MAC osservato puo essere quello del gateway, mai attribuirlo all'host remoto.
- Non inviare LLDP multicast: interrogare via SNMP le tabelle LLDP degli apparati gestiti.
- LLDP puo documentare adiacenze; una FDB mostra MAC appresi su porte, non prova da sola un collegamento fisico diretto.
- Distinguere graficamente e nei dettagli collegamenti rilevati, dedotti e manuali. La comune subnet non prova un cavo o uno switch condiviso.
- Gateway e route provengono da evidenze locali/SNMP; per subnet remote senza evidenze usare un gruppo logico, non inventare un gateway.
- Apparati non gestiti o credenziali mancanti possono rendere la topologia incompleta. Un vicino LLDP senza IP puo essere un nodo identificato ma non monitorabile.
- Una cache vicini o una FDB storica non e prova di raggiungibilita attuale.
- SNMPv2c trasmette la community senza cifratura: mostrarne il limite e raccomandare reti di gestione fidate.

## Architettura minima

Un solo package Cargo, senza workspace, server, plugin o framework a grafo aggiuntivi.

Struttura prevista, da accorpare se qualche modulo resta piccolo:

- `Cargo.toml`, `Cargo.lock`: dipendenze e versioni bloccate compatibili con il toolchain scelto.
- `src/main.rs`: avvio desktop.
- `src/app.rs`: stato UI, comandi, pannelli, ricezione eventi dei worker.
- `src/model.rs`: apparati, interfacce, collegamenti, osservazioni, impostazioni, eventi e merge.
- `src/discovery.rs`: pianificazione indirizzi, sonde, arricchimento e avanzamento.
- `src/platform/`: adattatori condizionali per ICMP, interfacce, route e tabelle vicini.
- `src/topology.rs`: interrogazioni SNMP, normalizzazione e correlazione LLDP/FDB.
- `src/monitor.rs`: pianificazione cicli e transizioni di raggiungibilita.
- `src/diagram.rs`: canvas egui, layout e interazioni.
- `src/storage.rs`: lettura, validazione e scrittura JSON sicura.
- `tests/`: solo test di integrazione e fixture necessarie ai percorsi principali.
- `README.md` e `.github/workflows/ci.yml`: istruzioni e verifiche multipiattaforma, quando si implementera.

Dipendenze candidate: `eframe` con la versione di `egui` corrispondente, `serde`/`serde_json`, `ipnet`, `rfd`, `snmp2`, `socket2`, binding OS mirati (`windows-sys`, `libc` e una libreria Netlink se necessaria), errori contestuali tramite `anyhow` o `thiserror` dove utile.

Verificare API, compatibilita, manutenzione e licenze prima di fissare le versioni. `snmp2` offre GET/GETNEXT/GETBULK: usare OID numerici, senza feature MIB/libnetsnmp o crittografia SNMPv3. Nessuna dipendenza da Npcap/libpcap.

La GUI possiede il modello. Worker con concorrenza limitata eseguono rete e I/O e inviano eventi tramite canali; niente sonde o letture bloccanti nel callback UI. Partire da thread e canali standard, senza introdurre un runtime async se non necessario. Un coordinatore serializza scansioni, aggiornamenti e monitoraggio.

## Todo e ordine di implementazione

### 1. Verificare discovery nativo e creare la base

- Creare il package e una finestra eframe minima; fissare le versioni e il toolchain supportato.
- Verificare ICMP e lettura interfacce/route/vicini su ciascun sistema: IP Helper su Windows; socket ICMP e API route/sysctl su macOS; socket ICMP e Netlink su Linux.
- Isolare l'eventuale `unsafe` nei binding OS, con controllo dimensioni/buffer, ownership degli handle e motivazione degli invarianti.
- Provare ICMP con utente normale e gestire il rifiuto dei permessi senza crash o elevazione automatica. Fallback TCP sempre disponibile.
- Selezionare pochi tentativi TCP iniziali (22, 80, 443), modificabili dall'utente. Connessione riuscita o rifiuto attribuibile al destinatario indicano una risposta; timeout/errore locale no.
- Distinguere problemi locali di rete dai risultati negativi dell'host. Verificare che non vengano usati eseguibili esterni.
- Dipendenze: nessuna.

### 2. Definire modello, identita e aggiornamento

- ID interni stabili indipendenti dall'IP; osservazioni con provenienza e timestamp, indirizzi/interfacce, identita SNMP/LLDP, MAC validati e metadati manuali.
- Collegamenti con endpoint/porte, origine, evidenza, ultima osservazione e stato storico.
- Correlare identita forti compatibili prima dell'IP; non assumere MAC/chassis ID sempre globalmente univoci. Conservare conflitti e casi ambigui senza fusioni distruttive.
- In assenza di identita forte conservare ID per IP nel relativo contesto di rete, segnalando possibile riuso DHCP.
- Il merge aggiorna dati osservati ma preserva posizioni, nomi/note personalizzati e collegamenti manuali.
- Conservare gli apparati non ritrovati. Marcare evidenze obsolete solo dopo una rilevazione pertinente completata; scansioni fallite/parziali non cancellano la mappa.
- Dipendenze: 1.

### 3. Implementare scansione IPv4

- UI per una o piu subnet CIDR, interfaccia/contesto di rete e impostazioni delle sonde.
- Validare input, unire intervalli e contare indirizzi prima di enumerarli; impedire espansioni enormi e scansioni oltre il limite configurato.
- Gestire sovrapposizioni, duplicati, /31 e /32; escludere network/broadcast solo dove applicabile e destinazioni non unicast.
- Sonde ICMP/TCP con timeout, concorrenza limitata, cancellazione e avanzamento. Leggere vicini e route come arricchimento, senza considerarli prova di presenza.
- Consentire apparati/IP manuali e seed SNMP espliciti: un dispositivo accessibile solo via SNMP non deve essere escluso per il fallimento ICMP/TCP.
- Nomi DNS, se aggiunti, devono avere budget limitato e non bloccare la scansione.
- Dipendenze: 1, 2.

### 4. Ricostruire topologia SNMP

- Profili SNMPv2c per apparati/subnet, UDP 161, timeout/retry limitati e community solo in memoria.
- Richieste solo GET/GETNEXT/GETBULK; nessun SET. Nessuna esplorazione automatica fuori dalle subnet autorizzate.
- Leggere SYSTEM/IF-MIB, LLDP-MIB e BRIDGE-MIB; Q-BRIDGE-MIB dove disponibile per FDB con contesto VLAN.
- Walk limitati per righe/durata, con controllo avanzamento OID, fine subtree, risposte malformate e agenti che ripetono dati.
- Correlare chassis ID, port ID, indirizzi di gestione, bridge-port e ifIndex: non assumere che gli indici coincidano.
- Deduplificare osservazioni reciproche preservando collegamenti paralleli tra porte. Conservare vicini non risolvibili come tali.
- Usare LLDP come evidenza di adiacenza; usare FDB come indizio, evitando falsi collegamenti diretti attraverso uplink/trunk o MAC duplicati.
- Generare gruppi logici per subnet e relazioni gateway solo dove supportate. Evidenze stale restano consultabili.
- Dipendenze: 2, 3.

### 5. Realizzare diagramma ed editing

- Canvas mediante egui Painter: zoom/pan, selezione, drag nodi, fit della mappa, ricerca e pannello dettagli.
- Layout iniziale deterministico per subnet/topologia; nuove scansioni posizionano solo nodi nuovi. Ridisposizione completa solo su comando.
- Stili distinti per collegamenti rilevati/dedotti/manuali e legenda; stato apparato indicato con testo/simbolo oltre al colore.
- Modifica nome/note, creazione/rimozione collegamenti manuali e inserimento apparati manuali.
- Dettagli mostrano IP/MAC, porte, fonte, timestamp, metodo della sonda e limiti di copertura.
- Ridurre dettagli/cullare elementi fuori vista per mantenere usabile la vista con 500 nodi.
- Dipendenze: 2.

### 6. Salvare e ricaricare mappe

- Schema JSON con versione, validazione ID/riferimenti, CIDR, limiti, coordinate finite e dimensione massima del file.
- Salvare modello, coordinate, impostazioni, metadati manuali, osservazioni e ultimi 10000 eventi; escludere community e dati runtime.
- Scrivere un file temporaneo nello stesso volume, sincronizzarlo e sostituire il file finale con la semantica atomica appropriata al sistema. Un errore non deve distruggere il precedente salvataggio.
- Caricare in un modello temporaneo prima di sostituire la mappa corrente; file corrotti/versioni future generano errori leggibili.
- Dopo la riapertura mantenere lo stato salvato come storico e quello live sconosciuto, senza fingere un monitoraggio recente.
- Gestire modifiche non salvate prima di aprire/creare una mappa o chiudere. Richiedere nuovamente le community quando servono.
- Dipendenze: 2, 5.

### 7. Implementare monitoraggio ed eventi

- Avvio/arresto espliciti, intervallo/timeout/soglia configurabili. Controllare gli apparati della mappa, non riscoprire tutte le subnet a ogni ciclo.
- Usare ICMP/TCP e, quando configurato, SNMP come evidenza positiva. Neighbor/FDB storici non bastano.
- Stato sconosciuto iniziale; risposta positiva -> raggiungibile; primi fallimenti -> in verifica; 3 cicli negativi -> non raggiungibile; una risposta -> recuperato.
- Ogni ciclo fallito conta una volta per apparato, non una volta per porta/sonda. Apparati senza IP non sono monitorabili.
- Errori locali, sospensione del computer o cancellazione producono copertura sconosciuta, non falsi eventi di spegnimento di massa.
- Cicli non sovrapposti; se il lavoro supera l'intervallo non accumulare una coda di cicli.
- Eventi solo per transizioni e problemi operativi significativi, con timestamp e cap di 10000; aggiornamento del diagramma senza spostare nodi.
- Dipendenze: 1, 2, 5.

### 8. Integrare il flusso completo

- Flusso: nuova mappa -> configura subnet -> scansione -> discovery/topologia -> modifica -> salva -> riapri -> aggiorna -> monitora.
- Una sola operazione di scansione alla volta; sospendere il monitoraggio durante l'aggiornamento e riprenderlo solo se era attivo.
- ID di generazione/job per scartare risultati tardivi dopo cancellazione, caricamento o nuova mappa.
- Risultati discovery parziali possono essere incorporati senza invalidare dati precedenti; aggiornamento topologia per sorgente solo a walk completato.
- Salvataggio coerente del modello posseduto dalla GUI; gestire progresso, annullamento, errori e chiusura dei worker.
- Dipendenze: 3, 4, 5, 6, 7.

### 9. Validare e documentare

- Test mirati: conteggio CIDR/limiti senza espansione, /31-/32, deduplicazione, classificazione esiti sonde, identita ambigue/DHCP e merge non distruttivo.
- Fixture SNMP sintetiche: indici porta diversi, LLDP reciproco/irrisolto, FDB ambigua/VLAN, walk incompleto/malformato.
- Test monitoraggio con clock/esiti controllati: soglia, recupero, errore locale, ciclo incompleto e risultati di job obsoleti.
- Test JSON: round-trip, metadati/coordinate, credenziali escluse, errori/versioni e preservazione del file precedente se il salvataggio fallisce.
- Test end-to-end con TCP listener e agente SNMP simulato in loopback: discovery -> merge -> salvataggio -> caricamento -> aggiornamento -> transizioni.
- Smoke test GUI e sonde native su macOS, Windows e Linux. Prova topologia su rete autorizzata con switch gestito e prova di fallback senza SNMP/ICMP.
- Fixture da 500 nodi per interazioni principali; nessuna promessa di copertura fisica completa dove mancano le evidenze.
- Comandi: `cargo fmt --all -- --check`, `cargo test --locked`, `cargo clippy --all-targets --all-features --locked -- -D warnings`, `cargo build --release --locked`.
- CI con matrice dei tre sistemi per build/lint/test non privilegiati. Le prove su apparati reali e le limitazioni non verificate devono essere dichiarate.
- README con build/avvio, privilegi e fallback, formato mappe, configurazione SNMPv2c e legenda. Nessun installer firmato in questa versione.
- Dipendenze: 8.

## Criteri di accettazione

1. Il programma si avvia sui tre sistemi senza Nmap, shell o driver di cattura obbligatori.
2. Scansioni di subnet configurate e autorizzate non bloccano la GUI e sono annullabili.
3. Una rete gestita con dati LLDP disponibili mostra adiacenze e porte; dati insufficienti restano esplicitamente parziali/dedotti.
4. La mappa si salva e ricarica senza perdere coordinate, metadati o collegamenti manuali, e senza includere credenziali.
5. Una nuova scansione aggiunge/aggiorna apparati senza duplicazioni evitabili o cancellazioni causate da fallimenti parziali.
6. Il monitoraggio aggiorna stati e registro dopo la soglia configurata, distinguendo irraggiungibilita e errori locali.
7. Test, formatter, Clippy e build passano; verifiche multipiattaforma o su apparati non eseguite vengono segnalate, non date per riuscite.

## Riferimenti tecnici consultati

- eframe: https://docs.rs/eframe/latest/eframe/
- socket2: https://docs.rs/socket2/latest/socket2/struct.Socket.html
- API ICMP Windows: https://learn.microsoft.com/en-us/windows/win32/api/icmpapi/nf-icmpapi-icmpsendecho2
- SNMP client Rust: https://docs.rs/snmp2/latest/snmp2/

## Stato di esecuzione

Le fasi 1-8 sono implementate nel progetto: package Rust/eframe, API native
ICMP/interfacce/route/vicini, modello e merge conservativo, discovery IPv4,
topologia SNMPv2c LLDP/FDB, diagramma, JSON e monitoraggio coordinato.

Sono disponibili test di unita e integrazione con loopback e agente SNMP
simulato, README, lockfile e CI per i tre sistemi. Le mappe mantengono le
modifiche manuali; credenziali escluse dalla persistenza; cancellazione e
risultati obsoleti non invalidano la mappa. Identita/IP ambigui rimangono
espliciti e possono essere risolti rimuovendo record obsoleti con conferma.

Verificati localmente: test automatici, formatter, Clippy rigoroso, build
release, avvio/chiusura GUI reale con 500 nodi sintetici e lettura delle
informazioni di rete native su macOS. Il binario e disponibile in
`target/release/network-scan-map`.

Restano esterne a questo ambiente le prove runtime Windows/Linux e il
collaudo della topologia su switch gestiti reali. Sono stati controllati i
binding Windows e fixture dei parser Linux, ma questo non equivale a
collaudo runtime. La CI e predisposta, non ancora eseguita su GitHub.

Non sono state avviate scansioni della LAN durante lo sviluppo.

### Limite rilevato sui MAC in macOS 27

Il sistema in uso nasconde la cache ARP alle applicazioni prive della
capability Network Topology Observation; le API route possono restituire
`02:00:00:00:00:00` invece dei MAC reali. Aggiunti messaggio esplicito nella
GUI, esclusione del segnaposto e visualizzazione MAC sui nodi/tooltip.

Apple richiede l'entitlement
`com.apple.developer.networking.topology-observation`, autorizzato tramite
provisioning profile e firma dell'app. La chiave e fornita in
`macos/NetworkScanMap.entitlements`; autorizzazione e collaudo della build
firmata restano bloccati finche non e disponibile un profilo Apple valido.
