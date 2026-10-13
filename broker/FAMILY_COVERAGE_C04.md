# C04 — copertura delle famiglie e delle regole dalle fonti

Il registro storico contiene17 famiglie e551 ID; il catalogo AAA contiene200 ID.
Il totale751 non dimostra, da solo, corrispondenza alle fonti o completezza.

Il nuovo inventario effettivo deriva gli ID e le clausole dalle fonti canoniche:
Regole Madri, MG0, gate globali/cognitivi, sottogate D,25 EXEC,30 G0,12
provocazioni,300 domande, completamento, delivery, governance, standard,
gate storici, comportamento/110 errori, P0–P8 e200 AAA.

La fonte R110 già richiede sei profili di asset e sei ulteriori sezioni di
sistema: questi obblighi sono resi espliciti in due gruppi di copertura, senza
inventare nuove regole. L'inventario effettivo corrente ha20 gruppi e763 ID
(551+12+200); le20 sezioni A–T del catalogo AAA restano distinguibili. Sono
controlli registrati, non763 PASS di un modello.

Ogni ID ha fonte, digest della fonte, clausola completa e digest della clausola,
fase/numero/sezione/tipo AAA dove previsti e obbligo di MG0 individuale. Gli
aggregati conservano le sotto-obbligazioni della clausola: non possono essere
giudicati con un semplice sì/no autoriportato. C06/C07 devono verificarne le prove.

Il gate confronta tutte le famiglie e tutti gli ID attesi, non un contatore:
famiglia mancante, ID omesso/sostituito/spostato, fonte diversa, fase sbagliata,
MG0 comune riusato per un altro ID, prova o MG0 assente bloccano la struttura.
Le classificazioni canoniche future/N_A conservano ID, prova e MG0. Una regola
dovuta non può diventare N_A; una fase futura non vale PASS o chiusura.

Le200 clausole AAA sono confrontate col testo integrale nel MASTER, per testo,
numero, sezione, fase e tipo asset. Le fonti ausiliarie sono pinned; cambiamenti
devono essere riconciliati. Le intestazioni storiche duplicate non sostituiscono
le definizioni operative globali recuperate nel corpo principale del MASTER.

## Limiti e collegamenti

- L'inventario effettivo più forte è il contratto per il nuovo supervisore;
  il registro/guard privato storico e la firma indipendente non sono modificati.
  Un vecchio manifest limitato ai751 ID non soddisfa il nuovo inventario763.
- Il caller fidato ricostruisce l'inventario da fonti reali; non accetta quello
  del producer come autorità. Fase, tipo e profili provengono dal contesto di
  lavoro verificato, non da un'esenzione scelta dall'esecutore.
- Il test nativo legge un commit privato immutabile e lo confronta con il digest
  del MASTER verificato in Library. Non è una lettura remota autonoma di Library;
  C05 resta responsabile del contesto aggiornato e delle dipendenze pertinenti.
- Le prove di omissione usano metadati sintetici dichiarati. Il risultato è
  COVERAGE_STRUCTURE_PRESENT_ONLY: non legge i contenuti delle prove, non
  certifica lavoro/QA asset e non autorizza avanzamento. C06/C07 e C08/C09
  devono completare verifica delle prove, giudizio operativo e ciclo reale.
- Profili di asset e gate storici non vengono eliminati dall'inventario quando
  non pertinenti: l'applicabilità deve restare esplicita e giustificata.

Nessun asset, modello, texture, render o pacchetto di produzione va su GitHub.
Le fonti private sono lette come dati dal runner pubblico immutabile, non
eseguite né stampate nei log. Nessuna nuova schedulazione, chiave o servizio.
