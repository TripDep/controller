# C03B — origine autentica del giudizio Git

Il supervisore usa i dati autenticati di GitHub Actions come origine del giudizio:
repository, workflow e codice immutabile registrati, esecuzione/tentativo/job,
esito completato e legame con PR/HEAD/BASE/fonti attese. Un JSON `PASS` scritto
dal producer non costituisce un risultato di Git.

`git_judgment_origin.verify_git_origin` effettua GET autenticati tramite il client
fisso; il lettore dei log usa l’API autorizzata o la connessione GitHub. Il client
nativo accetta soltanto storage HTTPS GitHub/Azure e apre una seconda richiesta
senza bearer; redirect ulteriori sono negati. Nessun nuovo secret, chiave privata, firma
autogenerata o servizio viene introdotto.

## Perimetro effettivo del primo adattatore

Autentica l'origine del precheck PR già installato, con workflow/public-source
pair immutabile registrata. Il risultato resta `PR_PRECHECK_ORIGIN_ONLY`, prova
storica, `advancement_authorized=false`, `all_families_verified=false`.
Leggere il MASTER corrente in Library resta un requisito separato; il vecchio
precheck attesta soltanto il suo snapshot pinned. HEAD/BASE cambiati o un nuovo
tentativo del run invalidano il legame; un log locale non è una fonte operativa.

Il guard privato e il suo gate di firma indipendente restano invariati. La
firma esterna richiesta dal vecchio percorso non viene dichiarata configurata.
La nuova architettura distingue autenticità Git e autorizzazione del lavoro:
la prima è dimostrabile attraverso Actions, la seconda richiede i controlli
per regola/fase/MG0 e le prove pertinenti. Il nuovo adattatore non aggira quel
gate per validare un asset o per autorizzare scritture/merge.

## Collegamenti da completare nei passi successivi

- C04: registro completo, applicabilità e controlli effettivi da fonti correnti.
- C05: contesto Rescue/Guardian verificato e aggiornamenti pertinenti.
- C06: prove leggibili/verificabili associate al singolo tentativo e controllo.
- C07: verdetto per regola/fase/MG0 prodotto dal workflow fidato; ricezione tramite
  API autenticata, legame con digest della richiesta/fonti e gate di avanzamento.
- C08/C09: prove contro omissioni/replay e primo ciclo reale completo.

Un'API autenticata dimostra dove è stato emesso il risultato; non dimostra da
sola qualità visiva, esecuzione di ogni controllo o correttezza semantica delle
prove. I controlli dei passi successivi devono stabilirlo prima dell'avanzamento.

Questa architettura non richiede isolamento fisico globale dei writer e non
sposta asset, texture o render su GitHub. Rescue/Guardian e frequenze invariati.
