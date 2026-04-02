# Check Point Log Server API – Interactive Export Script

Questo repository contiene uno **script Python** che utilizza la **Check Point Management API (API for Logs)** per:

- interrogare i log del Log Server
- applicare **filtri interattivi** (source, destination, time range)
- esportare i risultati in **CSV**

Lo script è pensato per **analisi, troubleshooting e report mirati**, non come sostituto di Log Exporter o SIEM.

---

## 🚀 Funzionalità principali

- ✅ Connessione via **Check Point Management API**
- ✅ Query logs tramite **show-logs (API for Logs)**
- ✅ **Input interattivo all’avvio**:
  - Source (`src:`)
  - Destination (`dst:`)
  - Time frame (predefinito o custom start/end)
- ✅ Supporto **time-frame custom**
- ✅ Paginazione tramite `query-id`
- ✅ Export in **CSV**
- ✅ Credenziali e parametri gestiti via **`.env`**
- ✅ Compatibile con R80.40+ / R81.x / R82.x (dipende dallo schema log)

---

## ⚠️ Limitazioni note

- Lo script **non è pensato per bulk export massivi**
- Alcuni campi (es. `SNI`, `TLS Server Host Name`) possono risultare vuoti:
  - TLS 1.3 + ECH
  - traffico bypassato
  - log non di primo handshake
- I nomi dei campi possono variare in base a:
  - versione Check Point
  - blade che genera il log

Per export continuativi o compliance → **Log Exporter / SIEM**.

---

## 📦 Requisiti

- Python **3.8+**
- Accesso API abilitato sulla Management
- Utente API con permessi di lettura log

### Dipendenze Python
```bash
pip install requests python-dotenv
