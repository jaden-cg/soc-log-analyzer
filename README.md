# SOC Log Analyzer (Python)

A lightweight SOC (Security Operations Center) simulation tool that monitors authentication logs in real time and detects suspicious login behavior such as brute-force attacks and potential account compromise.

---

## 🚨 What It Detects

- Repeated failed login attempts from the same IP
- Multiple usernames targeted by a single IP
- Escalating attack severity based on behavior
- Successful login after repeated failures (**potential compromise**)

---

## 🧠 Detection Logic

| Condition | Severity |
|----------|--------|
| < 3 failed attempts | LOW |
| 3–4 failed attempts | MEDIUM |
| 5+ failed attempts | HIGH |
| Successful login after failures | CRITICAL |

---

## ⚙️ How It Works

- Continuously monitors a log file (simulating real-time ingestion)
- Parses log entries using regex
- Tracks attacker behavior by IP address
- Applies rule-based detection logic
- Outputs structured alerts in real time

---

## 🛠️ Technologies Used

- Python 3
- Regular Expressions (regex)
- Linux log simulation

---

## ▶️ How to Run

```bash
python3 log_analyzer.py
