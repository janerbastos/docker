from flask import Flask, render_template
import json
import os

app = Flask(__name__)

AUDIT_LOG_PATH = '../var/log/modsec/audit.log'

def parse_logs():
    entries = []
    if not os.path.exists(AUDIT_LOG_PATH):
        return entries

    with open(AUDIT_LOG_PATH, 'r') as f:
        for line in f:
            try:
                entry = json.loads(line)
                if 'transaction' in entry:
                    tx = entry['transaction']
                    matched_rules = tx.get('messages', [])
                    entries.append({
                        'time': tx['time_stamp'],
                        'ip': tx['client_ip'],
                        'uri': tx['request'],
                        'rule_id': matched_rules[0]['details']['ruleId'],
                        'msg': matched_rules[0]['message'] if matched_rules else 'N/A',
                        'score': matched_rules[0]['details']['tags'],
                    })
            except Exception as e:
                print(e)
                continue
    return entries[::-1]  # mais recente primeiro

@app.route('/')
def index():
    logs = parse_logs()
    return render_template('dashboard.html', logs=logs)

if __name__ == '__main__':
    app.run(debug=True, port=5001)
