import _modsecurity as modsecurity
import ctypes
import pprint

def get_u_string(stringa):
  b_string = stringa.encode("utf-8")
  tipo_c = ctypes.POINTER(ctypes.c_ubyte)  # Equivale a unsigned char *
  data_c = (ctypes.c_ubyte * len(b_string)).from_buffer_copy(b_string)
  return tipo_c(data_c)

# Inizializza ModSecurity
modsec = modsecurity.msc_init()
if not modsec:
  raise Exception("Errore nell'inizializzazione di ModSecurity")

# Carica le regole da un file
rules_file = "./rules.conf"
rules = modsecurity.msc_create_rules_set()

ret = modsecurity.msc_rules_add_file_py(rules, rules_file)

if ret < 0:
  raise Exception("Errore nel caricamento delle regole")
print("[✅] Regole caricate correttamente!")

# Crea una transazione
transaction = modsecurity.msc_new_transaction(modsec, rules, None)
if not transaction:
  raise Exception("Errore nella creazione della transazione")

print("[✅] Transazione creata!")

modsecurity.msc_process_uri(transaction, "http://example.com/login", "POST", "HTTP/1.1")

modsecurity.msc_add_request_header_py(transaction, "Host", "example.com")
modsecurity.msc_add_request_header_py(transaction, "Content-Type", "application/x-www-form-urlencoded")
modsecurity.msc_process_request_headers(transaction)

#payload = "<script>alert</script>username=admin&password=123456"
payload = "script"
modsecurity.msc_append_request_body_py(transaction, payload, len(payload))
modsecurity.msc_process_request_body(transaction)

modsecurity.msc_intervention_py(transaction)

#modsecurity.msc_transaction_cleanup(transaction)
modsecurity.msc_rules_cleanup(rules);
modsecurity.msc_cleanup(modsec);
