%module modsecurity
%{
#include <modsecurity/modsecurity.h>
#include <modsecurity/rules.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>

int msc_rules_add_file_py(RulesSet *rules, const char *file) {
  const char *error;
  int r = msc_rules_add_file(rules, file, &error);
  if(r < 0) 
    fprintf(stderr, "error: %s\n", error);
  return r;
}

int msc_add_request_header_py(Transaction *transaction, const char *key, const char *value) {
  unsigned const char *u_key = (unsigned const char*) key; 
  unsigned const char *u_value = (unsigned const char*) value; 
  return msc_add_request_header(transaction, u_key, u_value);
}

int msc_append_request_body_py(Transaction *transaction, const char *body, int size) {
  unsigned const char *u_body = (unsigned const char*) body;
  size_t st_size = (size_t) size;
  return msc_append_request_body(transaction, u_body, st_size);
}

int msc_intervention_py(Transaction *transaction) {
  ModSecurityIntervention intervention;
  memset(&intervention, 0, sizeof(ModSecurityIntervention));
  if (msc_intervention(transaction, &intervention) && intervention.status == 403) {
    printf("🔴 ATTACCO RILEVATO! ModSecurity ha bloccato la richiesta.\n");
    if (intervention.log) {
      printf("📌 Regola attivata: %s\n", intervention.log);
    }
  } else {
    printf("🟢 Nessuna minaccia rilevata.\n");
  }
  msc_transaction_cleanup(transaction);
  return intervention.status;
}
%}

int msc_rules_add_file_py(RulesSet *rules, const char *file);
int msc_intervention_py(Transaction *transaction);
int msc_add_request_header_py(Transaction *transaction, const char *key, const char *value);
int msc_append_request_body_py(Transaction *transaction, const char *body, size_t size);

%include "modsecurity/modsecurity.h"
%include "modsecurity/rules.h"
%include "modsecurity/rules_set.h"
%include "modsecurity/transaction.h"
