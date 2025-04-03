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

typedef struct {
  int status;
  char *log;
} intervention_result;

intervention_result msc_intervention_py(Transaction *transaction) {
  ModSecurityIntervention intervention;
  memset(&intervention, 0, sizeof(ModSecurityIntervention));
  msc_intervention(transaction, &intervention);
  msc_transaction_cleanup(transaction);
  intervention_result ir;
  memset(&ir, 0, sizeof(intervention_result));  
  ir.status = intervention.status;
  ir.log = intervention.log;
  return ir;
}
%}

%typemap(out) intervention_result {
    PyObject *obj = Py_BuildValue("{s:i, s:s}", 
                                  "status", $1.status, 
                                  "log", $1.log ? $1.log : "");
    $result = obj;
}

int msc_rules_add_file_py(RulesSet *rules, const char *file);
intervention_result msc_intervention_py(Transaction *transaction);
int msc_add_request_header_py(Transaction *transaction, const char *key, const char *value);
int msc_append_request_body_py(Transaction *transaction, const char *body, size_t size);

%include "modsecurity/modsecurity.h"
%include "modsecurity/rules.h"
%include "modsecurity/rules_set.h"
%include "modsecurity/transaction.h"
