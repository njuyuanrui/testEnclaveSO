#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "user_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));

sgx_status_t calcu(sgx_enclave_id_t eid, uint64_t* retval, uint64_t a_enc, uint64_t b_enc, uint64_t c_enc, uint64_t d_enc, uint64_t pubkey_n, uint64_t pubkey_e);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
