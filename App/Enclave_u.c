#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_calcu_t {
	uint64_t ms_retval;
	uint64_t ms_a_enc;
	uint64_t ms_b_enc;
	uint64_t ms_c_enc;
	uint64_t ms_d_enc;
	uint64_t ms_pubkey_n;
	uint64_t ms_pubkey_e;
} ms_calcu_t;

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	1,
	{
		(void*)Enclave_ocall_print_string,
	}
};
sgx_status_t calcu(sgx_enclave_id_t eid, uint64_t* retval, uint64_t a_enc, uint64_t b_enc, uint64_t c_enc, uint64_t d_enc, uint64_t pubkey_n, uint64_t pubkey_e)
{
	sgx_status_t status;
	ms_calcu_t ms;
	ms.ms_a_enc = a_enc;
	ms.ms_b_enc = b_enc;
	ms.ms_c_enc = c_enc;
	ms.ms_d_enc = d_enc;
	ms.ms_pubkey_n = pubkey_n;
	ms.ms_pubkey_e = pubkey_e;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

