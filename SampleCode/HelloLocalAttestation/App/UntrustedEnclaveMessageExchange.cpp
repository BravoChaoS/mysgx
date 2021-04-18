#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "sgx_eid.h"
#include "error_codes.h"
#include "datatypes.h"
#include "sgx_urts.h"
#include "UntrustedEnclaveMessageExchange.h"
#include "sgx_dh.h"

#include "fifo_def.h"
#include "EnclaveResponder_u.h"

extern sgx_enclave_id_t responder_enclave_id;
extern "C"
uint32_t session_request_ocall(sgx_dh_msg1_t *dh_msg1, uint32_t *session_id) {
    uint32_t retcode;
    session_request_ecall(responder_enclave_id, &retcode, dh_msg1, session_id);
    return retcode == SGX_SUCCESS ? SGX_SUCCESS : INVALID_SESSION;
}

uint32_t exchange_report_ocall(sgx_dh_msg2_t *dh_msg2, sgx_dh_msg3_t *dh_msg3, uint32_t session_id) {
    uint32_t retcode;
    exchange_report_ecall(responder_enclave_id, &retcode, dh_msg2, dh_msg3, session_id);
    return retcode == SGX_SUCCESS ? SGX_SUCCESS : INVALID_SESSION;
}

uint32_t send_request_ocall(uint32_t session_id, secure_message_t *req_message, size_t req_message_size,
                            size_t max_payload_size, secure_message_t *resp_message, size_t resp_message_size) {
    uint32_t retcode;
    generate_response_ecall(responder_enclave_id, &retcode, req_message, req_message_size, max_payload_size, resp_message,
                      resp_message_size, session_id);
    return retcode == SGX_SUCCESS ? SGX_SUCCESS : INVALID_SESSION;
}


uint32_t end_session_ocall(uint32_t session_id) {
    uint32_t retcode;
    end_session_ecall(responder_enclave_id, &retcode, session_id);
    return retcode == SGX_SUCCESS ? SGX_SUCCESS : INVALID_SESSION;
}
