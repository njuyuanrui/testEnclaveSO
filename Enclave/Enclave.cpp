/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */

extern "C" {
#include "rsa.h"
}

/*
*demander key pair:
*pubkey: n 100761443  e 257
*prikey: n 100761443  d 89373665
*
*enclave key pair:
*pubkey: n 100160063  e 257
*prikey: n 100160063  d 50264849
*/


/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}


uint64_t calcu(uint64_t a_enc, uint64_t b_enc, uint64_t c_enc, uint64_t d_enc, uint64_t pubkey_n, uint64_t pubkey_e){

    struct public_key_class pub[1];
    struct private_key_class priv[1];
    priv->modulus = 100160063;
    priv->exponent = 50264849;
    pub->modulus = 100160063;
    pub->exponent = 257;
    
    // rsa_gen_keys(pub, priv);


    long long a = rsa_modExp(a_enc,priv->exponent, priv->modulus);
    long long b = rsa_modExp(b_enc,priv->exponent, priv->modulus);
    long long c = rsa_modExp(c_enc,priv->exponent, priv->modulus);
    long long d = rsa_modExp(d_enc,priv->exponent, priv->modulus);

    long long res = rsa_modExp((a+b+c+d),pubkey_e, pubkey_n);

    //printf("a_enc: %lld\n",a_dec);


    return res;
}
