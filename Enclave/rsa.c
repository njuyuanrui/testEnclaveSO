#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <string.h>
#include "Enclave.h"


char buffer[1024];
const int MAX_DIGITS = 50;
int i,j = 0;

struct public_key_class{
  long long modulus;
  long long exponent;
};

struct private_key_class{
  long long modulus;
  long long exponent;
};


// This should totally be in the math library.
long long gcd(long long a, long long b)
{
  long long c;
  while ( a != 0 ) {
    c = a; a = b%a;  b = c;
  }
  return b;
}


long long ExtEuclid(long long a, long long b)
{
 long long x = 0, y = 1, u = 1, v = 0, gcd = b, m, n, q, r;
 while (a!=0) {
   q = gcd/a; r = gcd % a;
   m = x-u*q; n = y-v*q;
   gcd = a; a = r; x = u; y = v; u = m; v = n;
   }
   return y;
}

long long rsa_modExp(long long b, long long e, long long m)
{
  if (b < 0 || e < 0 || m <= 0){
    return -1;
  }
  b = b % m;
  if(e == 0) return 1;
  if(e == 1) return b;
  if( e % 2 == 0){
    return ( rsa_modExp(b * b % m, e/2, m) % m );
  }
  if( e % 2 == 1){
    return ( b * rsa_modExp(b, (e-1), m) % m );
  }

}

// Calling this function will generate a public and private key and store them in the pointers
// it is given. 
void rsa_gen_keys(struct public_key_class *pub, struct private_key_class *priv)
{
  // choose random primes from the list, store them as p,q

  // TODO: require truly random numbers here =============

  long long p = 10037;
  long long q = 10039;

  // TODO ================================================

  long long e = powl(2, 8) + 1;
  long long d = 0;
  long long max = p*q;
  long long phi_max = (p-1)*(q-1);
  
  while(!(p && q) || (p == q) || (gcd(phi_max, e) != 1));
 
  // Next, we need to choose a,b, so that a*max+b*e = gcd(max,e). We actually only need b
  // here, and in keeping with the usual notation of RSA we'll call it d. We'd also like 
  // to make sure we get a representation of d as positive, hence the while loop.
  d = ExtEuclid(phi_max,e);
  while(d < 0){
    d = d+phi_max;
  }

  printf("pub are %lld and %lld\n",(long long)max, (long long )e);
  printf("pri are %lld and %lld\n",(long long)max, (long long )d);
  // We now store the public / private keys in the appropriate structs
  pub->modulus = max;
  pub->exponent = e;

  priv->modulus = max;
  priv->exponent = d;
}


long long *rsa_encrypt(const char *message, const unsigned long message_size, 
                     const struct public_key_class *pub)
{
  long long *encrypted = malloc(sizeof(long long)*message_size);
  if(encrypted == NULL){
    printf("Error: Heap allocation failed.\n");
    return NULL;
  }
  long long i = 0;
  for(i=0; i < message_size; i++){
    encrypted[i] = rsa_modExp(message[i], pub->exponent, pub->modulus);
  }
  return encrypted;
}


char *rsa_decrypt(const long long *message, 
                  const unsigned long message_size, 
                  const struct private_key_class *priv)
{
  if(message_size % sizeof(long long) != 0){
    printf("Error: message_size is not divisible by %d, so cannot be output of rsa_encrypt\n", (int)sizeof(long long));
     return NULL;
  }
  // We allocate space to do the decryption (temp) and space for the output as a char array
  // (decrypted)
  char *decrypted = malloc(message_size/sizeof(long long));
  char *temp = malloc(message_size);
  if((decrypted == NULL) || (temp == NULL)){
    printf("Error: Heap allocation failed.\n");
    return NULL;
  }
  // Now we go through each 8-byte chunk and decrypt it.
  long long i = 0;
  for(i=0; i < message_size/8; i++){
    temp[i] = rsa_modExp(message[i], priv->exponent, priv->modulus);
  }
  // The result should be a number in the char range, which gives back the original byte.
  // We put that into decrypted, then return.
  for(i=0; i < message_size/8; i++){
    decrypted[i] = temp[i];
  }
  free(temp);
  return decrypted;
}




























