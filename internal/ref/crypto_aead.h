int crypto_aead_decrypt_128l(unsigned char *m, unsigned long long *mlen,
			     unsigned char *nsec, const unsigned char *c,
			     unsigned long long clen, const unsigned char *ad,
			     unsigned long long adlen,
			     const unsigned char *npub, const unsigned char *k);
int crypto_aead_encrypt_128l(unsigned char *c, unsigned long long *clen,
			     const unsigned char *m, unsigned long long mlen,
			     const unsigned char *ad, unsigned long long adlen,
			     const unsigned char *nsec,
			     const unsigned char *npub, const unsigned char *k);
int crypto_aead_decrypt_256(unsigned char *m, unsigned long long *mlen,
			    unsigned char *nsec, const unsigned char *c,
			    unsigned long long clen, const unsigned char *ad,
			    unsigned long long adlen, const unsigned char *npub,
			    const unsigned char *k);
int crypto_aead_encrypt_256(unsigned char *c, unsigned long long *clen,
			    const unsigned char *m, unsigned long long mlen,
			    const unsigned char *ad, unsigned long long adlen,
			    const unsigned char *nsec,
			    const unsigned char *npub, const unsigned char *k);
