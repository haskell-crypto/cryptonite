#include "cryptonite_argon2.h"

int cryptonite_argon2_hash_haskell(const uint32_t t_cost,
                                   const uint32_t m_cost,
                                   const uint32_t parallelism, const void *pwd,
                                   const size_t pwdlen, const void *salt,
                                   const size_t saltlen, void *hash,
                                   const size_t hashlen, argon2_type type,
                                   const uint32_t version)
{
#ifdef USE_SYSTEM_LIBRARY
	return argon2_hash(t_cost, m_cost, parallelism, pwd, pwdlen,
	                   salt, saltlen, hash, hashlen, NULL, 0, type,
		           version);
#else
	return cryptonite_argon2_hash(t_cost, m_cost, parallelism, pwd, pwdlen,
	                              salt, saltlen, hash, hashlen, type,
	                              version);
#endif
}

