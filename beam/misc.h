#ifndef __BEAM_MISC__
#define __BEAM_MISC__

#include "definitions.h"


#define CMP_SIMPLE(a, b) \
    if (a < b) \
        return -1; \
    if (a > b) \
        return 1;

#define CMP_BY_FUN(a, b, cmp_fun) \
{ \
    const int cmp_res = cmp_fun(a, b); \
    if (cmp_res != 0) \
        return cmp_res; \
}


#define CMP_MEMBER(member, other_member) CMP_SIMPLE(member, other_member)

#define CMP_PTRS(a, b, cmp_fun) \
		if (a) \
		{ \
			if (!b) \
				return 1; \
			int n = cmp_fun(a, b); \
			if (n) \
				return n; \
		} else \
			if (b) \
				return -1;

void test_set_buffer(void* data, uint32_t size, uint8_t value);
int point_cmp(const point_t* lhs, const point_t* rhs);
int tx_element_cmp(const tx_element_t* lhs, const tx_element_t* rhs);
int bigint_cmp(const uint8_t* pSrc0, uint32_t nSrc0, const uint8_t* pSrc1, uint32_t nSrc1);
int signature_cmp(const ecc_signature_t* lhs, const ecc_signature_t* rhs);
int kernel_cmp(const tx_kernel_t* lhs, const tx_kernel_t* rhs);


#endif // __BEAM_MISC__
