#ifndef __BEAM_MISC__
#define __BEAM_MISC__

#define CMP_SIMPLE(a, b) \
		if (a < b) \
			return -1; \
		if (a > b) \
			return 1;

#define CMP_MEMBER(member, other_member) CMP_SIMPLE(member, other_member)

#define CMP_MEMBER_EX(member) \
		{ \
			int n = member.cmp(v.member); \
			if (n) \
				return n; \
		}

int bigint_cmp(const uint8_t* pSrc0, uint32_t nSrc0, const uint8_t* pSrc1, uint32_t nSrc1);
int signature_cmp(const ecc_signature_t* lhs, const ecc_signature_t* rhs);

#endif // __BEAM_MISC__
