#include "misc.h"
#include "internal.h"
#include "functions.h"


int bigint_cmp(const uint8_t* pSrc0, uint32_t nSrc0, const uint8_t* pSrc1, uint32_t nSrc1)
{
    if (nSrc0 > nSrc1)
    {
        uint32_t diff = nSrc0 - nSrc1;
        if (!memis0(pSrc0, diff))
            return 1;

        pSrc0 += diff;
        nSrc0 = nSrc1;
    } else
        if (nSrc0 < nSrc1)
        {
            uint32_t diff = nSrc1 - nSrc0;
            if (!memis0(pSrc1, diff))
                return -1;

            pSrc1 += diff;
        }

    return memcmp(pSrc0, pSrc1, nSrc0);
}

int signature_cmp(const ecc_signature_t* lhs, const ecc_signature_t* rhs)
{
    point_t lhs_nonce_pub_point;
    export_gej_to_point(&lhs.nonce_pub.x, &lhs_nonce_pub_point);
    point_t rhs_nonce_pub_point;
    export_gej_to_point(&rhs.nonce_pub.x, &rhs_nonce_pub_point);

    CMP_SIMPLE(lhs_nonce_pub_point.y, rhs.nonce_pub_point.y)

    return memcmp(lhs_nonce_pub_point.x, rhs_nonce_pub_point.x, DIGEST_LENGTH);
}
