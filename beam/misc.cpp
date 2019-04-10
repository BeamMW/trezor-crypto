#include "misc.h"
#include "internal.h"
#include "functions.h"


int bigint_cmp(const uint8_t* pSrc0, uint32_t nSrc0, const uint8_t* pSrc1, uint32_t nSrc1)
{
    if (nSrc0 > nSrc1)
    {
        uint32_t diff = nSrc0 - nSrc1;
        if (! memis0(pSrc0, diff))
            return 1;

        pSrc0 += diff;
        nSrc0 = nSrc1;
    }
    else if (nSrc0 < nSrc1)
    {
        uint32_t diff = nSrc1 - nSrc0;
        if (! memis0(pSrc1, diff))
            return -1;

        pSrc1 += diff;
    }

    return memcmp(pSrc0, pSrc1, nSrc0);
}

int point_cmp(const point_t* lhs, const point_t* rhs)
{
    if (lhs->y < rhs->y)
        return -1;
    if (lhs->y > rhs->y)
        return 1;

    return bigint_cmp(lhs->x, DIGEST_LENGTH, rhs->x, DIGEST_LENGTH);
}

int tx_element_cmp(const tx_element_t* lhs, const tx_element_t* rhs)
{
    CMP_MEMBER(lhs->maturity_height, rhs->maturity_height)
    return point_cmp(&lhs->commitment, &rhs->commitment);
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

int kernel_cmp(const tx_kernel_t* lhs, const tx_kernel_t* rhs)
{
    // Compare tx_element
    CMP_BY_FUN(&lhs->kernel.tx_element, &rhs->kernel.tx_element, tx_element_cmp)
    // Compare signature
    CMP_BY_FUN(&lhs->kernel.signature, &rhs->kernel.signature)

    CMP_MEMBER(lhs->kernel.fee, rhs->kernel.fee)
    CMP_MEMBER(lhs->kernel.min_height, rhs->kernel.min_height)
    CMP_MEMBER(lhs->kernel.max_height, rhs->kernel.max_height)
    CMP_MEMBER(lhs->kernel.asset_emission, rhs->kernel.asset_emission)

    //TODO: implement comparison of nested kernels
    //auto it0 = m_vNested.begin();
    //auto it1 = v.m_vNested.begin();

    //for ( ; m_vNested.end() != it0; it0++, it1++)
    //{
    //    if (v.m_vNested.end() == it1)
    //        return 1;

    //    int n = (*it0)->cmp(*(*it1));
    //    if (n)
    //        return n;
    //}

    //if (v.m_vNested.end() != it1)
    //    return -1;

    CMP_BY_FUN(lhs->kernel.hash_lock_preimage, rhs->kernel.hash_lock_preimage, bigint_cmp)
}

