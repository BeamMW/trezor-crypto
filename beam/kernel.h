#ifndef __BEAM_KERNEL__
#define __BEAM_KERNEL__

#ifndef BEAM_DEBUG
#include "mpconfigport.h"
#endif


void create_tx_kernel(tx_kernel_t* trg_kernels, uint32_t num_trg_kernels,
                      tx_kernel_t* nested_kernels, uint32_t num_nested_kernels,
                      uint64_t fee, uint32_t should_emit_custom_tag);

#endif // __BEAM_KERNEL__
