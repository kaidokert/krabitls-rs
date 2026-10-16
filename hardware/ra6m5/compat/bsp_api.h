/* Minimal FSP compatibility surface required by the SCE9 sources. */
#ifndef KRABITLS_RA6M5_BSP_API_H
#define KRABITLS_RA6M5_BSP_API_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
#define FSP_HEADER extern "C" {
#define FSP_FOOTER }
#else
#define FSP_HEADER
#define FSP_FOOTER
#endif

#define __IOM volatile
#define __IM volatile const
#define __OM volatile
#define __REV(value) __builtin_bswap32(value)

typedef uint32_t fsp_err_t;

#define FSP_SUCCESS                              (0x00000000U)
#define FSP_ERR_ASSERTION                        (0x00000001U)
#define FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT     (0x00010001U)
#define FSP_ERR_CRYPTO_SCE_FAIL                  (0x00010002U)
#define FSP_ERR_CRYPTO_SCE_RETRY                 (0x00010004U)
#define FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL          (0x00010012U)
#define FSP_ERR_CRYPTO_SCE_AUTHENTICATION        (0x00010013U)
#define FSP_ERR_CRYPTO_SCE_PARAMETER             (0x00010014U)
#define FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION     (0x00010015U)

#define FSP_PARAMETER_NOT_USED(parameter) ((void) (parameter))
#define FSP_ASSERT(condition) do { if (!(condition)) { return FSP_ERR_ASSERTION; } } while (0)
#define FSP_ERROR_RETURN(condition, error) do { if (!(condition)) { return (error); } } while (0)

typedef enum e_bsp_reg_protect {
    BSP_REG_PROTECT_CGC = 0,
    BSP_REG_PROTECT_OM_LPC_BATT,
    BSP_REG_PROTECT_LVD,
    BSP_REG_PROTECT_SAR,
    BSP_REG_PROTECT_RESET,
} bsp_reg_protect_t;

typedef struct st_krabitls_ra6m5_mstp {
    uint32_t MSTPCRA;
    uint32_t MSTPCRB;
    union {
        uint32_t MSTPCRC;
        struct {
            uint32_t reserved : 31;
            uint32_t MSTPC31 : 1;
        } MSTPCRC_b;
    };
} krabitls_ra6m5_mstp_t;

#define R_MSTP ((krabitls_ra6m5_mstp_t *) 0x40084000UL)

typedef struct st_krabitls_ra6m5_pscu {
    uint32_t reserved[11];
    __IM uint32_t DLMMON;
} krabitls_ra6m5_pscu_t;

#define R_PSCU ((krabitls_ra6m5_pscu_t *) 0x400E0000UL)

void R_BSP_RegisterProtectDisable(bsp_reg_protect_t protect);
void R_BSP_RegisterProtectEnable(bsp_reg_protect_t protect);

#endif
