/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "../asn1_defs/EUTRA-RRC-Definitions.asn"
 * 	`asn1c -gen-PER -fcompound-names -fnative-types`
 */

#ifndef	_CSI_IM_ConfigToReleaseList_r11_H_
#define	_CSI_IM_ConfigToReleaseList_r11_H_


#include <asn_application.h>

/* Including external dependencies */
#include "CSI-IM-ConfigId-r11.h"
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CSI-IM-ConfigToReleaseList-r11 */
typedef struct CSI_IM_ConfigToReleaseList_r11 {
	A_SEQUENCE_OF(CSI_IM_ConfigId_r11_t) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CSI_IM_ConfigToReleaseList_r11_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CSI_IM_ConfigToReleaseList_r11;

#ifdef __cplusplus
}
#endif

#endif	/* _CSI_IM_ConfigToReleaseList_r11_H_ */
#include <asn_internal.h>
