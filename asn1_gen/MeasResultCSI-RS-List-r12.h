/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "../asn1_defs/EUTRA-RRC-Definitions.asn"
 * 	`asn1c -gen-PER -fcompound-names -fnative-types`
 */

#ifndef	_MeasResultCSI_RS_List_r12_H_
#define	_MeasResultCSI_RS_List_r12_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct MeasResultCSI_RS_r12;

/* MeasResultCSI-RS-List-r12 */
typedef struct MeasResultCSI_RS_List_r12 {
	A_SEQUENCE_OF(struct MeasResultCSI_RS_r12) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MeasResultCSI_RS_List_r12_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MeasResultCSI_RS_List_r12;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "MeasResultCSI-RS-r12.h"

#endif	/* _MeasResultCSI_RS_List_r12_H_ */
#include <asn_internal.h>
