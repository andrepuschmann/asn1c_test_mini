/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "NBIOT-RRC-Definitions"
 * 	found in "../asn1_defs/NBIOT-RRC-Definitions.asn"
 * 	`asn1c -gen-PER -fcompound-names -fnative-types`
 */

#ifndef	_Standalone_NB_r13_H_
#define	_Standalone_NB_r13_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Standalone-NB-r13 */
typedef struct Standalone_NB_r13 {
	BIT_STRING_t	 spare;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Standalone_NB_r13_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Standalone_NB_r13;

#ifdef __cplusplus
}
#endif

#endif	/* _Standalone_NB_r13_H_ */
#include <asn_internal.h>