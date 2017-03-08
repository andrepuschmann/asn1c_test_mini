/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "NBIOT-RRC-Definitions"
 * 	found in "../asn1_defs/NBIOT-RRC-Definitions.asn"
 * 	`asn1c -gen-PER -fcompound-names -fnative-types`
 */

#include "PDCP-Parameters-NB-r13.h"

static int
maxNumberROHC_ContextSessions_r13_10_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	/* Replace with underlying type checker */
	td->check_constraints = asn_DEF_NativeEnumerated.check_constraints;
	return td->check_constraints(td, sptr, ctfailcb, app_key);
}

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static void
maxNumberROHC_ContextSessions_r13_10_inherit_TYPE_descriptor(asn_TYPE_descriptor_t *td) {
	td->free_struct    = asn_DEF_NativeEnumerated.free_struct;
	td->print_struct   = asn_DEF_NativeEnumerated.print_struct;
	td->check_constraints = asn_DEF_NativeEnumerated.check_constraints;
	td->ber_decoder    = asn_DEF_NativeEnumerated.ber_decoder;
	td->der_encoder    = asn_DEF_NativeEnumerated.der_encoder;
	td->xer_decoder    = asn_DEF_NativeEnumerated.xer_decoder;
	td->xer_encoder    = asn_DEF_NativeEnumerated.xer_encoder;
	td->uper_decoder   = asn_DEF_NativeEnumerated.uper_decoder;
	td->uper_encoder   = asn_DEF_NativeEnumerated.uper_encoder;
	td->aper_decoder   = asn_DEF_NativeEnumerated.aper_decoder;
	td->aper_encoder   = asn_DEF_NativeEnumerated.aper_encoder;
	if(!td->per_constraints)
		td->per_constraints = asn_DEF_NativeEnumerated.per_constraints;
	td->elements       = asn_DEF_NativeEnumerated.elements;
	td->elements_count = asn_DEF_NativeEnumerated.elements_count;
     /* td->specifics      = asn_DEF_NativeEnumerated.specifics;	// Defined explicitly */
}

static void
maxNumberROHC_ContextSessions_r13_10_free(asn_TYPE_descriptor_t *td,
		void *struct_ptr, int contents_only) {
	maxNumberROHC_ContextSessions_r13_10_inherit_TYPE_descriptor(td);
	td->free_struct(td, struct_ptr, contents_only);
}

static int
maxNumberROHC_ContextSessions_r13_10_print(asn_TYPE_descriptor_t *td, const void *struct_ptr,
		int ilevel, asn_app_consume_bytes_f *cb, void *app_key) {
	maxNumberROHC_ContextSessions_r13_10_inherit_TYPE_descriptor(td);
	return td->print_struct(td, struct_ptr, ilevel, cb, app_key);
}

static asn_dec_rval_t
maxNumberROHC_ContextSessions_r13_10_decode_ber(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const void *bufptr, size_t size, int tag_mode) {
	maxNumberROHC_ContextSessions_r13_10_inherit_TYPE_descriptor(td);
	return td->ber_decoder(opt_codec_ctx, td, structure, bufptr, size, tag_mode);
}

static asn_enc_rval_t
maxNumberROHC_ContextSessions_r13_10_encode_der(asn_TYPE_descriptor_t *td,
		void *structure, int tag_mode, ber_tlv_tag_t tag,
		asn_app_consume_bytes_f *cb, void *app_key) {
	maxNumberROHC_ContextSessions_r13_10_inherit_TYPE_descriptor(td);
	return td->der_encoder(td, structure, tag_mode, tag, cb, app_key);
}

static asn_dec_rval_t
maxNumberROHC_ContextSessions_r13_10_decode_xer(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const char *opt_mname, const void *bufptr, size_t size) {
	maxNumberROHC_ContextSessions_r13_10_inherit_TYPE_descriptor(td);
	return td->xer_decoder(opt_codec_ctx, td, structure, opt_mname, bufptr, size);
}

static asn_enc_rval_t
maxNumberROHC_ContextSessions_r13_10_encode_xer(asn_TYPE_descriptor_t *td, void *structure,
		int ilevel, enum xer_encoder_flags_e flags,
		asn_app_consume_bytes_f *cb, void *app_key) {
	maxNumberROHC_ContextSessions_r13_10_inherit_TYPE_descriptor(td);
	return td->xer_encoder(td, structure, ilevel, flags, cb, app_key);
}

static asn_dec_rval_t
maxNumberROHC_ContextSessions_r13_10_decode_uper(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints, void **structure, asn_per_data_t *per_data) {
	maxNumberROHC_ContextSessions_r13_10_inherit_TYPE_descriptor(td);
	return td->uper_decoder(opt_codec_ctx, td, constraints, structure, per_data);
}

static asn_enc_rval_t
maxNumberROHC_ContextSessions_r13_10_encode_uper(asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints,
		void *structure, asn_per_outp_t *per_out) {
	maxNumberROHC_ContextSessions_r13_10_inherit_TYPE_descriptor(td);
	return td->uper_encoder(td, constraints, structure, per_out);
}

static asn_dec_rval_t
maxNumberROHC_ContextSessions_r13_10_decode_aper(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints, void **structure, asn_per_data_t *per_data) {
	maxNumberROHC_ContextSessions_r13_10_inherit_TYPE_descriptor(td);
	return td->aper_decoder(opt_codec_ctx, td, constraints, structure, per_data);
}

static asn_enc_rval_t
maxNumberROHC_ContextSessions_r13_10_encode_aper(asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints,
		void *structure, asn_per_outp_t *per_out) {
	maxNumberROHC_ContextSessions_r13_10_inherit_TYPE_descriptor(td);
	return td->aper_encoder(td, constraints, structure, per_out);
}

static asn_per_constraints_t asn_PER_type_maxNumberROHC_ContextSessions_r13_constr_10 GCC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  0,  3 }	/* (0..3) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_supportedROHC_Profiles_r13_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct PDCP_Parameters_NB_r13__supportedROHC_Profiles_r13, profile0x0002),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"profile0x0002"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PDCP_Parameters_NB_r13__supportedROHC_Profiles_r13, profile0x0003),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"profile0x0003"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PDCP_Parameters_NB_r13__supportedROHC_Profiles_r13, profile0x0004),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"profile0x0004"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PDCP_Parameters_NB_r13__supportedROHC_Profiles_r13, profile0x0006),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"profile0x0006"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PDCP_Parameters_NB_r13__supportedROHC_Profiles_r13, profile0x0102),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"profile0x0102"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PDCP_Parameters_NB_r13__supportedROHC_Profiles_r13, profile0x0103),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"profile0x0103"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PDCP_Parameters_NB_r13__supportedROHC_Profiles_r13, profile0x0104),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"profile0x0104"
		},
};
static const ber_tlv_tag_t asn_DEF_supportedROHC_Profiles_r13_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_supportedROHC_Profiles_r13_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* profile0x0002 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* profile0x0003 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* profile0x0004 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* profile0x0006 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* profile0x0102 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* profile0x0103 */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 } /* profile0x0104 */
};
static asn_SEQUENCE_specifics_t asn_SPC_supportedROHC_Profiles_r13_specs_2 = {
	sizeof(struct PDCP_Parameters_NB_r13__supportedROHC_Profiles_r13),
	offsetof(struct PDCP_Parameters_NB_r13__supportedROHC_Profiles_r13, _asn_ctx),
	asn_MAP_supportedROHC_Profiles_r13_tag2el_2,
	7,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_supportedROHC_Profiles_r13_2 = {
	"supportedROHC-Profiles-r13",
	"supportedROHC-Profiles-r13",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	SEQUENCE_decode_uper,
	SEQUENCE_encode_uper,
	SEQUENCE_decode_aper,
	SEQUENCE_encode_aper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_supportedROHC_Profiles_r13_tags_2,
	sizeof(asn_DEF_supportedROHC_Profiles_r13_tags_2)
		/sizeof(asn_DEF_supportedROHC_Profiles_r13_tags_2[0]) - 1, /* 1 */
	asn_DEF_supportedROHC_Profiles_r13_tags_2,	/* Same as above */
	sizeof(asn_DEF_supportedROHC_Profiles_r13_tags_2)
		/sizeof(asn_DEF_supportedROHC_Profiles_r13_tags_2[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_supportedROHC_Profiles_r13_2,
	7,	/* Elements count */
	&asn_SPC_supportedROHC_Profiles_r13_specs_2	/* Additional specs */
};

static int asn_DFL_10_set_0(int set_value, void **sptr) {
	long *st = *sptr;
	
	if(!st) {
		if(!set_value) return -1;	/* Not a default value */
		st = (*sptr = CALLOC(1, sizeof(*st)));
		if(!st) return -1;
	}
	
	if(set_value) {
		/* Install default value 0 */
		*st = 0;
		return 0;
	} else {
		/* Test default value 0 */
		return (*st == 0);
	}
}
static const asn_INTEGER_enum_map_t asn_MAP_maxNumberROHC_ContextSessions_r13_value2enum_10[] = {
	{ 0,	3,	"cs2" },
	{ 1,	3,	"cs4" },
	{ 2,	3,	"cs8" },
	{ 3,	4,	"cs12" }
};
static const unsigned int asn_MAP_maxNumberROHC_ContextSessions_r13_enum2value_10[] = {
	3,	/* cs12(3) */
	0,	/* cs2(0) */
	1,	/* cs4(1) */
	2	/* cs8(2) */
};
static const asn_INTEGER_specifics_t asn_SPC_maxNumberROHC_ContextSessions_r13_specs_10 = {
	asn_MAP_maxNumberROHC_ContextSessions_r13_value2enum_10,	/* "tag" => N; sorted by tag */
	asn_MAP_maxNumberROHC_ContextSessions_r13_enum2value_10,	/* N => "tag"; sorted by N */
	4,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_maxNumberROHC_ContextSessions_r13_tags_10[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_maxNumberROHC_ContextSessions_r13_10 = {
	"maxNumberROHC-ContextSessions-r13",
	"maxNumberROHC-ContextSessions-r13",
	maxNumberROHC_ContextSessions_r13_10_free,
	maxNumberROHC_ContextSessions_r13_10_print,
	maxNumberROHC_ContextSessions_r13_10_constraint,
	maxNumberROHC_ContextSessions_r13_10_decode_ber,
	maxNumberROHC_ContextSessions_r13_10_encode_der,
	maxNumberROHC_ContextSessions_r13_10_decode_xer,
	maxNumberROHC_ContextSessions_r13_10_encode_xer,
	maxNumberROHC_ContextSessions_r13_10_decode_uper,
	maxNumberROHC_ContextSessions_r13_10_encode_uper,
	maxNumberROHC_ContextSessions_r13_10_decode_aper,
	maxNumberROHC_ContextSessions_r13_10_encode_aper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_maxNumberROHC_ContextSessions_r13_tags_10,
	sizeof(asn_DEF_maxNumberROHC_ContextSessions_r13_tags_10)
		/sizeof(asn_DEF_maxNumberROHC_ContextSessions_r13_tags_10[0]) - 1, /* 1 */
	asn_DEF_maxNumberROHC_ContextSessions_r13_tags_10,	/* Same as above */
	sizeof(asn_DEF_maxNumberROHC_ContextSessions_r13_tags_10)
		/sizeof(asn_DEF_maxNumberROHC_ContextSessions_r13_tags_10[0]), /* 2 */
	&asn_PER_type_maxNumberROHC_ContextSessions_r13_constr_10,
	0, 0,	/* Defined elsewhere */
	&asn_SPC_maxNumberROHC_ContextSessions_r13_specs_10	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_PDCP_Parameters_NB_r13_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct PDCP_Parameters_NB_r13, supportedROHC_Profiles_r13),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_supportedROHC_Profiles_r13_2,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"supportedROHC-Profiles-r13"
		},
	{ ATF_NOFLAGS, 1, offsetof(struct PDCP_Parameters_NB_r13, maxNumberROHC_ContextSessions_r13),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_maxNumberROHC_ContextSessions_r13_10,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		asn_DFL_10_set_0,	/* DEFAULT 0 */
		"maxNumberROHC-ContextSessions-r13"
		},
};
static const int asn_MAP_PDCP_Parameters_NB_r13_oms_1[] = { 1 };
static const ber_tlv_tag_t asn_DEF_PDCP_Parameters_NB_r13_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_PDCP_Parameters_NB_r13_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* supportedROHC-Profiles-r13 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* maxNumberROHC-ContextSessions-r13 */
};
static asn_SEQUENCE_specifics_t asn_SPC_PDCP_Parameters_NB_r13_specs_1 = {
	sizeof(struct PDCP_Parameters_NB_r13),
	offsetof(struct PDCP_Parameters_NB_r13, _asn_ctx),
	asn_MAP_PDCP_Parameters_NB_r13_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_PDCP_Parameters_NB_r13_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	1,	/* Start extensions */
	3	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_PDCP_Parameters_NB_r13 = {
	"PDCP-Parameters-NB-r13",
	"PDCP-Parameters-NB-r13",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	SEQUENCE_decode_uper,
	SEQUENCE_encode_uper,
	SEQUENCE_decode_aper,
	SEQUENCE_encode_aper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_PDCP_Parameters_NB_r13_tags_1,
	sizeof(asn_DEF_PDCP_Parameters_NB_r13_tags_1)
		/sizeof(asn_DEF_PDCP_Parameters_NB_r13_tags_1[0]), /* 1 */
	asn_DEF_PDCP_Parameters_NB_r13_tags_1,	/* Same as above */
	sizeof(asn_DEF_PDCP_Parameters_NB_r13_tags_1)
		/sizeof(asn_DEF_PDCP_Parameters_NB_r13_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_PDCP_Parameters_NB_r13_1,
	2,	/* Elements count */
	&asn_SPC_PDCP_Parameters_NB_r13_specs_1	/* Additional specs */
};
