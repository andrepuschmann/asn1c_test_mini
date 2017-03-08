#include <stdio.h>
#include "asn1_gen/BCCH-DL-SCH-Message-NB.h"

uint8_t sib1_payload_tx[] = { 0x43, 0x4d, 0xd0, 0x90, 0xa0, 0x06, 0x04, 0x30, 0x28, 0x6e,
  0x87, 0xd0, 0x4b, 0x13, 0x90, 0xb4, 0x12, 0xa1, 0x02, 0x1e,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };


BCCH_DL_SCH_Message_NB_t *bcch_dl_sch_deserializer(const void *buffer, size_t buf_size)
{
  BCCH_DL_SCH_Message_NB_t *bcch = 0;

  asn_dec_rval_t rval = aper_decode(0, &asn_DEF_BCCH_DL_SCH_Message_NB, (void **)&bcch, buffer, buf_size, 0, 0);
  if(rval.code == RC_OK) {
    printf("Consumed %d bits.\n", rval.consumed);
    return bcch;
  } else {
    ASN_STRUCT_FREE(asn_DEF_BCCH_DL_SCH_Message_NB, bcch);
    return 0;
  }
}


int main()
{
  BCCH_DL_SCH_Message_NB_t *bcch;
  bcch = bcch_dl_sch_deserializer(sib1_payload_tx, 8*sizeof(sib1_payload_tx));
  if (bcch == NULL) {
    printf("Error\n");
  }

  // print ASN struct
  asn_fprint(stdout, &asn_DEF_BCCH_DL_SCH_Message_NB, bcch);

  // some basic tests
  SystemInformationBlockType1_NB_t *sib1 = NULL;
  PLMN_Identity_t *cell = NULL;
  if (bcch->message.present == BCCH_DL_SCH_MessageType_NB_PR_c1) {
    if (bcch->message.choice.c1.present == BCCH_DL_SCH_MessageType_NB__c1_PR_systemInformationBlockType1_r13) {
      // set the SIB
      sib1 = &bcch->message.choice.c1.choice.systemInformationBlockType1_r13;
    }
  }

  if (sib1) {
    if (bcch->message.choice.c1.choice.systemInformationBlockType1_r13.cellAccessRelatedInfo_r13.plmn_IdentityList_r13.list.count) {
      cell = &bcch->message.choice.c1.choice.systemInformationBlockType1_r13.cellAccessRelatedInfo_r13.plmn_IdentityList_r13.list.array[0]->plmn_Identity_r13;
    }
  } else {
    printf("SIB1 not found\n");
    return -1;
  }

  assert(cell->mcc->list.count == 3);
  assert(*cell->mcc->list.array[0] == 2);
  assert(*cell->mcc->list.array[1] == 1);
  assert(*cell->mcc->list.array[2] == 4);

  // check SI window length
  assert(sib1->si_WindowLength_r13 == 4);

  // free MIB again
  ASN_STRUCT_FREE(asn_DEF_BCCH_DL_SCH_Message_NB, bcch);

  return 0;
}
