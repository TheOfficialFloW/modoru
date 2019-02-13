#ifndef __SPKG_H__
#define __SPKG_H__

#define ALIGN(x, align) (((x) + ((align) - 1)) & ~((align) - 1))

#define SCE_SBL_ERROR_SL_EDATA   0x800F0226
#define SCE_SBL_ERROR_SL_ESYSVER 0x800F0237
#define SCE_SBL_SM_COMM_FID_SM_AUTH_SPKG 0x40002

typedef struct {
  uint32_t magic;
  uint32_t version;
  uint8_t  platform;
  uint8_t  key_revision;
  uint16_t sce_type;
  uint32_t metadata_offset;
  uint64_t header_length;
  uint64_t data_length;
} SceHeader;

typedef struct {
  uint8_t  key[0x10];
  uint64_t pad0;
  uint64_t pad1;
  uint8_t  iv[0x10];
  uint64_t pad2;
  uint64_t pad3;
} MetadataInfo;

typedef struct {
  uint64_t signature_input_length;
  uint32_t signature_type;
  uint32_t section_count;
  uint32_t key_count;
  uint32_t opt_header_size;
  uint32_t field_18;
  uint32_t field_1C;
} MetadataHeader;

typedef struct {
  uint64_t offset;
  uint64_t size;
  uint32_t type;
  uint32_t seg_idx;
  uint32_t hashtype;
  uint32_t hash_idx;
  uint32_t encryption;
  uint32_t key_idx;
  uint32_t iv_idx;
  uint32_t compression;
} MetadataSection;

typedef struct {
  uint32_t field_0;
  uint32_t pkg_type;
  uint32_t flags;
  uint32_t field_C;
  uint64_t update_version;
  uint64_t final_size;
  uint64_t decrypted_size;
  uint64_t field_28;
  uint32_t field_30;
  uint32_t field_34;
  uint32_t field_38;
  uint32_t field_3C;
  uint64_t field_40;
  uint64_t field_48;
  uint64_t offset;
  uint64_t size;
  uint64_t part_idx;
  uint64_t total_parts;
  uint64_t field_70;
  uint64_t field_78;
} SpkgHeader;

int decrypt_spkg(void *buf, int size);

#endif
