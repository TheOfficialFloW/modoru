/* spkg.c -- spkg decryption
 *
 * Copyright (C) 2019 TheFloW
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/utils.h>

#include <stdio.h>
#include <string.h>

#include "spkg.h"

int ksceSblDmac5AEsCbcDec(void *src, void *dst, int size, void *key, int key_size, void *iv, int mask_enable);

uint8_t spkg_key[0x20] = {
  // FILL ME IN
};

uint8_t spkg_iv[0x10] = {
  // FILL ME IN
};

void xor_key(uint8_t *dst, uint8_t *src, int len) {
  int i;
  for (i = 0; i < len; i++) {
    dst[i] ^= src[i];
  }
}

void key_inc(uint8_t *key, int pos) {
  if (key[pos] == 0xFF) {
    key[pos] = 0;
    key_inc(key, pos - 1);
  } else {
    key[pos] += 1;
  }
}

int aes_ctr_encrypt(void *data, int size, void *key, void *iv) {
  uint8_t ikey[16], xkey[16];
  int res;

  SceAesContext ctx;
  res = ksceAesInit1(&ctx, 128, 128, key);
  if (res < 0)
    return res;

  memcpy(ikey, iv, 16);

  int i;
  for (i = 0; i < size; i += 16) {
    memcpy(xkey, ikey, 16);
    res = ksceAesEncrypt1(&ctx, xkey, xkey);
    if (res < 0)
      return res;
    xor_key(data + i, xkey, 16);
    key_inc(ikey, 15);
  }

  return 0;
}

int decrypt_spkg(void *buf, int size) {
  char key[0x20], iv[0x10];
  int res;

  SceHeader *sce_header = (SceHeader *)buf;
  if (sce_header->magic != 0x00454353 || sce_header->version != 3 || sce_header->sce_type != 3)
    return SCE_SBL_ERROR_SL_EDATA;

  MetadataInfo *metadata_info = (MetadataInfo *)((char *)sce_header + sce_header->metadata_offset + 0x30);

  memcpy(key, spkg_key, 0x20);
  memcpy(iv,  spkg_iv,  0x10);

  res = ksceSblDmac5AEsCbcDec(metadata_info, metadata_info, sizeof(MetadataInfo), key, 256, iv, 1);
  if (res < 0)
    return res;

  if (metadata_info->pad0 != 0 || metadata_info->pad1 != 0 ||
      metadata_info->pad2 != 0 || metadata_info->pad3 != 0)
    return SCE_SBL_ERROR_SL_EDATA;

  char *dec = (char *)metadata_info + sizeof(MetadataInfo);
  int dec_size = sce_header->header_length - sce_header->metadata_offset - 0x30 - sizeof(MetadataInfo);

  memcpy(key, metadata_info->key, 0x10);
  memcpy(iv,  metadata_info->iv,  0x10);

  res = ksceSblDmac5AEsCbcDec(dec, dec, dec_size, key, 128, iv, 1);
  if (res < 0)
    return res;

  MetadataHeader *metadata_header = (MetadataHeader *)dec;
  MetadataSection *metadata_section = (MetadataSection *)((char *)metadata_header + sizeof(MetadataHeader));

  char *vault = (char *)metadata_section + metadata_header->section_count * sizeof(MetadataSection);

  int i;
  for (i = 0; i < metadata_header->section_count; i++) {
    if (metadata_section[i].encryption == 3) {
      char *vault_key = vault + metadata_section[i].key_idx * 0x10;
      char *vault_iv  = vault + metadata_section[i].iv_idx  * 0x10;

      memcpy(key, vault_key, 0x10);
      memcpy(iv,  vault_iv,  0x10);

      res = aes_ctr_encrypt(buf + metadata_section[i].offset, metadata_section[i].size, key, iv);
      if (res < 0)
        return res;
    }
  }

  ksceKernelCpuDcacheAndL2WritebackRange(buf, ALIGN(size, 0x40));

  return 0;
}
