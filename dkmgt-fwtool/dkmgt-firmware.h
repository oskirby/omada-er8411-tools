#ifndef DKMGT_FIRMWARE
#define DKMGT_FIRMWARE

#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>

#define DKMGT_MAGIC_0       0xa5a5a5a5
#define DKMGT_MAGIC_1       0x8f72632a
#define DKMGT_MAGIC_2       0x40f8600
#define DKMGT_MAGIC_3       0x9206b51
#define DKMGT_MAGIC_4       0xd2b7636a
#define DKMGT_MAGIC_5       0x5a5a5a5a

struct dkmgt_fw_header {
    uint32_t magic[6];
    uint32_t version;
    uint32_t next_header;
    uint32_t header_len;
    uint32_t total_len;
    uint32_t unknown[2];
    uint8_t md5hash[16];
    uint8_t __padding1[240];
    uint8_t signature[112];
    uint8_t __padding2[3744];
};

#define DKMGT_PTN_MAGIC_0   0xaa55d98f
#define DKMGT_PTN_MAGIC_1   0x04e955aa

struct dkmgt_ptn_header {
    uint32_t magic[2];
    uint32_t length;
    uint32_t checksum;
};

struct dkmgt_ptn_entry {
    char name[32];
    const uint8_t *data;
    uint32_t base;
    uint32_t size;
};

#define DKMGT_PTN_BLOCK_SIZE (64 * 1024)
#define DKMGT_MAX_PARTITIONS 64

struct dkmgt_ptn_table {
    uint32_t disk_size;
    uint32_t count;
    struct dkmgt_ptn_entry partitions[DKMGT_MAX_PARTITIONS];
};


const void* dkmgt_ptn_parse(const struct dkmgt_ptn_entry *entry, struct dkmgt_ptn_header *hdr);
const void* dkmgt_ptn_lookup(const struct dkmgt_ptn_table* ptable, const char* name, struct dkmgt_ptn_header *hdr);

struct dkmgt_device_info {
    char manufacturer_name[64];
    char manufacturer_full_name[256];
    char manufacturer_url[256];
    char model_name[64];
    char model_full_name[256];
    char model_id[64];
    char model_version[16];
    char region[16];
    char special_id[64];
    char flash_version[64];
    char hw_id[64];
    char oem_id[64];
    char public_key[256];
    char license_key[256];
};

struct dkmgt_support_entry {
    char model_name[64];
    char model_version[16];
    char special_id[64];
    char flash_version[64];
};

#define DKMGT_MAX_SUPPORT_ENTRIES 64

struct dkmgt_support_list {
    uint32_t count;
    struct dkmgt_support_entry list[DKMGT_MAX_SUPPORT_ENTRIES];
};

struct dkmgt_fw_info {
    uint32_t ver_major;
    uint32_t ver_minor;
    uint32_t ver_patch;
    uint32_t buildnum;
    uint32_t release;
    char firmware_id[64];
};

struct dkmgt_firmware {
    struct dkmgt_fw_header header;
    struct dkmgt_ptn_table ptable;
    const char* md5check;
};

struct dkmgt_firmware *dkmgt_firmware_parse(const void* data, size_t length);
void dkmgt_firmware_free(struct dkmgt_firmware *fw);
void dkmgt_firmware_dump(const struct dkmgt_firmware *fw, FILE *fp);

#endif // DKMGT_FIRMWARE