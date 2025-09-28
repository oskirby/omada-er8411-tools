
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <md5.h>

#include "cJSON.h"
#include "dkmgt-firmware.h"

#define HEXIFY_SIZE(_type_) (sizeof(_type_) * 2 + 1)

static char* hexify(const void *data, size_t length, char* output) {
    const uint8_t* udata = data;
    for (size_t i = 0; i < length; i++) {
        sprintf(output + (i*2), "%02x", udata[i]);
    }
    return output;
}

static char* dkmgt_validate_md5(const struct dkmgt_fw_header* h, const uint8_t *data) {
    MD5_CTX ctx;
    uint8_t digest[MD5_DIGEST_LENGTH];

    MD5Init(&ctx);
    MD5Update(&ctx, data + h->header_len, h->total_len - h->header_len);
    MD5Final(digest, &ctx);

    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        if (h->md5hash[i] != digest[i]) {
            return "fail";
        }
    }

    return "okay";
}

static void dkmgt_fw_header_parse(const void *data, size_t length, struct dkmgt_fw_header* h) {
    memcpy(h, data, sizeof(struct dkmgt_fw_header));
    for (int i = 0; i < 6; i++) {
        h->magic[i] = htonl(h->magic[i]);
    }
    h->version = htonl(h->version);
    h->next_header = htonl(h->next_header);
    h->header_len = htonl(h->header_len);
    h->total_len = htonl(h->total_len);
}

static void dkmgt_fw_header_dump(const struct dkmgt_fw_header* h, const char* md5status, FILE *fp) {
    fprintf(fp, "DKMGT File Header:\n");
    for (int i = 0; i < 6; i++) {
        fprintf(fp, "\tmagic%d: 0x%08lx\n", i, h->magic[i]);
    }
    fprintf(fp, "\tversion: %d\n", h->version);
    fprintf(fp, "\tnext_header: 0x%08lx\n", h->next_header);
    fprintf(fp, "\theader_len: 0x%08lx (%d)\n", h->header_len, h->header_len);
    fprintf(fp, "\ttotal_len: 0x%08lx (%d)\n", h->total_len, h->total_len);

    char buffer[HEXIFY_SIZE(h->md5hash)];
    fprintf(fp, "\tmd5hash: %s (%s)\n", hexify(h->md5hash, sizeof(h->md5hash), buffer), md5status);
    fprintf(fp, "\n");
}

static int dkmgt_ptn_table_parse(const struct dkmgt_fw_header *h, const uint8_t *data, struct dkmgt_ptn_table *ptable) {
    size_t ptsize = 64 * 1024;
    const char* ptraw = data + h->header_len;
    if (h->header_len + ptsize > h->total_len) {
        fprintf(stderr, "Firmware partition table truncated\n");
        return -1;
    }

    cJSON *root = cJSON_Parse(ptraw);
    if (!root || !cJSON_IsObject(root)) {
        fprintf(stderr, "partition table JSON malformed\n");
        return -1;
    }
    cJSON* list = cJSON_GetObjectItem(root, "up-ptn-table");
    if (!list || !cJSON_IsArray(list)) {
        fprintf(stderr, "partition table JSON malformed\n");
        return -1;
    }

    memset(ptable, 0, sizeof(struct dkmgt_ptn_table));
    for (int i = 0; i < cJSON_GetArraySize(list); i++) {
        cJSON* item = cJSON_GetArrayItem(list, i);
        if (!cJSON_IsObject(item)) {
            continue;
        }

        if (ptable->count >= DKMGT_MAX_PARTITIONS) {
            fprintf(stderr, "partition table overflow\n");
        }
        struct dkmgt_ptn_entry* entry = &ptable->partitions[ptable->count];

        cJSON* name = cJSON_GetObjectItem(item, "name");
        if (!cJSON_IsString(name)) {
            continue;
        }
        strncpy(entry->name, cJSON_GetStringValue(name), sizeof(entry->name));

        cJSON* base = cJSON_GetObjectItem(item, "base");
        if (!cJSON_IsString(base)) {
            continue;
        }
        entry->base = strtoul(cJSON_GetStringValue(base), NULL, 0);

        cJSON* size = cJSON_GetObjectItem(item, "size");
        if (!cJSON_IsString(size)) {
            continue;
        }
        entry->size = strtoul(cJSON_GetStringValue(size), NULL, 0);
        entry->data = data + h->header_len + ptsize + entry->base;
        ptable->count++;
    }

    ptable->disk_size = h->total_len - h->header_len - ptsize;
    return 0;
}

static void dkmgt_ptn_table_dump(const struct dkmgt_ptn_table* ptable, FILE *fp) {
    fprintf(fp, "Upgrade Partition Table:\n");
    fprintf(fp, "\t%010s  %010s  %010s  %s\n", "BASE", "END", "SIZE", "NAME");
    for (int i = 0; i < ptable->count; i++) {
        const struct dkmgt_ptn_entry* entry = &ptable->partitions[i];
        fprintf(fp, "\t0x%08lx  0x%08lx  %10d  %s\n", entry->base, entry->base + entry->size - 1, entry->size, entry->name);
    }
    fprintf(fp, "\n");
}

const void* dkmgt_ptn_parse(const struct dkmgt_ptn_entry *entry, struct dkmgt_ptn_header *hdr) {
    if (entry->size < sizeof(struct dkmgt_ptn_header)) {
        fprintf(stderr, "Partition \'%s\' header truncated\n", entry->name);
        return NULL;
    }

    memcpy(hdr, entry->data, sizeof(struct dkmgt_ptn_header));
    hdr->magic[0] = htonl(hdr->magic[0]);
    hdr->magic[1] = htonl(hdr->magic[1]);
    hdr->length = htonl(hdr->length);
    hdr->checksum = htonl(hdr->checksum);
    if ((hdr->magic[0] != DKMGT_PTN_MAGIC_0) || (hdr->magic[1] != DKMGT_PTN_MAGIC_1) ||
        (hdr->length > (entry->size - sizeof(struct dkmgt_ptn_header)))) {
        fprintf(stderr, "Partition \'%s\' has invalid header\n", entry->name);
        return NULL;
    }

    return entry->data + sizeof(struct dkmgt_ptn_header);
}

const void* dkmgt_ptn_lookup(const struct dkmgt_ptn_table* ptable, const char* name, struct dkmgt_ptn_header *hdr) {
    for (int i = 0; i < ptable->count; i++) {
        const struct dkmgt_ptn_entry* entry = &ptable->partitions[i];
        if (strncmp(name, entry->name, sizeof(entry->name)) != 0) {
            continue;
        }
        return dkmgt_ptn_parse(entry, hdr);
    }
    return NULL;
}

int dkmgt_support_list_parse(const struct dkmgt_ptn_table* ptable, struct dkmgt_support_list *support) {
    struct dkmgt_ptn_header hdr;
    const char* data = dkmgt_ptn_lookup(ptable, "support-list", &hdr);
    if (!data) {
        return -1;
    }

    cJSON *root = cJSON_ParseWithLength(data, hdr.length);
    if (!root) {
        fprintf(stderr, "Support list JSON malformed\n");
        return -1;
    }
    if (!root || !cJSON_IsObject(root)) {
        goto err;
    }
    cJSON* list = cJSON_GetObjectItem(root, "support-list");
    if (!list || !cJSON_IsArray(list)) {
        goto err;
    }

    memset(support, 0, sizeof(struct dkmgt_support_list));
    for (int i = 0; i < cJSON_GetArraySize(list); i++) {
        cJSON* item = cJSON_GetArrayItem(list, i);
        if (!cJSON_IsObject(item)) {
            continue;
        }

        struct dkmgt_support_entry* entry = &support->list[i];
        if (support->count >= DKMGT_MAX_SUPPORT_ENTRIES) {
            fprintf(stderr, "support list overflow\n");
            break;
        }

        cJSON* m_name = cJSON_GetObjectItem(item, "model_name");
        if (!cJSON_IsString(m_name)) {
            continue;
        }
        strncpy(entry->model_name, cJSON_GetStringValue(m_name), sizeof(entry->model_name));

        cJSON* m_version = cJSON_GetObjectItem(item, "model_version");
        if (!cJSON_IsString(m_version)) {
            continue;
        }
        strncpy(entry->model_version, cJSON_GetStringValue(m_version), sizeof(entry->model_version));

        cJSON* id = cJSON_GetObjectItem(item, "special_id");
        if (!cJSON_IsString(id)) {
            continue;
        }
        strncpy(entry->special_id, cJSON_GetStringValue(id), sizeof(entry->special_id));

        cJSON* f_version = cJSON_GetObjectItem(item, "flash_version");
        if (!cJSON_IsString(f_version)) {
            continue;
        }
        strncpy(entry->flash_version, cJSON_GetStringValue(f_version), sizeof(entry->flash_version));

        support->count++;
    }
    cJSON_free(root);
    return 0;

err:
    cJSON_free(root);
    return -1;
}

void dkmgt_support_list_dump(const struct dkmgt_support_list *support, FILE *fp) {
    fprintf(fp, "Supported Devices:\n");
    fprintf(fp, "\t%-024s  %08s  %08s  %s\n", "MODEL", "VERSION", "SPECIAL", "FLASH");
    for (int i = 0; i < support->count; i++) {
        const struct dkmgt_support_entry* entry = &support->list[i];
        fprintf(fp, "\t%-024s  %08s  %08s  %s\n", entry->model_name, entry->model_version, entry->special_id, entry->flash_version);
    }
    fprintf(fp, "\n");
}

static int dkmgt_fw_info_parse(const struct dkmgt_ptn_table* ptable, struct dkmgt_fw_info *fwinfo) {
    struct dkmgt_ptn_header hdr;
    const char* data = dkmgt_ptn_lookup(ptable, "firmware-info", &hdr);
    if (!data) {
        data = dkmgt_ptn_lookup(ptable, "firmware-info.b", &hdr);
        if (!data) {
            return -1;
        }
    }
    cJSON *root = cJSON_ParseWithLength(data, hdr.length);
    if (!root) {
        fprintf(stderr, "Firmware info JSON malformed\n");
        return -1;
    }

    memset(fwinfo, 0, sizeof(struct dkmgt_fw_info));
    do {
        if (!cJSON_IsObject(root)) {
            break;
        }
        cJSON* swver = cJSON_GetObjectItem(root, "software-version");
        cJSON* fwid = cJSON_GetObjectItem(root, "firmware-id");
        if (!swver || !cJSON_IsString(swver) || !fwid || !cJSON_IsString(fwid)) {
            break;
        }
        strncpy(fwinfo->firmware_id, cJSON_GetStringValue(fwid), sizeof(fwinfo->firmware_id));

        // Parse the software version number.
        char* version = cJSON_GetStringValue(swver);
        char* end;
        fwinfo->ver_major = strtoul(version, &end, 10);
        if (*end != '.') {
            break;
        }
        version = end+1;
        fwinfo->ver_minor = strtoul(version, &end, 10);
        if (*end != '.') {
            break;
        }
        version = end+1;
        fwinfo->ver_patch = strtoul(version, &end, 10);
        if (!isspace(*end)) {
            break;
        }
        version = end+1;

        // Parse the build numver.
        while (isspace(*version) || !isdigit(*version)) version++;
        fwinfo->buildnum = strtoul(version, &end, 10);
        if (!isspace(*end)) {
            break;
        }
        version = strchr(end, '.');

        // Parse the release number.
        if (version) {
            fwinfo->release = strtoul(version+1, &end, 10);
        }
        cJSON_free(root);
        return 0;
    } while(0);

    fprintf(stderr, "Firmware info JSON malformed\n");
    cJSON_free(root);
    return -1;
}

void dkmgt_fw_info_dump(const struct dkmgt_fw_info *fwinfo, FILE *fp) {
    fprintf(fp, "Firmware Info:\n");
    fprintf(fp, "\tversion: %d.%d.%d\n", fwinfo->ver_major, fwinfo->ver_minor, fwinfo->ver_patch);
    fprintf(fp, "\tbuild:   %u\n", fwinfo->buildnum);
    fprintf(fp, "\trelease: %u\n", fwinfo->release);
    fprintf(fp, "\tid:      %s\n", fwinfo->firmware_id);
    fprintf(fp, "\n");
}

struct dkmgt_firmware* dkmgt_firmware_parse(const void* data, size_t length) {
    if (length < sizeof(struct dkmgt_fw_header)) {
        fprintf(stderr, "Firmware header truncated\n");
        return NULL;
    }

    struct dkmgt_firmware* fw = calloc(sizeof(struct dkmgt_firmware), 1);
    dkmgt_fw_header_parse(data, length, &fw->header);
    if (length < fw->header.total_len) {
        fw->md5check = "truncated";
        fprintf(stderr, "Firmware contents truncated\n");
        free(fw);
        return NULL;
    }
    fw->md5check = dkmgt_validate_md5(&fw->header, data);

    // Parse the partition table so long as it hasn't been truncated.
    if (fw->header.header_len + 0x10000 <= length) {
        dkmgt_ptn_table_parse(&fw->header, data, &fw->ptable);
    }
    return fw;
}

void dkmgt_firmware_free(struct dkmgt_firmware *fw) {
    free(fw);
}

void dkmgt_firmware_dump(const struct dkmgt_firmware *fw, FILE *fp) {
    // Start by parsing the firmware file header.
    dkmgt_fw_header_dump(&fw->header, fw->md5check, fp);
    dkmgt_ptn_table_dump(&fw->ptable, fp);

    struct dkmgt_fw_info fwinfo;
    if (dkmgt_fw_info_parse(&fw->ptable, &fwinfo) >= 0) {
        dkmgt_fw_info_dump(&fwinfo, fp);
    }

    // Parse and display the support list.
    struct dkmgt_support_list support;
    if (dkmgt_support_list_parse(&fw->ptable, &support) >= 0) {
        dkmgt_support_list_dump(&support, fp);
    }

}
