Firmware Upgrade File Format
----------------------------

The DKMGT firmware format used by the TP-Link ER8411 appears to contain three
sections:
 - Header
 - Upgrade partition table
 - Upgrade data block

The header section is (typically) 4160 bytes in length and contains an MD5
checksum and RSA signature. Although the header does contain a `header_len`
field that should make the header size dynamic, it seems that there are some
firmware tools in the router that hard-code the header size, so it is probably
unsafe to change it.

The format of the header is as follows:
```
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
```

The next 64kiB of data immediately following the header contains the upgrade
partiton table. This is a JSON file that gives the UBI/MTD partition names to be
upgraded as well as the offset and length into the upgrade data block where the
new partition data can be found.

Partitions
----------

The following flash partitions have been found on the ER8411

| Name                | Description                                                       |
| ------------------- | ----------------------------------------------------------------- |
| bootloader-factory  | Factory bootloader in SPI NOR flash.                              |
| bootloader-recovery | Recovery bootloader in SPI NOR flash.                             |
| partition-table     | JSON file describing the NAND flash partition layout              |
| support-list        | JSON file listing the hardware devices supported by this firmware |
| device-info         | JSON file describing the hardware                                 |
| kernel              | FDT and Linux Kernel                                              |
| rootfs              | Squashfs root filesystem                                          |
| firmware-info       | JSON file describint the current firmware                         |
| rootfs_data         |                                                                   |
| log                 |                                                                   |
| extra-para          | JSON file to select primary vs. backup firmware to boot           |
| tddp                | Seems to contain device configuration                             |
| database            |                                                                   |
| log_recovery        |                                                                   |

Many of these partitions may be duplicated with a '.b' suffix which indicates
they are backup partitions.
