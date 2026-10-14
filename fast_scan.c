#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#pragma pack(push, 1)
typedef struct {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_hdr_t;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcaprec_hdr_t;
#pragma pack(pop)

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file.pcap>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("Could not open pcap file");
        return 1;
    }

    pcap_hdr_t ghdr;
    if (fread(&ghdr, sizeof(pcap_hdr_t), 1, fp) != 1) {
        fprintf(stderr, "Failed to read global header\n");
        fclose(fp);
        return 1;
    }

    if (ghdr.magic_number != 0xa1b2c3d4 && ghdr.magic_number != 0xd4c3b2a1) {
        fprintf(stderr, "Unsupported file format (use standard .pcap, not .pcapng)\n");
        fclose(fp);
        return 2;
    }

    pcaprec_hdr_t phdr;
    uint64_t total_pkts = 0;
    uint64_t total_bytes = 0;
    uint32_t first_ts = 0;
    uint32_t last_ts = 0;

    while (fread(&phdr, sizeof(pcaprec_hdr_t), 1, fp) == 1) {
        if (total_pkts == 0) {
            first_ts = phdr.ts_sec;
        }
        last_ts = phdr.ts_sec;
        total_pkts++;
        total_bytes += phdr.orig_len;

        if (fseek(fp, phdr.incl_len, SEEK_CUR) != 0) {
            break;
        }
    }

    fclose(fp);

    uint32_t duration = (last_ts >= first_ts) ? (last_ts - first_ts) : 0;
    double avg_size = (total_pkts > 0) ? ((double)total_bytes / total_pkts) : 0.0;

    printf("PCAP_VERSION=%u.%u\n", ghdr.version_major, ghdr.version_minor);
    printf("SNAPLEN=%u\n", ghdr.snaplen);
    printf("TOTAL_PKTS=%llu\n", (unsigned long long)total_pkts);
    printf("TOTAL_BYTES=%llu\n", (unsigned long long)total_bytes);
    printf("DURATION_SEC=%u\n", duration);
    printf("AVG_PKT_SIZE=%.2f\n", avg_size);

    return 0;
}
