#ifdef __gnu_linux__
    #define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define GET_OFFSET(len, x) (x - (uintptr_t) libimg4)

typedef unsigned long long addr_t;

void exception() {
        printf("patch not found!\n");
    	exit(1);
}

/*function imported from xerub's patchfinder64*/

static addr_t
step64(const uint8_t *buf, addr_t start, size_t length, uint32_t what, uint32_t mask)
{
    addr_t end = start + length;
    while (start < end) {
        uint32_t x = *(uint32_t *)(buf + start);
        if ((x & mask) == what) {
            return start;
        }
        start += 4;
    }
    return 0;
}

/*function imported from xerub's patchfinder64*/

static addr_t
step64_back(const uint8_t *buf, addr_t start, size_t length, uint32_t what, uint32_t mask)
{
    addr_t end = start - length;
    while (start >= end) {
        uint32_t x = *(uint32_t *)(buf + start);
        if ((x & mask) == what) {
            return start;
        }
        start -= 4;
    }
    return 0;
}

/*function imported from xerub's patchfinder64*/

static addr_t
xref64(const uint8_t *buf, addr_t start, addr_t end, addr_t what)
{
    addr_t i;
    uint64_t value[32];

    memset(value, 0, sizeof(value));

    end &= ~3;
    for (i = start & ~3; i < end; i += 4) {
        uint32_t op = *(uint32_t *)(buf + i);
        unsigned reg = op & 0x1F;
        if ((op & 0x9F000000) == 0x90000000) {
            signed adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //printf("%llx: ADRP X%d, 0x%llx\n", i, reg, ((long long)adr << 1) + (i & ~0xFFF));
            value[reg] = ((long long)adr << 1) + (i & ~0xFFF);
            continue;				// XXX should not XREF on its own?
        /*} else if ((op & 0xFFE0FFE0) == 0xAA0003E0) {
            unsigned rd = op & 0x1F;
            unsigned rm = (op >> 16) & 0x1F;
            //printf("%llx: MOV X%d, X%d\n", i, rd, rm);
            value[rd] = value[rm];*/
        } else if ((op & 0xFF000000) == 0x91000000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned shift = (op >> 22) & 3;
            unsigned imm = (op >> 10) & 0xFFF;
            if (shift == 1) {
                imm <<= 12;
            } else {
                //assert(shift == 0);
                if (shift > 1) continue;
            }
            //printf("%llx: ADD X%d, X%d, 0x%x\n", i, reg, rn, imm);
            value[reg] = value[rn] + imm;
        } else if ((op & 0xF9C00000) == 0xF9400000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 3;
            //printf("%llx: LDR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            if (!imm) continue;			// XXX not counted as true xref
            value[reg] = value[rn] + imm;	// XXX address, not actual value
        /*} else if ((op & 0xF9C00000) == 0xF9000000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 3;
            //printf("%llx: STR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            if (!imm) continue;			// XXX not counted as true xref
            value[rn] = value[rn] + imm;	// XXX address, not actual value*/
        } else if ((op & 0x9F000000) == 0x10000000) {
            signed adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //printf("%llx: ADR X%d, 0x%llx\n", i, reg, ((long long)adr >> 11) + i);
            value[reg] = ((long long)adr >> 11) + i;
        } else if ((op & 0xFF000000) == 0x58000000) {
            unsigned adr = (op & 0xFFFFE0) >> 3;
            //printf("%llx: LDR X%d, =0x%llx\n", i, reg, adr + i);
            value[reg] = adr + i;		// XXX address, not actual value
        }
        if (value[reg] == what) {
            return i;
        }
    }
    return 0;
}

int get_signature_check_patch(void *libimg4, size_t len) {

    printf("getting %s()\n", __FUNCTION__);

    void *firm_auth = memmem(libimg4,len,"firmware authenticated", strlen("firmware authenticated"));
    if (!firm_auth) {
    	exception();
    }

	printf("[*] firmware authenticated string at 0x%llx\n", (int64_t) GET_OFFSET(len, firm_auth));

    addr_t ref_firm_auth = xref64(libimg4,0,len,(addr_t)GET_OFFSET(len, firm_auth));
    
    if(!ref_firm_auth) {
    	exception();
    }

    printf("[*] firmware authenticated xref at 0x%llx\n", (int64_t) ref_firm_auth);

    addr_t current_addr = 0;
    //searching for next unconditional branch instruction 'b'
    current_addr = step64(libimg4, ref_firm_auth, 40, 0x14000000, 0xFC000000);

    if (current_addr) {
        printf("[*] next b at 0x%llx\n", (int64_t) current_addr);

        //go to the target of the branch instruction
        int32_t imm = 0;
        int32_t branch_offset = 0;
        imm = (*(uint32_t *) (libimg4 + current_addr)) & 0x03FFFFFF;
        //check for negative offset
        if ((imm & 0x02000000))
            imm |= 0xFC000000;
        branch_offset = imm << 2;
        current_addr += branch_offset;
        printf("[*] target offset: 0x%llx\n", current_addr);

        //search for next b.ne (b.cond)
        current_addr = step64(libimg4, current_addr, 15 * 4, 0x54000000, 0xFF000000);

        if(!current_addr) {
            exception();
        }

        printf("[*] next b.cond at 0x%llx\n", (int64_t) current_addr);

        printf("[*] patching b.cond to nop\n");

        *(uint32_t *) (libimg4 + current_addr) = 0xd503201f;

        //searching for next mov (register to register, implemented as orr)
        current_addr = step64(libimg4, current_addr, 5 * 4, 0xaa0003e0, 0xffc0ffe0);

        if(!current_addr) {
            exception();
        }

        printf("[*] next mov at 0x%llx\n", (int64_t) current_addr);

        printf("[*] patching return value to 0\n");

        //mov x0, #0
        *(uint32_t *) (libimg4 + current_addr) = 0xd2800000;
    }

    //searching for next ret instead (iOS 15)
    else {
        current_addr = step64(libimg4, ref_firm_auth, 128, 0xd65f0000, 0xffff0000);

        if(!current_addr) {
            exception();
        }

        printf("[*] next ret at 0x%llx\n", (int64_t) current_addr);


        //searching for previous mov (register to register, implemented as orr)
        current_addr = step64_back(libimg4, current_addr, 128, 0xaa0003e0, 0xffc0ffe0);

        if(!current_addr) {
            exception();
        }

        printf("[*] previous mov at 0x%llx\n", (int64_t) current_addr);

        printf("[*] patching return value to 0\n");

        //mov x0, #0
        *(uint32_t *) (libimg4 + current_addr) = 0xd2800000;


        //searching for previous b.ne
        current_addr = step64_back(libimg4, current_addr, 128, 0x54000001, 0xff00000f);

        if(!current_addr) {
            exception();
        }

        printf("[*] previous b.ne at 0x%llx\n", (int64_t) current_addr);

        printf("[*] patching b.ne to nop\n");

        *(uint32_t *) (libimg4 + current_addr) = 0xd503201f;
    }

    return 0;

}


int main(int argc, char* argv[]) { 

	if (argc < 3) {
		printf("Incorrect usage!\n");
		printf("Usage: %s [libimg4] [Patched libimg4]\n", argv[0]);
		return -1;
	}

	char *in = argv[1];
	char *out = argv[2];

	void *libimg4;
	size_t len;

	 FILE* fp = fopen(in, "rb");
     if (!fp) {
     	printf("[-] Failed to open libimg4\n");
     	return -1;
     }

    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    libimg4 = (void*)malloc(len);
    if(!libimg4) {
        printf("[-] Out of memory\n");
        fclose(fp);
        return -1;
    }

    fread(libimg4, 1, len, fp);
    fclose(fp);

    get_signature_check_patch(libimg4,len);


    printf("[*] Writing out patched file to %s\n", out);

    fp = fopen(out, "wb+");

    fwrite(libimg4, 1, len, fp);
    fflush(fp);
    fclose(fp);
    
    free(libimg4);

    
    return 0;

}
