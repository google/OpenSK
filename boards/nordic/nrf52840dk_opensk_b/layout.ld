/* Memory Space Definitions, 1M flash, 256K ram */
MEMORY
{
  rom (rx)  : ORIGIN = 0x00060000, LENGTH = 128K
  prog (rx) : ORIGIN = 0x00080000, LENGTH = 128K
  ram (rwx) : ORIGIN = 0x20000000, LENGTH = 256K
}

MPU_MIN_ALIGN = 8K;
PAGE_SIZE = 4K;

INCLUDE ../../kernel_layout.ld

