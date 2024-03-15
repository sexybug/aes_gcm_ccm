#ifndef _TEST_H_
#define _TEST_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/**
 * @brief 打印内存数据
 *
 * @param ptr
 * @param len
 */
void dump_mem(const void *ptr, int len);

/**
 * @brief 16进制字符串转数组
 *
 * @param str 16进制字符串
 * @param strLen 字节串长度(in Byte)
 * @param out 输出
 */
void HexString2Hex(const char *str, int strLen, uint8_t *out);

#endif // _TEST_H_