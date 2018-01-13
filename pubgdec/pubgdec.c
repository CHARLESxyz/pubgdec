#include <stdarg.h>
#include <stdio.h>
#include "def.h"

// https://github.com/calccrypto/uint128_t
#ifdef __cplusplus
#include "uint128_t.h"
#endif

#ifdef _MSC_VER

#pragma warning(disable: 4244)
#pragma warning(disable: 4293)

#endif

#ifdef __cplusplus
#define EXTERN extern "C"
#else
#define EXTERN
#endif

/*
InterlockedCompareExchange128
*/

#ifdef __GNUC__

static unsigned char _InterlockedCompareExchange128(int64 volatile *Destination, int64 ExchangeHigh, int64 ExchangeLow, int64* ComparandResult) {
	unsigned char Equal;
	__asm__ __volatile__
	(
		"lock cmpxchg16b %1\n\t"
		"setz %0"
		: "=q" (Equal), "+m" (*Destination), "+d" (ComparandResult[1]), "+a" (ComparandResult[0])
		: "c" (ExchangeHigh), "b" (ExchangeLow)
		: "cc"
	);
	return Equal;
}

#else

EXTERN unsigned char __cdecl _InterlockedCompareExchange128(int64 volatile *Destination, int64 ExchangeHigh, int64 ExchangeLow, int64 *ComparandResult);

#endif

/*
debug
*/

EXTERN int __stdcall MessageBoxA(void *, const char *, const char *, int);

void debug(const char *format, ...) {
	va_list ap;
	va_start(ap, format);
	char text[0x200];
	vsprintf(text, format, ap);
	va_end(ap);
	MessageBoxA((void *)0, text, "debug", 0);
}

/*
rpm
*/

#define DUMMY_PID 1
#define DUMMY_BASE_ADDR 2
#define DUMMY_READ 3
#define DUMMY_WRITE 4

typedef struct dummy {
	void *handle;
	uint64 user_pid;
	uint64 game_pid;
	uint64 game_base_addr;
} dummy;

typedef struct dummy_request {
	uint64 msg;
	uint64 user_pid;
	uint64 user_addr;
	uint64 game_pid;
	uint64 game_addr;
	uint64 size;
} dummy_request;

EXTERN int __stdcall WriteFile(void *, const void *, uint, uint *, void *);

static int dummy_read(dummy *dummy, void *game_addr, void *user_addr, uint64 size) {
	dummy_request request;
	uint written;
	request.msg = DUMMY_READ;
	request.user_pid = dummy->user_pid;
	request.user_addr = (uint64)user_addr;
	request.game_pid = dummy->game_pid;
	request.game_addr = (uint64)game_addr;
	request.size = size;
	return WriteFile(dummy->handle, &request, sizeof(dummy_request), &written, (void *)0);
}

static uint8 dummy_read8(dummy *dummy, void *game_addr) {
	uint8 ret = 0;
	dummy_read(dummy, game_addr, &ret, 1);
	return ret;
}

static uint16 dummy_read16(dummy *dummy, void *game_addr) {
	uint16 ret = 0;
	dummy_read(dummy, game_addr, &ret, 2);
	return ret;
}

static uint32 dummy_read32(dummy *dummy, void *game_addr) {
	uint32 ret = 0;
	dummy_read(dummy, game_addr, &ret, 4);
	return ret;
}

static uint64 dummy_read64(dummy *dummy, void *game_addr) {
	uint64 ret = 0;
	dummy_read(dummy, game_addr, &ret, 8);
	return ret;
}

#define READ(addr, dest, size) dummy_read(dummy, (void *)(addr), dest, size)
#define READ8(addr) dummy_read8(dummy, (void *)(addr))
#define READ16(addr) dummy_read16(dummy, (void *)(addr))
#define READ32(addr) dummy_read32(dummy, (void *)(addr))
#define READ64(addr) dummy_read64(dummy, (void *)(addr))

/*
dec
*/

typedef struct int128 {
	int64 low;
	int64 high;
} int128;

#ifdef __cplusplus
typedef uint128_t uint128;
#else
#ifdef __GNUC__
typedef unsigned __int128 uint128;
#else
#error uint128
#endif
#endif

#define GET_ADDR(addr) (dummy->game_base_addr + (addr))

#define TABLE_SIZE 256

typedef struct decrypt_struct {
	uint8 table[TABLE_SIZE];
	uint32 xor1;
	uint32 xor2;
} decrypt_struct;

static decrypt_struct g_decrypt;

void decinit(dummy *dummy) {
	READ(GET_ADDR(0x3AFF120), g_decrypt.table, TABLE_SIZE);
	g_decrypt.xor1 = READ32(700 + GET_ADDR(0x3DEB690));
	g_decrypt.xor2 = READ32(924 + GET_ADDR(0x3DEB690));
}

static uint8 read_table(uint32 index) {
	if (index >= TABLE_SIZE) {
		debug("[read_table] out of bounds = %d", index);
	}
	return g_decrypt.table[index];
}

static uint64 dec1(dummy *dummy, int128 *_RCX22) {
	uint64 v1;
	int128 v2;
	uint8 v3;
	uint v4;
	int16 v5;
	uint v6;
	uint64 v7;
	uint64 v8;
	uint64 v9;
	uint8 v11;
	uint16 v13;
	uint v14;
	char v16;
	int v19;
	do
	{
		v2 = *_RCX22;
		v3 = _InterlockedCompareExchange128((int64 *)_RCX22, v2.high, v2.low, (int64 *)&v2);
		v1 = v2.high;
		v19 = DWORD1(v2);
		v4 = v2.low;
		v5 = WORD4(v2);
	} while (!v3);
	v6 = 2067041945;
	v7 = ((_DWORD)v1
		+ v4
		+ HIDWORD(v1)
		- 2145172163
		* (uint)((uint64)(((v1 + v4 + (v1 >> 32)) * (uint128)0x469DEF623F2C51u >> 64)
			+ ((uint64)(v1
				+ v4
				+ (v1 >> 32)
				- ((v1 + v4 + (v1 >> 32))
					* (uint128)0x469DEF623F2C51u >> 64)) >> 1)) >> 30)) ^ 0xFEA07C43;
	v8 = 0;
	v9 = 0;
	do
	{
		v11 = v6 + v9++;
		LODWORD(v7) = ((read_table(BYTE2(v7)) | (((read_table((uint8)v7) << 8) | read_table(BYTE1(v7))) << 8)) << 8) | read_table((v7 >> 24));
		v6 = read_table((uint64)v6 >> 24) | ((read_table(BYTE2(v6)) | (((read_table((uint8)v6) << 8) | read_table(BYTE1(v6))) << 8)) << 8);
	} while (v9 < 3);
	if ((v6 ^ (uint)v7) != v19)
	{
		// error
		return 0;
	}
	v13 = v5 ^ ~(_WORD)v4 ^ 0xD25;
	do
	{
		v14 = v13;
		v16 = v8++ + 2;
		v13 = read_table(read_table((v14 ^ 0x4400u) >> 8)) | (uint16)(read_table(read_table((uint8)(v14 ^ 0x55))) << 8);
	} while (v8 < 5);
	return ~(
		READ32((uint64)(4) * (uint8)(v13 ^ 0xBC) + GET_ADDR(0x3DEBE90)) ^
		READ32(4 * ((uint64)(v13 ^ 0xD7AF5ABC) >> 24) + GET_ADDR(0x3DEB290)) ^
		(READ32((uint64)(4) * (uint8)(HIBYTE(v13) ^ 0x5A) + GET_ADDR(0x3DEBA90)) ^ g_decrypt.xor1)) % 0x2B;
}

static uint64 dec2(dummy *dummy, int128 *_RCX23) {
	uint64 v1;
	int128 v2;
	uint8 v3;
	uint v4;
	int16 v5;
	uint v6;
	uint64 v7;
	uint64 v8;
	uint64 v9;
	uint8 v11;
	uint16 v13;
	uint v14;
	char v16;
	int v19;
	do
	{
		v2 = *_RCX23;
		v3 = _InterlockedCompareExchange128((int64 *)_RCX23, v2.high, v2.low, (int64 *)&v2);
		v1 = v2.high;
		v19 = DWORD1(v2);
		v4 = v2.low;
		v5 = WORD4(v2);
	} while (!v3);
	v6 = 2067041945;
	v7 = ((_DWORD)v1
		+ v4
		+ HIDWORD(v1)
		- 2145172163
		* (uint)((uint64)(((v1 + v4 + (v1 >> 32)) * (uint128)0x469DEF623F2C51u >> 64)
			+ ((uint64)(v1
				+ v4
				+ (v1 >> 32)
				- ((v1 + v4 + (v1 >> 32))
					* (uint128)0x469DEF623F2C51u >> 64)) >> 1)) >> 30)) ^ 0xFEA07C43;
	v8 = 0;
	v9 = 0;
	do
	{
		v11 = v6 + v9++;
		LODWORD(v7) = ((read_table(BYTE2(v7)) | (((read_table((uint8)v7) << 8) | read_table(BYTE1(v7))) << 8)) << 8) | read_table(v7 >> 24);
		v6 = read_table((uint64)v6 >> 24) | ((read_table(BYTE2(v6)) | (((read_table((uint8)v6) << 8) | read_table(BYTE1(v6))) << 8)) << 8);
	} while (v9 < 3);
	if ((v6 ^ (uint)v7) != v19)
	{
		// error
		return 0;
	}
	v13 = v5 ^ ~(_WORD)v4 ^ 0xD25;
	do
	{
		v14 = v13;
		v16 = v8++ + 2;
		v13 = read_table(read_table((v14 ^ 0x4400u) >> 8)) | (uint16)(read_table(read_table((uint8)(v14 ^ 0x55))) << 8);
	} while (v8 < 5);
	return ~(
		READ32((uint64)(4) * (uint8)(v13 ^ 0xC) + GET_ADDR(0x3DEBE90)) ^
		READ32(4 * ((uint64)(v13 ^ 0x5CE7E30Cu) >> 24) + GET_ADDR(0x3DEB290)) ^
		(READ32((uint64)(4) * (uint8)(HIBYTE(v13) ^ 0xE3) + GET_ADDR(0x3DEBA90)) ^ g_decrypt.xor2)) % 0x2B;
}

uint64 decptr(dummy *dummy, void *x) {
	int128 rcx22;
	int128 rcx23;
	READ((int128 *)x + 22, &rcx22, sizeof(int128));
	READ((int128 *)x + 23, &rcx23, sizeof(int128));
	uint64 xor1 = READ64((uint64 *)x + dec1(dummy, &rcx22));
	uint64 xor2 = dec2(dummy, &rcx23);
	return xor1 ^ xor2;
}
