#include <stdio.h>
#include <stdint.h>
#include <stdlib.h> 
#include <time.h>
#include "AES.h"

const uint64_t mod = 0x100000000;

//定义大整数
typedef struct {
	int sign; //符号， 0代表正数， 1代表负数
	int len; //大整数有多少位
	uint32_t position[64]; //定义2^32进制的数，在RSA模数为512的情况下，两数相乘最多1024比特，position[0]表示最低位，保存数据的绝对值
}bigint;

typedef struct {
	int len;
	uint32_t bin[1024];
}uint2_t;

// 打印大整数
void print_bigint(bigint num) {
	if (num.sign) printf("- 0x");
	else printf("  0x");
	for (int i = num.len - 1; i >= 0; --i) {
		printf("%08x ", num.position[i]);
	}
	printf("\n");
}

// 打印二进制
void print_binary(uint2_t num) {
	// 检查长度是否有效
	if (num.len <= 0) {
		printf("0\n"); // 如果长度为 0，直接打印 0
		return;
	}

	// 按二进制的顺序从高位到低位打印
	for (int i = num.len - 1; i >= 0; i--) {
		printf("%d", num.bin[i]);
		// 每 8 位添加一个空格，便于阅读
		if (i > 0 && i % 8 == 0) {
			printf(" ");
		}
	}

	printf("\n"); // 换行
}

/*
	name: mod_2_k
	discrption: 数据模2^k
	input: 大整数a，模2的k次幂
	output: a % (2^k)
*/
bigint mod_2_k(bigint a, int k) {
	bigint result = a;

	// 计算需要保留的位数
	int full_words = k / 32;      // 完整的 32 位块
	int remaining_bits = k % 32; // 剩余的位数

	// 保留完整的块
	for (int i = full_words + 1; i < a.len; ++i) {
		result.position[i] = 0; // 清零超出位数的块
	}

	// 保留部分位数
	if (remaining_bits > 0 && full_words < a.len) {
		uint32_t mask = (1U << remaining_bits) - 1; // 生成部分位的掩码
		result.position[full_words] &= mask;       // 应用掩码
	}

	// 更新结果长度
	result.len = full_words + (remaining_bits > 0 ? 1 : 0);
	return result;
}

/*
	name: addition_without_sign
	discrption: 不考虑符号的相加，仅将两数的绝对值相加，得到的数符号与传入的两数相同
	input: 输入两个符号相同的数相加
	output: 输出两数绝对值相加的结果
*/
bigint addition_without_sign(bigint a, bigint b) {
	bigint result;
	result.sign = a.sign; // 符号保持一致
	result.len = (a.len > b.len) ? a.len : b.len; // 结果的长度至少等于较长的输入

	uint64_t carry = 0; // 进位
	uint64_t sum;

	// 按位相加
	for (int i = 0; i < result.len; ++i) {
		sum = carry;
		if (i < a.len) sum += a.position[i];
		if (i < b.len) sum += b.position[i];

		result.position[i] = (uint32_t)(sum & 0xFFFFFFFF); // 当前位的值
		carry = sum >> 32; // 计算新的进位
	}

	// 如果最高位有进位
	if (carry > 0) {
		result.position[result.len] = (uint32_t)carry;
		result.len += 1;
	}

	// 确保多余的高位清零
	for (int i = result.len; i < 32; ++i) {
		result.position[i] = 0;
	}

	return result;
}

/*
	name: compare_abs
	discrption: 比较无符号两个大整数的大小
	input: 输入俩个无符号的大整数a, b
	output: 输出两数的大小关系，若a > b 返回 1, 若a < b 返回 -1, 若a = b 返回 0
*/
int compare_abs(bigint a, bigint b) {
	// 比较位数，位数多的数字较大
	if (a.len > b.len) return 1;
	if (a.len < b.len) return -1;

	// 位数相同，逐位比较
	for (int i = a.len - 1; i >= 0; --i) {
		if (a.position[i] > b.position[i]) return 1;
		if (a.position[i] < b.position[i]) return -1;
	}

	// 如果所有位都相等
	return 0;
}

/*
	name: subtraction_without_sign
	discrption: 输入两个大整数a,b且都为正数,输出其相减后的结果
	input: 大整数a, 大整数b, a,b都为正数
	output: a - b
*/
bigint subtraction_without_sign(bigint a, bigint b) {
	bigint result = { 0 }; // 初始化结果
	int cmp = compare_abs(a, b);

	// 如果 a < b，交换 a 和 b，并标记为负数
	if (cmp < 0) {
		bigint temp = a;
		a = b;
		b = temp;
		result.sign = 1; // 结果为负数
	}
	else {
		result.sign = 0; // 结果为正数
	}

	// 减法操作
	int borrow = 0;             // 借位标记
	result.len = a.len;         // 结果长度与较大数一致

	for (int i = 0; i < result.len; ++i) {
		// 获取当前位的被减数与减数
		uint64_t minuend = (uint64_t)a.position[i];
		uint64_t subtrahend = (i < b.len ? (uint64_t)b.position[i] : 0);

		// 减去当前位的值和借位
		uint64_t diff = minuend - subtrahend - borrow;

		if (diff > 0xFFFFFFFF) { // 检查借位
			borrow = 1;
			result.position[i] = (uint32_t)(diff + (1ULL << 32)); // 修正差值
		}
		else {
			borrow = 0;
			result.position[i] = (uint32_t)diff;
		}
	}

	// 去掉高位无效的 0
	while (result.len > 1 && result.position[result.len - 1] == 0) {
		result.len--;
	}

	return result;
}

/*
	name: compare_with_sing
	discrption: 比较有符号两个大整数的大小
	input: 输入两个有符号的大整数a, b
	output: 输出两数的大小关系，若a > b 返回 1, 若a < b 返回 -1, 若a = b 返回 0
*/
int compare_with_sign(bigint a, bigint b) {
	// 如果符号不同，负数小于正数
	if (a.sign != b.sign) return a.sign ? -1 : 1;  // 负数小于正数

	// 符号相同，比较绝对值
	return compare_abs(a, b);  // 使用 compare_abs 比较绝对值
}

/*
	name: addition_with_sign
	discrption: 考虑有符号数的相加，得到的数符号依据数的不同而不同
	input: 输入两个有符号的数相加
	output: 输出两数相加的结果
*/
bigint addition_with_sign(bigint a, bigint b) {
	bigint result;

	// 情况 1: 符号相同，直接执行无符号加法
	if (a.sign == b.sign) {
		result = addition_without_sign(a, b);
		result.sign = a.sign;  // 结果的符号与输入相同
		return result;
	}

	// 情况 2: 符号不同，计算绝对值较大的数减去较小的数
	int cmp = compare_abs(a, b);
	if (cmp > 0) { // |a| > |b|
		result = subtraction_without_sign(a, b);
		result.sign = a.sign;  // 结果符号与 a 的符号相同
	}
	else if (cmp < 0) { // |a| < |b|
		result = subtraction_without_sign(b, a);
		result.sign = b.sign;  // 结果符号与 b 的符号相同
	}
	else { // |a| == |b|，结果为零
		result.sign = 0;
		result.len = 1;
		result.position[0] = 0;
	}

	return result;
}

/*
	name: subtraction_with_sign
	discrption: 输入两个大整数a,b,输出其相减后的结果
	input: 大整数a, 大整数b, a,b符号不定
	output: a - b
*/
bigint subtraction_with_sign(bigint a, bigint b) {
	// 创建 b 的相反数
	bigint neg_b = b;
	neg_b.sign = 1 - b.sign;  // 反转符号

	// 执行 a + (-b)
	return addition_with_sign(a, neg_b);
}

/*
	name: multiplication_without_sign
	discrption: 将两个无符号的大整数相乘
	input: 无符号的大整数a,b
	output: 两大整数相乘的结果
*/
bigint multiplication_without_sign(bigint a, bigint b) {
	bigint result = { 0, 0, {0} };
	uint64_t carry;

	// 逐位相乘，模拟竖式乘法
	for (int i = 0; i < a.len; i++) {
		carry = 0;
		for (int j = 0; j < b.len || carry; j++) {
			uint64_t prod = (uint64_t)result.position[i + j] +
				(uint64_t)a.position[i] * (j < b.len ? b.position[j] : 0) +
				carry;
			result.position[i + j] = prod % (1ULL << 32);
			carry = prod / (1ULL << 32);
		}
	}

	// 计算结果的长度
	result.len = a.len + b.len;
	while (result.len > 1 && result.position[result.len - 1] == 0) {
		result.len--;
	}

	return result;
}

/*
	name: multiplication
	discrption: 将两个有符号的大整数相乘
	input: 有符号的大整数a,b
	output: 两大整数相乘的结果
*/
bigint multiplication(bigint a, bigint b) {
	// 符号计算：结果符号取决于 a.sign 和 b.sign 的异或
	int result_sign = a.sign ^ b.sign;

	// 计算绝对值相乘
	bigint abs_result = multiplication_without_sign(a, b);

	// 设置符号
	abs_result.sign = result_sign;

	return abs_result;
}


/*
	name: bigint_to_binary
	discrption: 将输入的2^32进制的数转化为2进制数
	input: 2^32进制数
	output: 2进制数
*/
uint2_t bigint_to_binary(bigint a) {
	uint2_t result = { 0 }; // 初始化结果
	int bit_index = 0;    // 当前二进制存储的位置索引

	// 遍历 bigint 的每个位置
	for (int i = 0; i < a.len; i++) {
		uint32_t value = a.position[i];
		int valid_bits = 32; // 默认每个位置有 32 位

		// 如果是最高位，计算实际的有效位数
		if (i == a.len - 1) {
			while (valid_bits > 0 && (value & (1U << (valid_bits - 1))) == 0) {
				valid_bits--; // 从高位向低位寻找第一个 1
			}
		}

		// 提取有效位的二进制
		for (int j = 0; j < valid_bits; j++) {
			result.bin[bit_index++] = value & 1; // 提取最低位
			value >>= 1;                        // 右移一位
		}
	}

	// 更新二进制长度
	result.len = bit_index;

	return result;
}

/*
	name: subtract_binary
	discrption: 输入两个二进制数a,b,输出其相减后的结果
	input: 二进制数a, 二进制数b, 
	output: a - b
*/
uint2_t subtract_binary(uint2_t a, uint2_t b) {
	uint2_t result = { 0 };
	result.len = a.len;
	int borrow = 0;

	for (int i = 0; i < a.len; i++) {
		int sub = a.bin[i] - (i < b.len ? b.bin[i] : 0) - borrow;
		if (sub < 0) {
			sub += 2;
			borrow = 1;
		}
		else {
			borrow = 0;
		}
		result.bin[i] = sub;
	}

	// 更新有效长度
	while (result.len > 0 && result.bin[result.len - 1] == 0) {
		result.len--;
	}

	return result;
}

/*
	name: left_shift
	discrption: 将大整数整体左移 shift 位
	input: 大整数 a, 左移位数 shift
	output: a 左移 shift位的结果
*/
bigint left_shift(bigint a, int shift) {
	bigint result = { 0 }; // 初始化结果
	result.sign = a.sign; // 符号保持一致

	// 计算左移多少个 "32 位块" 和 "块内位移"
	int block_shift = shift / 32;       // 左移的块数
	int bit_shift = shift % 32;        // 块内的位移
	int carry_bits = 32 - bit_shift;   // 需要保留的高位部分

	// 设置结果长度
	result.len = a.len + block_shift + (bit_shift > 0 ? 1 : 0);

	// 检查是否超出最大存储范围
	if (result.len > 33) {
		printf("Error: Shift exceeds maximum length.\n");
		result.len = 0;
		return result;
	}

	// 左移块和块内位
	for (int i = a.len - 1; i >= 0; i--) {
		uint64_t shifted_value = (uint64_t)a.position[i] << bit_shift;

		// 保存高位到下一块
		if (i + block_shift + 1 < 33 && bit_shift > 0) {
			result.position[i + block_shift + 1] |= (uint32_t)(shifted_value >> 32);
		}

		// 当前块的低位
		if (i + block_shift < 33) {
			result.position[i + block_shift] |= (uint32_t)(shifted_value & 0xFFFFFFFF);
		}
	}

	// 清除超出范围的位
	while (result.len > 1 && result.position[result.len - 1] == 0) {
		result.len--;
	}

	return result;
}


/*
	name: division_2_k
	discrption: 数据除2^k
	input: 大整数a，除2的k次幂
	output: a / (2^k)
*/
bigint division_2_k(bigint a, int k) {
	bigint result = { 0 }; // 初始化结果
	result.sign = a.sign; // 保留符号

	// 如果 k 为 0，直接返回原数
	if (k == 0) {
		result = a;
		return result;
	}

	// 计算需要右移的完整 position 和剩余的位数
	int shift_positions = k / 32;  // 完整 position 的移动数
	int bit_shift = k % 32;        // 单个 position 内的位移数

	// 如果右移超过了所有位数，结果为 0
	if (shift_positions >= a.len) {
		result.len = 0;
		return result;
	}

	// 更新结果的长度
	result.len = a.len - shift_positions;

	// 逐个处理剩余部分
	uint32_t carry = 0; // 用于跨 position 的进位
	for (int i = a.len - 1; i >= shift_positions; i--) {
		uint64_t current = ((uint64_t)carry << 32) | a.position[i]; // 当前 position 数据加上进位
		result.position[i - shift_positions] = (current >> bit_shift) & 0xFFFFFFFF; // 右移并截断高位
		carry = (uint32_t)(current & ((1U << bit_shift) - 1)); // 保留未移出的部分作为下一个 position 的进位
	}

	// 移除结果中可能多余的高位 0
	while (result.len > 0 && result.position[result.len - 1] == 0) {
		result.len--;
	}

	return result;
}

/*
	name: division_without_sign
	discrption: 使用left_shift函数对大整数进行对齐, 再2进行除法
	input: 被除数a, 除数b
	output: a / b 
*/
bigint division_without_sign(bigint a, bigint b) {
	bigint quotient = { 0 }; // 初始化商
	bigint remainder = a;  // 初始化余数为被除数

	// 特殊情况：除数为0
	if (b.len == 0 || (b.len == 1 && b.position[0] == 0)) {
		printf("Error: Division by zero.\n");
		return quotient;
	}

	// 特殊情况：a < b，直接返回商为0
	if (compare_abs(a, b) < 0) {
		return quotient;
	}

	// 计算移位值，使 b 对齐到 a 的最高位
	int shift = (a.len - b.len) * 32;
	uint32_t high_bit_a = a.position[a.len - 1];
	uint32_t high_bit_b = b.position[b.len - 1];
	while (high_bit_a > high_bit_b) {
		high_bit_a >>= 1;
		shift++;
	}
	while (high_bit_a < high_bit_b) {
		high_bit_b >>= 1;
		shift--;
	}
	bigint shifted_b = left_shift(b, shift);
	//printf("shift:%d\n", shift);

	// 迭代除法
	while (shift >= 0) {
		if (compare_abs(remainder, shifted_b) >= 0) {
			// 如果余数大于等于移位后的 b，则进行减法
			remainder = subtraction_without_sign(remainder, shifted_b);
			/*printf("remainder");
			print_bigint(remainder);*/

			// 更新商，设置对应二进制位
			int block_idx = shift / 32;   // 商的存储位置块
			int bit_idx = shift % 32;    // 商的存储位置位
			quotient.position[block_idx] |= (1U << bit_idx); // 在商的对应位置设置 1
			//printf("%x\n", quotient.position[block_idx]);
		}

		// 无论是否进行了减法操作，都需要右移 b
		shifted_b = division_2_k(shifted_b, 1);
		shift--;
	}

	// 更新商的有效长度
	quotient.len = (a.len > b.len) ? a.len : b.len;
	while (quotient.len > 1 && quotient.position[quotient.len - 1] == 0) {
		quotient.len--;
	}

	return quotient;
}

/*
	name: division
	discrption: 输出有符号大整数a整除b的结果
	input: 有符号大整数a, b
	output: 整除结果a/b
*/
bigint division(bigint a, bigint b) {
	bigint result = { 0 }; // 初始化结果

	// 特殊情况：除数为 0
	if (b.len == 0 || (b.len == 1 && b.position[0] == 0)) {
		printf("Error: Division by zero.\n");
		return result;
	}

	// 计算符号：结果的符号由被除数和除数的符号决定
	int result_sign = a.sign ^ b.sign; // 异或运算，符号相同结果为 0，符号不同结果为 1

	// 取被除数和除数的绝对值
	a.sign = 0;
	b.sign = 0;

	// 调用无符号除法
	result = division_without_sign(a, b);

	// 设置结果的符号
	result.sign = result_sign;

	return result;
}

/*
	name: mod
	discrption: 输出有符号大整数a 模 b的结果
	input: 有符号大整数a, b
	output: a % b
*/
bigint mod_op(bigint a, bigint b) {
	bigint quotient, multi;
	bigint result;

	if (compare_abs(a, b) < 0) return a;
	quotient = division_without_sign(a, b); // q = floor(a / b)
	multi = multiplication(b, quotient); // m = b * q
	result = subtraction_without_sign(a, multi); // a - b*q

	return result;
}

/*
	name: u8tobigint
	discrption: 将2*16的uint8_t的数据转化为256比特的bigint型数据
	input: uint8_t ct[2][16]
	output: 256比特的bigint型数据
*/
bigint u8tobigint(uint8_t ct[2][16]) {
	bigint result = { 0 }; // 初始化 bigint 结构体
	result.sign = 0;     // 确保为正数
	result.len = 8;      // 每个 uint32_t 4 字节，256 比特对应 8 个 uint32_t

	// 遍历 256 比特数据并填充到 bigint 的 position 数组
	for (int i = 0; i < 8; ++i) {
		result.position[i] = 0; // 清空当前位置
		for (int j = 0; j < 4; ++j) {
			int byte_index = i * 4 + j;         // 计算二维数组中的字节位置
			int row = byte_index / 16;         // 行索引
			int col = byte_index % 16;         // 列索引
			result.position[i] |= (uint32_t)ct[row][col] << (8 * j); // 填充每 8 比特
		}
	}

	return result;
}

/*
	name: get_256bits_num
	discrption: 通过AES加密生成随机数，初始明文与密钥通过自带库生成
	input: uint8_t a 用来调控自带随机数库生成的不随机数
	output: 256比特的bigint数据
*/
bigint get_256bits_num(uint8_t a) {

	uint8_t pt[16], key[16], rk[11][16];
	uint8_t ct[2][16];
	for (int i = 0; i < 16; i++) {
		pt[i] = (uint8_t)rand() * 3 * a + 3*i + 3489; key[i] = (uint8_t)rand() * 257 * a + 19*i + 4671;
	}
	aes_key_schedule(key, rk);
	aes_encrypt_with_tables(pt, rk, ct[0]);

	for (int i = 0; i < 16; i++) {
		pt[i] = (uint8_t)rand() * 349 * a + 3 * i + 1753; key[i] = (uint8_t)rand() * 273 * a + 19 * i + 4272;
	}
	aes_key_schedule(key, rk);
	aes_encrypt_with_tables(pt, rk, ct[1]);

	return u8tobigint(ct);
}

const bigint one = { 0, 1, {1} };
const bigint zero = { 0, 1, {0} };
/*
	name: exEuclid
	discrption: 扩展欧几里得算法，返回a模b的逆元
	input: 大整数a, b
	output: a^(-1), s.t. a*a^(-1) mod b = 1
*/
bigint exEuclid(bigint a, bigint b) {
	bigint x[3] = { one, zero, a };
	bigint y[3] = { zero, one, b };
	bigint t[3] = { zero, zero, zero };
	bigint p = a;
	bigint q = b;
	int flag = 0;
	bigint quotient;

	// 确保 a >= b
	if (compare_with_sign(p, q) < 0) {
		bigint temp = x[2];
		x[2] = y[2];
		y[2] = temp;
		p = x[2];
		q = y[2];
		flag = 1;
	}

	while (1) {
		if (compare_abs(y[2], one) == 0) {
			if (flag != 1) {
				while (y[0].sign == 1) {
					y[0] = addition_with_sign(y[0], q);
				}
				return y[0];
			}
			else {
				while (y[1].sign == 1) {
					y[1] = addition_with_sign(y[1], p);
				}
				return y[1];
			}
		}

		else if (compare_abs(y[2], zero) == 0) {
			return zero;  // 无逆元
		}
		else {
			quotient = division_without_sign(x[2], y[2]); // 计算 x2 / y2
			for (int i = 0; i < 3; i++) {
				t[i] = subtraction_with_sign(x[i], multiplication(quotient, y[i]));  // t[i] = x[i] - Q*y[i]
			}

			for (int i = 0; i < 3; i++) {
				x[i] = y[i];
				y[i] = t[i];
			}

		}
	}
}

const bigint R_256 = { 0, 9, {0,0,0,0, 0,0,0,0, 1} };
const bigint R_512 = { 0, 17, {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 1} };
/*
	name: montgomery
	discrption: 将输入的数转化到 montgomery domain 上
	input: 需要转化的数据a, 模数mod_mont, 模数对基数R的逆mod_inv, 基数R为2^(R_k)次
	output: a * R_inv , 基数R对于模数mod_mont的逆R_inv
*/
bigint montgomery(bigint a, bigint mod_mont, bigint mod_inv, int R_k) {
	bigint m = multiplication(a, mod_inv);
	m = mod_2_k(m, R_k);

	bigint t = multiplication(m, mod_mont);
	t = subtraction_with_sign(a, t);
	t = division_2_k(t, R_k);

	if (t.sign == 1) return addition_with_sign(t, mod_mont);
	else return t;
}

/*
	name: montgomery_multi
	discrption: 将两数相乘的结果放到 montgomery domain 上
	input: a, b, 模数mod_mont, 模数对基数R的逆mod_inv, 基数R为2^(R_k)次
	output: 两数在montgomery domain 上相乘后的结果
*/
bigint montgomery_multi(bigint a, bigint b, bigint mod_mont, bigint mod_inv, int R_k) {
	bigint c = multiplication(a, b);
	return montgomery(c, mod_mont, mod_inv, R_k);
}

/*
	name: fast_mod_pow
	discrption: 使用蒙哥马利的快速模幂运算
	input: 底数a, 指数 pow, 模数 mod_fast, 模数的基数 R, 基数R为2^(R_k)次
	output: 快速模幂运算的结果
*/
bigint fast_mod_pow(bigint a, bigint pow, bigint mod_fast, bigint R, int R_k) {
	uint2_t pow_2 = bigint_to_binary(pow);
	bigint R_mod = mod_op(R, mod_fast);
	bigint mod_inv = exEuclid(mod_fast, R);
	
	bigint x = R_mod;
	bigint a_R = multiplication(a, R);
	a_R = mod_op(a_R, mod_fast);
	
	for (int times = pow_2.len - 1; times >= 0; times--) {
		x = montgomery_multi(x, x, mod_fast, mod_inv, R_k);
		if (pow_2.bin[times] == 1) {
			x = montgomery_multi(x, a_R, mod_fast, mod_inv, R_k);
		}
	}
	x = montgomery_multi(x, one, mod_fast, mod_inv, R_k);

	return x;
}

/*
	name: feramt_is_prime
	discrption: 费马检测 256 位的素数, 均以素数 17 为证据 a
	input: 需要检测的数 n
	output: 通过检测则返回 1 , 反之放回 0
*/
int feramt_is_prime(bigint n) {
	bigint a = { 0, 1, {17} };
	bigint n_sub1 = subtraction_without_sign(n, one);

	bigint chack = fast_mod_pow(a, n_sub1, n, R_256, 256);
	if (compare_abs(one, chack) == 0) return 1;
	else return 0;
}

/*
	name: get_prime
	discrption: 生成素数
	input: NULL 
	output: 一个素数
*/
bigint get_prime(uint8_t a) {
	bigint n = get_256bits_num(a);
	int flag = feramt_is_prime(n);

	while (!flag)
	{
		a++;
		n = get_256bits_num(a);
		flag = feramt_is_prime(n);
	}

	return n;
}

bigint RSA_encryption(bigint m, bigint e, bigint N) {
	bigint c = fast_mod_pow(m, e, N, R_512, 512);
	return c;
}

bigint RSA_decryption(bigint c, bigint d, bigint N) {
	bigint m = fast_mod_pow(c, d, N, R_512, 512);
	return m;
}

void RSA() {
	bigint p = get_prime(3329);
	bigint q = get_prime(1687);
	bigint N = multiplication(p, q);

	printf("p:");print_bigint(p);
	printf("q:");print_bigint(q);
	printf("N:");print_bigint(N);

	bigint p_sub1 = subtraction_with_sign(p, one);
	bigint q_sub1 = subtraction_with_sign(q, one);
	bigint phi = multiplication(p_sub1, q_sub1);
	printf("phi:");print_bigint(phi);

	bigint e = get_prime(237);
	bigint d = exEuclid(e, phi);
	bigint chack = multiplication(e, d);

	printf("e:");print_bigint(e);
	printf("d:");print_bigint(d);

	bigint m = get_256bits_num(23);
	printf("m:");print_bigint(m);

	bigint c = RSA_encryption(m, e, N);
	printf("c:"); print_bigint(c);

	bigint m_ = RSA_decryption(c, d, N);
	printf("m:");print_bigint(m_);

	if (compare_abs(m, m_) == 0) printf("RSA encrypts and decrypts right!\n");
	else printf("There has some wrong!\n");
}

int main() {
	srand((unsigned)time(NULL));
	double time;
	int times = 32;
	clock_t start, end, start1, end1;

	start1 = clock();
	for (int i = 0; i < times; i++) {
		start = clock();
		RSA();
		end = clock();
		time = end - start;
		printf("the RSA encryption and decryption run %.2f s\n", time/1000);
		printf("\n");
	}
	end1 = clock();

	time = end1 - start1;
	printf("the average time is %.2f s\n", (time / (1000 * times)));
	
	return 0;
}