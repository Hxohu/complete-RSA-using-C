#include <stdio.h>
#include <stdint.h>
#include <stdlib.h> 
#include <time.h>
#include "AES.h"

const uint64_t mod = 0x100000000;

//���������
typedef struct {
	int sign; //���ţ� 0���������� 1������
	int len; //�������ж���λ
	uint32_t position[64]; //����2^32���Ƶ�������RSAģ��Ϊ512������£�����������1024���أ�position[0]��ʾ���λ���������ݵľ���ֵ
}bigint;

typedef struct {
	int len;
	uint32_t bin[1024];
}uint2_t;

// ��ӡ������
void print_bigint(bigint num) {
	if (num.sign) printf("- 0x");
	else printf("  0x");
	for (int i = num.len - 1; i >= 0; --i) {
		printf("%08x ", num.position[i]);
	}
	printf("\n");
}

// ��ӡ������
void print_binary(uint2_t num) {
	// ��鳤���Ƿ���Ч
	if (num.len <= 0) {
		printf("0\n"); // �������Ϊ 0��ֱ�Ӵ�ӡ 0
		return;
	}

	// �������Ƶ�˳��Ӹ�λ����λ��ӡ
	for (int i = num.len - 1; i >= 0; i--) {
		printf("%d", num.bin[i]);
		// ÿ 8 λ���һ���ո񣬱����Ķ�
		if (i > 0 && i % 8 == 0) {
			printf(" ");
		}
	}

	printf("\n"); // ����
}

/*
	name: mod_2_k
	discrption: ����ģ2^k
	input: ������a��ģ2��k����
	output: a % (2^k)
*/
bigint mod_2_k(bigint a, int k) {
	bigint result = a;

	// ������Ҫ������λ��
	int full_words = k / 32;      // ������ 32 λ��
	int remaining_bits = k % 32; // ʣ���λ��

	// ���������Ŀ�
	for (int i = full_words + 1; i < a.len; ++i) {
		result.position[i] = 0; // ���㳬��λ���Ŀ�
	}

	// ��������λ��
	if (remaining_bits > 0 && full_words < a.len) {
		uint32_t mask = (1U << remaining_bits) - 1; // ���ɲ���λ������
		result.position[full_words] &= mask;       // Ӧ������
	}

	// ���½������
	result.len = full_words + (remaining_bits > 0 ? 1 : 0);
	return result;
}

/*
	name: addition_without_sign
	discrption: �����Ƿ��ŵ���ӣ����������ľ���ֵ��ӣ��õ����������봫���������ͬ
	input: ��������������ͬ�������
	output: �����������ֵ��ӵĽ��
*/
bigint addition_without_sign(bigint a, bigint b) {
	bigint result;
	result.sign = a.sign; // ���ű���һ��
	result.len = (a.len > b.len) ? a.len : b.len; // ����ĳ������ٵ��ڽϳ�������

	uint64_t carry = 0; // ��λ
	uint64_t sum;

	// ��λ���
	for (int i = 0; i < result.len; ++i) {
		sum = carry;
		if (i < a.len) sum += a.position[i];
		if (i < b.len) sum += b.position[i];

		result.position[i] = (uint32_t)(sum & 0xFFFFFFFF); // ��ǰλ��ֵ
		carry = sum >> 32; // �����µĽ�λ
	}

	// ������λ�н�λ
	if (carry > 0) {
		result.position[result.len] = (uint32_t)carry;
		result.len += 1;
	}

	// ȷ������ĸ�λ����
	for (int i = result.len; i < 32; ++i) {
		result.position[i] = 0;
	}

	return result;
}

/*
	name: compare_abs
	discrption: �Ƚ��޷��������������Ĵ�С
	input: ���������޷��ŵĴ�����a, b
	output: ��������Ĵ�С��ϵ����a > b ���� 1, ��a < b ���� -1, ��a = b ���� 0
*/
int compare_abs(bigint a, bigint b) {
	// �Ƚ�λ����λ��������ֽϴ�
	if (a.len > b.len) return 1;
	if (a.len < b.len) return -1;

	// λ����ͬ����λ�Ƚ�
	for (int i = a.len - 1; i >= 0; --i) {
		if (a.position[i] > b.position[i]) return 1;
		if (a.position[i] < b.position[i]) return -1;
	}

	// �������λ�����
	return 0;
}

/*
	name: subtraction_without_sign
	discrption: ��������������a,b�Ҷ�Ϊ����,����������Ľ��
	input: ������a, ������b, a,b��Ϊ����
	output: a - b
*/
bigint subtraction_without_sign(bigint a, bigint b) {
	bigint result = { 0 }; // ��ʼ�����
	int cmp = compare_abs(a, b);

	// ��� a < b������ a �� b�������Ϊ����
	if (cmp < 0) {
		bigint temp = a;
		a = b;
		b = temp;
		result.sign = 1; // ���Ϊ����
	}
	else {
		result.sign = 0; // ���Ϊ����
	}

	// ��������
	int borrow = 0;             // ��λ���
	result.len = a.len;         // ���������ϴ���һ��

	for (int i = 0; i < result.len; ++i) {
		// ��ȡ��ǰλ�ı����������
		uint64_t minuend = (uint64_t)a.position[i];
		uint64_t subtrahend = (i < b.len ? (uint64_t)b.position[i] : 0);

		// ��ȥ��ǰλ��ֵ�ͽ�λ
		uint64_t diff = minuend - subtrahend - borrow;

		if (diff > 0xFFFFFFFF) { // ����λ
			borrow = 1;
			result.position[i] = (uint32_t)(diff + (1ULL << 32)); // ������ֵ
		}
		else {
			borrow = 0;
			result.position[i] = (uint32_t)diff;
		}
	}

	// ȥ����λ��Ч�� 0
	while (result.len > 1 && result.position[result.len - 1] == 0) {
		result.len--;
	}

	return result;
}

/*
	name: compare_with_sing
	discrption: �Ƚ��з��������������Ĵ�С
	input: ���������з��ŵĴ�����a, b
	output: ��������Ĵ�С��ϵ����a > b ���� 1, ��a < b ���� -1, ��a = b ���� 0
*/
int compare_with_sign(bigint a, bigint b) {
	// ������Ų�ͬ������С������
	if (a.sign != b.sign) return a.sign ? -1 : 1;  // ����С������

	// ������ͬ���ȽϾ���ֵ
	return compare_abs(a, b);  // ʹ�� compare_abs �ȽϾ���ֵ
}

/*
	name: addition_with_sign
	discrption: �����з���������ӣ��õ����������������Ĳ�ͬ����ͬ
	input: ���������з��ŵ������
	output: ���������ӵĽ��
*/
bigint addition_with_sign(bigint a, bigint b) {
	bigint result;

	// ��� 1: ������ͬ��ֱ��ִ���޷��żӷ�
	if (a.sign == b.sign) {
		result = addition_without_sign(a, b);
		result.sign = a.sign;  // ����ķ�����������ͬ
		return result;
	}

	// ��� 2: ���Ų�ͬ���������ֵ�ϴ������ȥ��С����
	int cmp = compare_abs(a, b);
	if (cmp > 0) { // |a| > |b|
		result = subtraction_without_sign(a, b);
		result.sign = a.sign;  // ��������� a �ķ�����ͬ
	}
	else if (cmp < 0) { // |a| < |b|
		result = subtraction_without_sign(b, a);
		result.sign = b.sign;  // ��������� b �ķ�����ͬ
	}
	else { // |a| == |b|�����Ϊ��
		result.sign = 0;
		result.len = 1;
		result.position[0] = 0;
	}

	return result;
}

/*
	name: subtraction_with_sign
	discrption: ��������������a,b,����������Ľ��
	input: ������a, ������b, a,b���Ų���
	output: a - b
*/
bigint subtraction_with_sign(bigint a, bigint b) {
	// ���� b ���෴��
	bigint neg_b = b;
	neg_b.sign = 1 - b.sign;  // ��ת����

	// ִ�� a + (-b)
	return addition_with_sign(a, neg_b);
}

/*
	name: multiplication_without_sign
	discrption: �������޷��ŵĴ��������
	input: �޷��ŵĴ�����a,b
	output: ����������˵Ľ��
*/
bigint multiplication_without_sign(bigint a, bigint b) {
	bigint result = { 0, 0, {0} };
	uint64_t carry;

	// ��λ��ˣ�ģ����ʽ�˷�
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

	// �������ĳ���
	result.len = a.len + b.len;
	while (result.len > 1 && result.position[result.len - 1] == 0) {
		result.len--;
	}

	return result;
}

/*
	name: multiplication
	discrption: �������з��ŵĴ��������
	input: �з��ŵĴ�����a,b
	output: ����������˵Ľ��
*/
bigint multiplication(bigint a, bigint b) {
	// ���ż��㣺�������ȡ���� a.sign �� b.sign �����
	int result_sign = a.sign ^ b.sign;

	// �������ֵ���
	bigint abs_result = multiplication_without_sign(a, b);

	// ���÷���
	abs_result.sign = result_sign;

	return abs_result;
}


/*
	name: bigint_to_binary
	discrption: �������2^32���Ƶ���ת��Ϊ2������
	input: 2^32������
	output: 2������
*/
uint2_t bigint_to_binary(bigint a) {
	uint2_t result = { 0 }; // ��ʼ�����
	int bit_index = 0;    // ��ǰ�����ƴ洢��λ������

	// ���� bigint ��ÿ��λ��
	for (int i = 0; i < a.len; i++) {
		uint32_t value = a.position[i];
		int valid_bits = 32; // Ĭ��ÿ��λ���� 32 λ

		// ��������λ������ʵ�ʵ���Чλ��
		if (i == a.len - 1) {
			while (valid_bits > 0 && (value & (1U << (valid_bits - 1))) == 0) {
				valid_bits--; // �Ӹ�λ���λѰ�ҵ�һ�� 1
			}
		}

		// ��ȡ��Чλ�Ķ�����
		for (int j = 0; j < valid_bits; j++) {
			result.bin[bit_index++] = value & 1; // ��ȡ���λ
			value >>= 1;                        // ����һλ
		}
	}

	// ���¶����Ƴ���
	result.len = bit_index;

	return result;
}

/*
	name: subtract_binary
	discrption: ����������������a,b,����������Ľ��
	input: ��������a, ��������b, 
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

	// ������Ч����
	while (result.len > 0 && result.bin[result.len - 1] == 0) {
		result.len--;
	}

	return result;
}

/*
	name: left_shift
	discrption: ���������������� shift λ
	input: ������ a, ����λ�� shift
	output: a ���� shiftλ�Ľ��
*/
bigint left_shift(bigint a, int shift) {
	bigint result = { 0 }; // ��ʼ�����
	result.sign = a.sign; // ���ű���һ��

	// �������ƶ��ٸ� "32 λ��" �� "����λ��"
	int block_shift = shift / 32;       // ���ƵĿ���
	int bit_shift = shift % 32;        // ���ڵ�λ��
	int carry_bits = 32 - bit_shift;   // ��Ҫ�����ĸ�λ����

	// ���ý������
	result.len = a.len + block_shift + (bit_shift > 0 ? 1 : 0);

	// ����Ƿ񳬳����洢��Χ
	if (result.len > 33) {
		printf("Error: Shift exceeds maximum length.\n");
		result.len = 0;
		return result;
	}

	// ���ƿ�Ϳ���λ
	for (int i = a.len - 1; i >= 0; i--) {
		uint64_t shifted_value = (uint64_t)a.position[i] << bit_shift;

		// �����λ����һ��
		if (i + block_shift + 1 < 33 && bit_shift > 0) {
			result.position[i + block_shift + 1] |= (uint32_t)(shifted_value >> 32);
		}

		// ��ǰ��ĵ�λ
		if (i + block_shift < 33) {
			result.position[i + block_shift] |= (uint32_t)(shifted_value & 0xFFFFFFFF);
		}
	}

	// ���������Χ��λ
	while (result.len > 1 && result.position[result.len - 1] == 0) {
		result.len--;
	}

	return result;
}


/*
	name: division_2_k
	discrption: ���ݳ�2^k
	input: ������a����2��k����
	output: a / (2^k)
*/
bigint division_2_k(bigint a, int k) {
	bigint result = { 0 }; // ��ʼ�����
	result.sign = a.sign; // ��������

	// ��� k Ϊ 0��ֱ�ӷ���ԭ��
	if (k == 0) {
		result = a;
		return result;
	}

	// ������Ҫ���Ƶ����� position ��ʣ���λ��
	int shift_positions = k / 32;  // ���� position ���ƶ���
	int bit_shift = k % 32;        // ���� position �ڵ�λ����

	// ������Ƴ���������λ�������Ϊ 0
	if (shift_positions >= a.len) {
		result.len = 0;
		return result;
	}

	// ���½���ĳ���
	result.len = a.len - shift_positions;

	// �������ʣ�ಿ��
	uint32_t carry = 0; // ���ڿ� position �Ľ�λ
	for (int i = a.len - 1; i >= shift_positions; i--) {
		uint64_t current = ((uint64_t)carry << 32) | a.position[i]; // ��ǰ position ���ݼ��Ͻ�λ
		result.position[i - shift_positions] = (current >> bit_shift) & 0xFFFFFFFF; // ���Ʋ��ضϸ�λ
		carry = (uint32_t)(current & ((1U << bit_shift) - 1)); // ����δ�Ƴ��Ĳ�����Ϊ��һ�� position �Ľ�λ
	}

	// �Ƴ�����п��ܶ���ĸ�λ 0
	while (result.len > 0 && result.position[result.len - 1] == 0) {
		result.len--;
	}

	return result;
}

/*
	name: division_without_sign
	discrption: ʹ��left_shift�����Դ��������ж���, ��2���г���
	input: ������a, ����b
	output: a / b 
*/
bigint division_without_sign(bigint a, bigint b) {
	bigint quotient = { 0 }; // ��ʼ����
	bigint remainder = a;  // ��ʼ������Ϊ������

	// �������������Ϊ0
	if (b.len == 0 || (b.len == 1 && b.position[0] == 0)) {
		printf("Error: Division by zero.\n");
		return quotient;
	}

	// ���������a < b��ֱ�ӷ�����Ϊ0
	if (compare_abs(a, b) < 0) {
		return quotient;
	}

	// ������λֵ��ʹ b ���뵽 a �����λ
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

	// ��������
	while (shift >= 0) {
		if (compare_abs(remainder, shifted_b) >= 0) {
			// ����������ڵ�����λ��� b������м���
			remainder = subtraction_without_sign(remainder, shifted_b);
			/*printf("remainder");
			print_bigint(remainder);*/

			// �����̣����ö�Ӧ������λ
			int block_idx = shift / 32;   // �̵Ĵ洢λ�ÿ�
			int bit_idx = shift % 32;    // �̵Ĵ洢λ��λ
			quotient.position[block_idx] |= (1U << bit_idx); // ���̵Ķ�Ӧλ������ 1
			//printf("%x\n", quotient.position[block_idx]);
		}

		// �����Ƿ�����˼�������������Ҫ���� b
		shifted_b = division_2_k(shifted_b, 1);
		shift--;
	}

	// �����̵���Ч����
	quotient.len = (a.len > b.len) ? a.len : b.len;
	while (quotient.len > 1 && quotient.position[quotient.len - 1] == 0) {
		quotient.len--;
	}

	return quotient;
}

/*
	name: division
	discrption: ����з��Ŵ�����a����b�Ľ��
	input: �з��Ŵ�����a, b
	output: �������a/b
*/
bigint division(bigint a, bigint b) {
	bigint result = { 0 }; // ��ʼ�����

	// �������������Ϊ 0
	if (b.len == 0 || (b.len == 1 && b.position[0] == 0)) {
		printf("Error: Division by zero.\n");
		return result;
	}

	// ������ţ�����ķ����ɱ������ͳ����ķ��ž���
	int result_sign = a.sign ^ b.sign; // ������㣬������ͬ���Ϊ 0�����Ų�ͬ���Ϊ 1

	// ȡ�������ͳ����ľ���ֵ
	a.sign = 0;
	b.sign = 0;

	// �����޷��ų���
	result = division_without_sign(a, b);

	// ���ý���ķ���
	result.sign = result_sign;

	return result;
}

/*
	name: mod
	discrption: ����з��Ŵ�����a ģ b�Ľ��
	input: �з��Ŵ�����a, b
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
	discrption: ��2*16��uint8_t������ת��Ϊ256���ص�bigint������
	input: uint8_t ct[2][16]
	output: 256���ص�bigint������
*/
bigint u8tobigint(uint8_t ct[2][16]) {
	bigint result = { 0 }; // ��ʼ�� bigint �ṹ��
	result.sign = 0;     // ȷ��Ϊ����
	result.len = 8;      // ÿ�� uint32_t 4 �ֽڣ�256 ���ض�Ӧ 8 �� uint32_t

	// ���� 256 �������ݲ���䵽 bigint �� position ����
	for (int i = 0; i < 8; ++i) {
		result.position[i] = 0; // ��յ�ǰλ��
		for (int j = 0; j < 4; ++j) {
			int byte_index = i * 4 + j;         // �����ά�����е��ֽ�λ��
			int row = byte_index / 16;         // ������
			int col = byte_index % 16;         // ������
			result.position[i] |= (uint32_t)ct[row][col] << (8 * j); // ���ÿ 8 ����
		}
	}

	return result;
}

/*
	name: get_256bits_num
	discrption: ͨ��AES�����������������ʼ��������Կͨ���Դ�������
	input: uint8_t a ���������Դ�����������ɵĲ������
	output: 256���ص�bigint����
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
	discrption: ��չŷ������㷨������aģb����Ԫ
	input: ������a, b
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

	// ȷ�� a >= b
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
			return zero;  // ����Ԫ
		}
		else {
			quotient = division_without_sign(x[2], y[2]); // ���� x2 / y2
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
	discrption: ���������ת���� montgomery domain ��
	input: ��Ҫת��������a, ģ��mod_mont, ģ���Ի���R����mod_inv, ����RΪ2^(R_k)��
	output: a * R_inv , ����R����ģ��mod_mont����R_inv
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
	discrption: ��������˵Ľ���ŵ� montgomery domain ��
	input: a, b, ģ��mod_mont, ģ���Ի���R����mod_inv, ����RΪ2^(R_k)��
	output: ������montgomery domain ����˺�Ľ��
*/
bigint montgomery_multi(bigint a, bigint b, bigint mod_mont, bigint mod_inv, int R_k) {
	bigint c = multiplication(a, b);
	return montgomery(c, mod_mont, mod_inv, R_k);
}

/*
	name: fast_mod_pow
	discrption: ʹ���ɸ������Ŀ���ģ������
	input: ����a, ָ�� pow, ģ�� mod_fast, ģ���Ļ��� R, ����RΪ2^(R_k)��
	output: ����ģ������Ľ��
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
	discrption: ������ 256 λ������, �������� 17 Ϊ֤�� a
	input: ��Ҫ������ n
	output: ͨ������򷵻� 1 , ��֮�Ż� 0
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
	discrption: ��������
	input: NULL 
	output: һ������
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