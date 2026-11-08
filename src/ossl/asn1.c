/*
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>
 */

#include <limits.h>
#include <string.h>
#include <time.h>

#include <openssl/bn.h>

#include <anyca/osal/memory.h>
#include <anyca/osal/time.h>

#include <anyca/ossl/asn1.h>

bool ossl_asn1_read_tlv(const unsigned char **cursor, long available,
			ossl_asn1_tlv_t *tlv)
{
	const unsigned char *content;
	long length;
	int tag;
	int xclass;
	int flags;

	if (cursor == nullptr || *cursor == nullptr || tlv == nullptr
	    || available <= 0)
		return false;

	content = *cursor;
	flags = ASN1_get_object(&content, &length, &tag, &xclass, available);
	if ((flags & 0x80) != 0 || (flags & 0x01) != 0 || length < 0)
		return false;

	tlv->tag = tag;
	tlv->xclass = xclass;
	tlv->constructed = (flags & 0x20) != 0;
	tlv->content = content;
	tlv->content_length = length;
	*cursor = content;
	return true;
}

bool ossl_asn1_expect_tlv(const unsigned char **cursor, long available,
			  int tag, int xclass, ossl_asn1_tlv_t *tlv)
{
	return ossl_asn1_read_tlv(cursor, available, tlv)
		&& tlv->tag == tag && tlv->xclass == xclass;
}

bool ossl_asn1_integer_to_bytes(const ASN1_INTEGER *integer,
				unsigned char **data, size_t *length,
				bool *negative)
{
	BIGNUM *number;
	unsigned char *buffer;
	int size;
	bool ok = false;

	if (negative != nullptr)
		*negative = false;
	if (data == nullptr || length == nullptr)
		return false;
	*data = nullptr;
	*length = 0;

	if (integer == nullptr)
		return false;

	number = ASN1_INTEGER_to_BN(integer, nullptr);
	if (number == nullptr)
		return false;

	if (BN_is_negative(number)) {
		if (negative != nullptr)
			*negative = true;
		goto done;
	}

	/* BN_bn2bin() returns the minimal big-endian magnitude, so sign
	 * padding and leading zeroes are already gone. */
	size = BN_num_bytes(number);
	if (size <= 0) {
		/* Canonical zero: one zero byte, not an empty string. */
		buffer = osal_malloc(1);
		if (buffer == nullptr)
			goto done;
		buffer[0] = 0x00;
		*data = buffer;
		*length = 1;
	} else {
		buffer = osal_malloc((size_t) size);
		if (buffer == nullptr)
			goto done;
		if (BN_bn2bin(number, buffer) != size) {
			osal_free(buffer);
			goto done;
		}
		*data = buffer;
		*length = (size_t) size;
	}

	ok = true;

done:
	BN_free(number);
	return ok;
}

ASN1_INTEGER *ossl_asn1_integer_from_bytes(const unsigned char *data,
					   size_t length)
{
	BIGNUM *number;
	ASN1_INTEGER *integer;

	if (data == nullptr || length == 0 || length > (size_t) INT_MAX)
		return nullptr;

	number = BN_bin2bn(data, (int) length, nullptr);
	if (number == nullptr)
		return nullptr;
	if (BN_is_zero(number)) {
		BN_free(number);
		return nullptr;
	}

	integer = BN_to_ASN1_INTEGER(number, nullptr);
	BN_free(number);
	return integer;
}

ASN1_INTEGER *ossl_asn1_integer_from_uint64(uint64_t value)
{
	ASN1_INTEGER *integer = ASN1_INTEGER_new();

	if (integer == nullptr
	    || ASN1_INTEGER_set_uint64(integer, value) != 1) {
		ASN1_INTEGER_free(integer);
		return nullptr;
	}
	return integer;
}

char *ossl_asn1_integer_to_hex(const ASN1_INTEGER *integer)
{
	BIGNUM *number;
	char *text;
	char *copy;
	size_t length;

	if (integer == nullptr)
		return nullptr;

	number = ASN1_INTEGER_to_BN(integer, nullptr);
	if (number == nullptr)
		return nullptr;

	text = BN_bn2hex(number);
	BN_free(number);
	if (text == nullptr)
		return nullptr;

	length = strlen(text) + 1;
	copy = osal_malloc(length);
	if (copy != nullptr)
		memcpy(copy, text, length);

	OPENSSL_free(text);
	return copy;
}

/* ASN.1 UTCTime/GeneralizedTime can only represent years 0 through 9999. */
#define OSSL_ASN1_MAX_YEAR 9999
#define OSSL_ASN1_MIN_YEAR 0

static bool _asn1_year_is_valid(const struct tm *broken_down)
{
	int year = broken_down->tm_year + 1900;

	return year >= OSSL_ASN1_MIN_YEAR && year <= OSSL_ASN1_MAX_YEAR;
}

/* True for 1969-12-31T23:59:59Z, whose Unix time equals the timegm() error
 * sentinel. */
static bool _asn1_tm_is_unix_minus_one(const struct tm *broken_down)
{
	return broken_down->tm_year == 69 && broken_down->tm_mon == 11
		&& broken_down->tm_mday == 31 && broken_down->tm_hour == 23
		&& broken_down->tm_min == 59 && broken_down->tm_sec == 59;
}

static bool _asn1_epoch_to_tm(int64_t epoch, struct tm *broken_down)
{
	time_t timestamp = (time_t) epoch;

	if ((int64_t) timestamp != epoch)
		return false;
	if (timestamp == (time_t) -1) {
		/*
		 * timegm()/_mkgmtime() report errors with -1, which is also the
		 * valid Unix time of 1969-12-31T23:59:59Z.  Build that value
		 * explicitly instead of rejecting it.
		 */
		memset(broken_down, 0, sizeof *broken_down);
		broken_down->tm_year = 69;
		broken_down->tm_mon = 11;
		broken_down->tm_mday = 31;
		broken_down->tm_hour = 23;
		broken_down->tm_min = 59;
		broken_down->tm_sec = 59;
		return true;
	}

#if defined(_WIN32)
	if (gmtime_s(broken_down, &timestamp) != 0)
		return false;
#else
	if (gmtime_r(&timestamp, broken_down) == nullptr)
		return false;
#endif
	return true;
}

bool ossl_asn1_time_to_epoch(const ASN1_TIME *time, int64_t *epoch)
{
	struct tm broken_down;
	time_t timestamp;

	if (time == nullptr || epoch == nullptr)
		return false;
	if (ASN1_TIME_to_tm(time, &broken_down) != 1)
		return false;
	if (!_asn1_year_is_valid(&broken_down))
		return false;

	timestamp = osal_timegm(&broken_down);
	/*
	 * osal_timegm() also returns -1 on failure; accept it only for the one
	 * instant it legitimately denotes.
	 */
	if (timestamp == (time_t) -1
	    && !_asn1_tm_is_unix_minus_one(&broken_down))
		return false;

	*epoch = (int64_t) timestamp;
	return true;
}

ASN1_TIME *ossl_asn1_time_from_epoch(int64_t epoch)
{
	struct tm broken_down;
	time_t timestamp = (time_t) epoch;

	if (!_asn1_epoch_to_tm(epoch, &broken_down)
	    || !_asn1_year_is_valid(&broken_down)
	    || (int64_t) timestamp != epoch)
		return nullptr;
	return ASN1_TIME_set(nullptr, timestamp);
}

ASN1_TIME *ossl_asn1_time_now(void)
{
	time_t now = time(nullptr);

	if (now == (time_t) -1)
		return nullptr;
	return ASN1_TIME_set(nullptr, now);
}

ASN1_GENERALIZEDTIME *ossl_asn1_generalized_time_from_epoch(int64_t epoch)
{
	struct tm broken_down;
	time_t timestamp = (time_t) epoch;

	if (!_asn1_epoch_to_tm(epoch, &broken_down)
	    || !_asn1_year_is_valid(&broken_down)
	    || (int64_t) timestamp != epoch)
		return nullptr;
	return ASN1_GENERALIZEDTIME_set(nullptr, timestamp);
}

ASN1_BIT_STRING *ossl_asn1_bit_string_from_bytes(const unsigned char *data,
						 size_t length)
{
	ASN1_BIT_STRING *string;

	if (data == nullptr || length == 0 || length > (size_t) INT_MAX)
		return nullptr;

	string = ASN1_BIT_STRING_new();
	if (string == nullptr
	    || ASN1_BIT_STRING_set(string, (unsigned char *) data,
				   (int) length) != 1) {
		ASN1_BIT_STRING_free(string);
		return nullptr;
	}
	string->flags = ASN1_STRING_FLAG_BITS_LEFT;
	return string;
}
