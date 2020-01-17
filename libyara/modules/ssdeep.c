/*
Copyright (c) 2014. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

ssdeep https://ssdeep-project.github.io/ssdeep/usage.html 
copyright https://github.com/ssdeep-project/ssdeep/blob/master/COPYING  GNU General Public License v2.0
*/

#include <fuzzy.h>

#include <yara/mem.h>
#include <yara/modules.h>
#include <yara/strutils.h>

#define MODULE_NAME ssdeep
#define MIN_SSDEEP_DATA 4096

typedef struct _CACHE_KEY
{
	int64_t offset;
	int64_t length;
} CACHE_KEY;

static char* get_from_cache(
	YR_OBJECT* module_object,
	const char* ns,
	int64_t offset,
	int64_t length)
{
	CACHE_KEY key;
	YR_HASH_TABLE* hash_table = (YR_HASH_TABLE*)module_object->data;

	key.offset = offset;
	key.length = length;

	return (char*)yr_hash_table_lookup_raw_key(
		hash_table,
		&key,
		sizeof(key),
		ns);
}


static int add_to_cache(
	YR_OBJECT* module_object,
	const char* ns,
	int64_t offset,
	int64_t length,
	const char* digest)
{
	CACHE_KEY key;
	YR_HASH_TABLE* hash_table = (YR_HASH_TABLE*)module_object->data;

	char* copy = yr_strdup(digest);

	key.offset = offset;
	key.length = length;

	if (copy == NULL)
		return ERROR_INSUFFICIENT_MEMORY;

	return yr_hash_table_add_raw_key(
		hash_table,
		&key,
		sizeof(key),
		ns,
		(void*)copy);
}

/*.hash(size_start,size_end); */
define_function(data_hash)
{
	char digest_ascii[FUZZY_MAX_RESULT + 1] = {0,};
	char* cached_ascii_digest;

	bool past_first_block = false;

	YR_SCAN_CONTEXT* context = scan_context();
	YR_MEMORY_BLOCK* block = first_memory_block(context);
	YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

	int64_t arg_offset = integer_argument(1);   // offset where to start
	int64_t arg_length = integer_argument(2);   // length of bytes we want hash on

	int64_t offset = arg_offset;
	int64_t length = arg_length;

	struct fuzzy_state *ctx;
	int status = 0;

	if (offset < 0 || length < 0 || offset < block->base || length<MIN_SSDEEP_DATA)
		return_string(UNDEFINED);

	cached_ascii_digest = get_from_cache(
		module(), "ssdeep", arg_offset, arg_length);

	if (cached_ascii_digest != NULL)
		return_string(cached_ascii_digest);

	if (NULL == (ctx = fuzzy_new()))
		return_string(UNDEFINED);;

	foreach_memory_block(iterator, block)
	{
		// if desired block within current block

		if (offset >= block->base &&
			offset < block->base + block->size)
		{
			const uint8_t* block_data = block->fetch_data(block);

			if (block_data != NULL)
			{
				size_t data_offset = (size_t)(offset - block->base);
				size_t data_len = (size_t)yr_min(
					length, (size_t)(block->size - data_offset));

				offset += data_len;
				length -= data_len;

				if ((status = fuzzy_update(ctx, block_data + data_offset, data_len)) < 0)
					goto out;
			}

			past_first_block = true;
		}
		else if (past_first_block)
		{
			// If offset is not within current block and we already
			// past the first block then the we are trying to compute
			// the checksum over a range of non contiguous blocks. As
			// range contains gaps of undefined data the checksum is
			// undefined.

			return_string(UNDEFINED);
		}

		if (block->base + block->size > offset + length)
			break;
	}

	if (!past_first_block)
		return_string(UNDEFINED);

	if ((status=fuzzy_digest(ctx, digest_ascii, 0)) < 0)
		goto out;

	FAIL_ON_ERROR(
		add_to_cache(module(), "ssdeep", arg_offset, arg_length, digest_ascii));

	status = 0;
out:

	fuzzy_free(ctx);
	if (status != 0)
	{
		return_string(UNDEFINED);
	}
	return_string(digest_ascii);
}

/*.distance("external-digest");*/
define_function(compare)
{
	YR_OBJECT* module = module();
	SIZED_STRING* digest = get_string(module, "digest");
	char* s = string_argument(1);
	int dist = 0;

	if (digest == NULL || digest->c_string[0] == '\0')
	{
		return_integer(0);
	}

	dist = fuzzy_compare(s, digest->c_string);
	return_integer(dist);
}

/*.score();*/
define_function(score)
{
	YR_OBJECT* module = module();
	int counter = 0;
	uint64_t threshold = integer_argument(1);
	SIZED_STRING* digest = get_string(module, "digest");
	int rules = 0;
	int score = 0;

	if (is_undefined(module, "number_of_rules"))
	{
		return_integer(UNDEFINED);
	}
	rules = (int)get_integer(module, "number_of_rules");

	if (digest == NULL)
	{
		return_integer(UNDEFINED);
	}

	for (counter=0; counter<rules; counter++)
	{
		SIZED_STRING* rule = get_string(module, "rules[%i]", counter);
		if (rule == NULL || rule->length == 0)
		{
			return_integer(0);
		}
		score = fuzzy_compare(digest->c_string, rule->c_string);
		if (score >= threshold)
		{
			return_integer(score);
		}
	}

	return_integer(0);
}

define_function(max_score)
{
	YR_OBJECT* module = module();
	int counter = 0;
	SIZED_STRING* digest = get_string(module, "digest");
	int max = 0;
	int score = 0;
	int rules = 0;

	if (is_undefined(module, "number_of_rules"))
	{
		return_integer(UNDEFINED);
	}
	rules = (int)get_integer(module, "number_of_rules");

	if (digest == NULL)
	{
		return_integer(UNDEFINED);
	}

	for (counter=0; counter<rules; counter++)
	{
		SIZED_STRING* rule = get_string(module, "rules[%i]", counter);
		if (rule == NULL || rule->length == 0)
		{
			return_integer(0);
		}
		score = fuzzy_compare(digest->c_string, rule->c_string);
		if (score > max)
		{
			max = score;
		}
	}

	return_integer(max);
}

/*.distance("string-x-1", "string-x-2");*/
define_function(data_compare)
{
	char* s1 = string_argument(1);
	char* s2 = string_argument(2);
	int dist = fuzzy_compare(s1, s2);
	return_integer(dist);
}


begin_declarations;

declare_string_array("rules");
declare_integer("number_of_rules");

declare_string("digest");

declare_function("hash", "ii", "s", data_hash);
declare_function("compare", "ss", "i", data_compare);
declare_function("compare", "s", "i", compare);
declare_function("score", "i", "i", score);
declare_function("max", "", "i", max_score);

end_declarations;


int module_initialize(
	YR_MODULE* module)
{
	return ERROR_SUCCESS;
}

int module_finalize(
	YR_MODULE* module)
{
	return ERROR_SUCCESS;
}

int module_load(
	YR_SCAN_CONTEXT* context,
	YR_OBJECT* module_object,
	void* module_data,
	size_t module_data_size)
{
	YR_HASH_TABLE* hash_table;
	char digest_ascii[FUZZY_MAX_RESULT + 1] = { 0, };
	YR_MEMORY_BLOCK* block = first_memory_block(context);;
	YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;
	int64_t total_size = 0;
	int status = 0;

	struct fuzzy_state *ctx;
	if (NULL == (ctx = fuzzy_new()))
		return -1;

	FAIL_ON_ERROR(yr_hash_table_create(17, &hash_table));
	module_object->data = hash_table;

	if (module_data != NULL && module_data_size > 0)
	{
		if (strncasecmp((const char*)module_data, "no-default", 10) == 0)
		{
			return ERROR_SUCCESS;
		}
		else
		{
			const char* sep = "\n"; //可按多个字符来分割
			int counter = 0;
			char* p = NULL;
			char* dup = (char*)calloc(sizeof(char), module_data_size + 1);
			strcpy(dup, (const char*)module_data);
			
			p = strtok(dup, sep);
			while (p) 
			{
				set_string(p, module_object, "rules[%i]", counter++);
				p = strtok(NULL, sep);
			}
			free(dup);
			set_integer(counter, module_object, "number_of_rules");
		}
	}

	foreach_memory_block(iterator, block)
	{
		const uint8_t* block_data = block->fetch_data(block);

		if (block_data == NULL)
			continue;

		total_size += block->size;
		status = fuzzy_update(ctx, block_data, block->size);
		if (status < 0)
			goto out;
	}
	status = fuzzy_digest(ctx, digest_ascii, 0);
	if (status < 0)
	{
		goto out;
	}
	status = 0;

out:
	fuzzy_free(ctx);
	if (status == 0)
	{
		add_to_cache(module_object, "ssdeep", 0, total_size, digest_ascii);
		set_string(digest_ascii, module_object, "digest");
	}
	return ERROR_SUCCESS;
}

int module_unload(
	YR_OBJECT* module_object)
{
	YR_HASH_TABLE* hash_table = (YR_HASH_TABLE*)module_object->data;

	if (hash_table != NULL)
		yr_hash_table_destroy(
			hash_table,
			(YR_HASH_TABLE_FREE_VALUE_FUNC)yr_free);

	return ERROR_SUCCESS;
}
