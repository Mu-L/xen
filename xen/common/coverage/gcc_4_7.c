/*
 *  This code provides functions to handle gcc's profiling data format
 *  introduced with gcc 4.7.
 *
 *  This file is based heavily on gcc_3_4.c file.
 *
 *  For a better understanding, refer to gcc source:
 *  gcc/gcov-io.h
 *  libgcc/libgcov.c
 *
 *  Uses gcc-internal data definitions.
 *
 *  Imported from Linux and modified for Xen by
 *    Wei Liu <wei.liu2@citrix.com>
 */

#include <xen/string.h>

#include "gcov.h"

#if GCC_VERSION < 40700
#error "Wrong version of GCC used to compile gcov"
#elif GCC_VERSION < 40900
#define GCOV_COUNTERS 8
#elif GCC_VERSION < 50000
#define GCOV_COUNTERS 9
#elif GCC_VERSION < 70000
#define GCOV_COUNTERS 10
#elif GCC_VERSION < 100000
#define GCOV_COUNTERS 9
#elif GCC_VERSION < 140000
#define GCOV_COUNTERS 8
#else
#define GCOV_COUNTERS 9
#endif

#define GCOV_TAG_FUNCTION_LENGTH        3

#if GCC_VERSION < 120000
#define GCOV_UNIT_SIZE 1
#else
/* Since GCC 12, sizes are in BYTES and not in WORDS (4B). */
#define GCOV_UNIT_SIZE 4
#endif

static struct gcov_info *gcov_info_head;

/**
 * struct gcov_ctr_info - information about counters for a single function
 * @num: number of counter values for this type
 * @values: array of counter values for this type
 *
 * This data is generated by gcc during compilation and doesn't change
 * at run-time with the exception of the values array.
 */
struct gcov_ctr_info {
    unsigned int num;
    gcov_type *values;
};

/**
 * struct gcov_fn_info - profiling meta data per function
 * @key: comdat key
 * @ident: unique ident of function
 * @lineno_checksum: function lineo_checksum
 * @cfg_checksum: function cfg checksum
 * @ctrs: instrumented counters
 *
 * This data is generated by gcc during compilation and doesn't change
 * at run-time.
 *
 * Information about a single function.  This uses the trailing array
 * idiom. The number of counters is determined from the merge pointer
 * array in gcov_info.  The key is used to detect which of a set of
 * comdat functions was selected -- it points to the gcov_info object
 * of the object file containing the selected comdat function.
 */
struct gcov_fn_info {
    const struct gcov_info *key;
    unsigned int ident;
    unsigned int lineno_checksum;
    unsigned int cfg_checksum;
    struct gcov_ctr_info ctrs[0];
};

/**
 * struct gcov_info - profiling data per object file
 * @version: gcov version magic indicating the gcc version used for compilation
 * @next: list head for a singly-linked list
 * @stamp: uniquifying time stamp
 * @filename: name of the associated gcov data file
 * @merge: merge functions (null for unused counter type)
 * @n_functions: number of instrumented functions
 * @functions: pointer to pointers to function information
 *
 * This data is generated by gcc during compilation and doesn't change
 * at run-time with the exception of the next pointer.
 */
struct gcov_info {
    unsigned int version;
    struct gcov_info *next;
    unsigned int stamp;
#if GCC_VERSION >= 120000
    /*  GCC 12 introduced a checksum field */
    unsigned int checksum;
#endif
    const char *filename;
    void (*merge[GCOV_COUNTERS])(gcov_type *, unsigned int);
    unsigned int n_functions;
    struct gcov_fn_info **functions;
};

static int counter_active(const struct gcov_info *info, unsigned int type)
{
    return info->merge[type] ? 1 : 0;
}

void gcov_info_link(struct gcov_info *info)
{
    info->next = gcov_info_head;
    gcov_info_head = info;
}

struct gcov_info *gcov_info_next(const struct gcov_info *info)
{
    if ( !info )
        return gcov_info_head;
    return info->next;
}

void gcov_info_reset(struct gcov_info *info)
{
    struct gcov_ctr_info *ci_ptr;
    unsigned int fi_idx;
    unsigned int ct_idx;

    for ( fi_idx = 0; fi_idx < info->n_functions; fi_idx++ )
    {
        ci_ptr = info->functions[fi_idx]->ctrs;

        for ( ct_idx = 0; ct_idx < GCOV_COUNTERS; ct_idx++ )
        {
            if ( !counter_active(info, ct_idx) )
                continue;

            memset(ci_ptr->values, 0, sizeof(gcov_type) * ci_ptr->num);
            ci_ptr++;
        }
    }
}

const char *gcov_info_filename(const struct gcov_info *info)
{
    return info->filename;
}


/**
 * gcov_info_to_gcda - convert profiling data set to gcda file format
 * @buffer: the buffer to store file data or %NULL if no data should be stored
 * @info: profiling data set to be converted
 *
 * Returns the number of bytes that were/would have been stored into the buffer.
 */
size_t gcov_info_to_gcda(char *buffer, const struct gcov_info *info)
{
    struct gcov_fn_info *fi_ptr;
    struct gcov_ctr_info *ci_ptr;
    unsigned int fi_idx;
    unsigned int ct_idx;
    unsigned int cv_idx;
    size_t pos = 0;

    /* File header. */
    pos += gcov_store_uint32(buffer, pos, GCOV_DATA_MAGIC);
    pos += gcov_store_uint32(buffer, pos, info->version);
    pos += gcov_store_uint32(buffer, pos, info->stamp);

#if GCC_VERSION >= 120000
    /* Use zero as checksum of the compilation unit. */
    pos += gcov_store_uint32(buffer, pos, 0);
#endif

    for ( fi_idx = 0; fi_idx < info->n_functions; fi_idx++ )
    {
        fi_ptr = info->functions[fi_idx];

        /* Function record. */
        pos += gcov_store_uint32(buffer, pos, GCOV_TAG_FUNCTION);
        pos += gcov_store_uint32(buffer, pos, GCOV_TAG_FUNCTION_LENGTH * GCOV_UNIT_SIZE);
        pos += gcov_store_uint32(buffer, pos, fi_ptr->ident);
        pos += gcov_store_uint32(buffer, pos, fi_ptr->lineno_checksum);
        pos += gcov_store_uint32(buffer, pos, fi_ptr->cfg_checksum);

        ci_ptr = fi_ptr->ctrs;

        for ( ct_idx = 0; ct_idx < GCOV_COUNTERS; ct_idx++ )
        {
            if (! counter_active(info, ct_idx) )
                continue;

            /* Counter record. */
            pos += gcov_store_uint32(buffer, pos,
                                     GCOV_TAG_FOR_COUNTER(ct_idx));
            pos += gcov_store_uint32(buffer, pos, ci_ptr->num * 2 * GCOV_UNIT_SIZE);

            for ( cv_idx = 0; cv_idx < ci_ptr->num; cv_idx++ )
                pos += gcov_store_uint64(buffer, pos, ci_ptr->values[cv_idx]);

            ci_ptr++;
        }
    }

    return pos;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
