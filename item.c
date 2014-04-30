#include "memcachefile.h"
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>

#define MAX_ITEM_FREELIST_LENGTH 4000
#define INIT_ITEM_FREELIST_LENGTH 500

static size_t item_make_header(const uint8_t nkey, const int flags, const int nbytes, char *suffix, uint8_t *nsuffix);

static item **freeitem;
static int freeitemtotal;
static int freeitemcurr;

void item_init(void) {
    freeitemtotal = INIT_ITEM_FREELIST_LENGTH;
    freeitemcurr  = 0;

    freeitem = (item **)malloc( sizeof(item *) * freeitemtotal );
    if (freeitem == NULL) {
        perror("malloc()");
    }
    return;
}

/*
 * Returns a item buffer from the freelist, if any. Sholud call
 * item_from_freelist for thread safty.
 * */
item *do_item_from_freelist(void) {
    item *s;

    if (freeitemcurr > 0) {
        s = freeitem[--freeitemcurr];
    } else {
        /* If malloc fails, let the logic fall through without spamming
         * STDERR on the server. */
        s = (item *)malloc( settings.item_buf_size );
        if (s != NULL){
            memset(s, 0, settings.item_buf_size);
        }
    }

    return s;
}

/*
 * Adds a item to the freelist. Should call 
 * item_add_to_freelist for thread safty.
 */
int do_item_add_to_freelist(item *it) {
    if (freeitemcurr < freeitemtotal) {
        freeitem[freeitemcurr++] = it;
        return 0;
    } else {
        if (freeitemtotal >= MAX_ITEM_FREELIST_LENGTH){
            return 1;
        }
        /* try to enlarge free item buffer array */
        item **new_freeitem = (item **)realloc(freeitem, sizeof(item *) * freeitemtotal * 2);
        if (new_freeitem) {
            freeitemtotal *= 2;
            freeitem = new_freeitem;
            freeitem[freeitemcurr++] = it;
            return 0;
        }
    }
    return 1;
}

/**
 * Generates the variable-sized part of the header for an object.
 *
 * key     - The key
 * nkey    - The length of the key
 * flags   - key flags
 * nbytes  - Number of bytes to hold value and addition CRLF terminator
 * suffix  - Buffer for the "VALUE" line suffix (flags, size).
 * nsuffix - The length of the suffix is stored here.
 *
 * Returns the total size of the header.
 */
static size_t item_make_header(const uint8_t nkey, const int flags, const int nbytes,
                     char *suffix, uint8_t *nsuffix) {
    /* suffix is defined at 40 chars elsewhere.. */
    *nsuffix = (uint8_t) snprintf(suffix, 40, " %d %d\r\n", flags, nbytes - 2);
    return sizeof(item) + nkey + *nsuffix + nbytes;
}

/*
 * alloc a item buffer, and init it.
 */
item *item_alloc1(char *key, const size_t nkey, const int flags, const int nbytes) {
    uint8_t nsuffix;
    item *it;
    char suffix[40];
    size_t ntotal = item_make_header(nkey + 1, flags, nbytes, suffix, &nsuffix);

    if (ntotal > settings.item_buf_size){
        it = (item *)malloc(ntotal);
        if (it == NULL){
            return NULL;
        }
        memset(it, 0, ntotal);
        if (settings.verbose > 1) {
            fprintf(stderr, "alloc a item buffer from malloc.\n");
        }
    }else{
        it = item_from_freelist();
        if (it == NULL){
            return NULL;
        }
        if (settings.verbose > 1) {
            fprintf(stderr, "alloc a item buffer from freelist.\n");
        }
    }

    it->nkey = nkey;
    it->nbytes = nbytes;
    strcpy(ITEM_key(it), key);
    memcpy(ITEM_suffix(it), suffix, (size_t)nsuffix);
    it->nsuffix = nsuffix;
    return it;
}

/*
 * alloc a item buffer only.
 */
item *item_alloc2(size_t ntotal) {
    item *it;
    if (ntotal > settings.item_buf_size){
        it = (item *)malloc(ntotal);
        if (it == NULL){
            return NULL;
        }
        memset(it, 0, ntotal);
        if (settings.verbose > 1) {
            fprintf(stderr, "alloc a item buffer from malloc.\n");
        }
    }else{
        it = item_from_freelist();
        if (it == NULL){
            return NULL;
        }
        if (settings.verbose > 1) {
            fprintf(stderr, "alloc a item buffer from freelist.\n");
        }
    }

    return it;
}

/*
 * free a item buffer. here 'it' must be a full item.
 */

int item_free(item *it) {
    size_t ntotal = 0;
    if (NULL == it)
        return 0;

    /* ntotal may be wrong, if 'it' is not a full item. */
    ntotal = ITEM_ntotal(it);
    if (ntotal > settings.item_buf_size){
        if (settings.verbose > 1) {
            fprintf(stderr, "ntotal: %zd, use free() directly.\n", ntotal);
        }
        free(it);   
    }else{
        if (0 != item_add_to_freelist(it)) {
            if (settings.verbose > 1) {
                fprintf(stderr, "ntotal: %zd, add a item buffer to freelist fail, use free() directly.\n", ntotal);
            }
            free(it);   
        }else{
            if (settings.verbose > 1) {
                fprintf(stderr, "ntotal: %zd, add a item buffer to freelist.\n", ntotal);
            }
        }
    }
    return 0;
}

/* if return item is not NULL, free by caller */
item *item_get(char *key, size_t nkey) {
    FILE *fp;
    size_t len;
    struct stat st;

    if(!(fp = fopen(key, "r"))) {
        //fprintf(stderr, "%s: %s\n", strerror(errno), key);
        return NULL;
    }

    if (stat(key, &st) <0) {
        //fprintf(stderr, "%s: %s\n", strerror(errno), key);
        return NULL;
    }

    item *it = item_alloc1(key, nkey, 0, st.st_size+2);

    if (!it)
        return NULL;

    if (fread(ITEM_data(it), st.st_size, 1, fp) != 1) {
        if (ferror(fp)) {
            //fprintf(stderr, "%s: %s\n", strerror(errno), key);
            return NULL;
        }
    }

    fclose(fp);

    *((char *)ITEM_data(it) + st.st_size) = '\r';
    *((char *)ITEM_data(it) + st.st_size + 1) = '\n';

    return it;
}

#if 0
item *item_get(char *key, size_t nkey){
    item *it = NULL;
    DBT dbkey, dbdata;
    bool stop;
    int ret;
    
    /* first, alloc a fixed size */
    it = item_alloc2(settings.item_buf_size);
    if (it == 0) {
        return NULL;
    }

    BDB_CLEANUP_DBT();
    dbkey.data = key;
    dbkey.size = nkey;
    dbdata.ulen = settings.item_buf_size;
    dbdata.data = it;
    dbdata.flags = DB_DBT_USERMEM;

    stop = false;
    /* try to get a item from bdb */
    while (!stop) {
        switch (ret = dbp->get(dbp, NULL, &dbkey, &dbdata, 0)) {
        case DB_BUFFER_SMALL:    /* user mem small */
            /* free the original smaller buffer */
            item_free(it);
            /* alloc the correct size */
            it = item_alloc2(dbdata.size);
            if (it == NULL) {
                return NULL;
            }
            dbdata.ulen = dbdata.size;
            dbdata.data = it;
            break;
        case 0:                  /* Success. */
            stop = true;
            break;
        case DB_NOTFOUND:
            stop = true;
            item_free(it);
            it = NULL;
            break;
        default:
            /* TODO: may cause bug here, if return DB_BUFFER_SMALL then retun non-zero again
             * here 'it' may not a full one. a item buffer larger than item_buf_size may be added to freelist */
            stop = true;
            item_free(it);
            it = NULL;
            if (settings.verbose > 1) {
                fprintf(stderr, "dbp->get: %s\n", db_strerror(ret));
            }
        }
    }
    return it;
}
#endif

/* 0 for Success
   -1 for SERVER_ERROR
*/

#define savestring(x) strcpy(malloc((1 + strlen(x))), (x))

static int create_file(char *path, void *content, size_t len)
{
    int original_mask, parent_mode, nmode;
    FILE *fp;
    struct stat sb;
    char *p, *npath;

    original_mask = umask(0);
    umask(original_mask);

    nmode = (S_IRWXU | S_IRWXG | S_IRWXO) & ~original_mask;
    parent_mode = (S_IWRITE | S_IEXEC) | nmode;

    npath = savestring(path);

    if (stat(path, &sb) == 0) {
        if (S_ISDIR(sb.st_mode) || S_ISREG(sb.st_mode))
            goto write_file;
        fprintf(stderr, "file `%s' exists but not a directory or a regular file.\n", path);
        return 1;
    }

    p = npath;
    while (*p == '/')
        p++;

    while ((p = strchr(p, '/'))) {
        *p = '\0';
        if (stat(npath, &sb) != 0) {
            if (mkdir(npath, parent_mode)) {
                fprintf(stderr, "cannot create directory `%s': %s\n", npath, strerror(errno));
                goto failure;
            }
        } else if (S_ISDIR(sb.st_mode) == 0) {
            fprintf(stderr, "file `%s' exists but is not a directory\n", npath);
            goto failure;
        }

        *p++ = '/';
        while (*p == '/')
            p++;
    }

write_file:
    if (!(fp = fopen(npath, "w"))) {
        fprintf(stderr, "file `%s' open failed: %s\n", npath, strerror(errno));
        goto failure;
    }

    if (fwrite(content, len, 1, fp) != 1) {
        fprintf(stderr, "file `%s' write failed: %s\n", npath, strerror(errno));
        goto failure;
    }

    fclose(fp);

    umask(original_mask);
    free(npath);
    return 0;

failure:
    umask(original_mask);
    free(npath);
    return -1;
}

int item_put(char *key, size_t nkey, item *it)
{
    int ret;

    ret = create_file(key, ITEM_data(it), it->nbytes-2);
    if (ret) {
        fprintf(stderr, "file `%s' failed to create: %s\n", key, strerror(errno));
        return -1;
    }
    return 0;
}

/*
int item_put(char *key, size_t nkey, item *it){
    int ret;
    DBT dbkey, dbdata;

    BDB_CLEANUP_DBT();
    dbkey.data = key;
    dbkey.size = nkey;
    dbdata.data = it;
    dbdata.size = ITEM_ntotal(it);
    ret = dbp->put(dbp, NULL, &dbkey, &dbdata, 0);
    if (ret == 0) {
        return 0;
    } else {
        if (settings.verbose > 1) {
            fprintf(stderr, "dbp->put: %s\n", db_strerror(ret));
        }
        return -1;
    }
}
*/

/* 0 for Success
   1 for NOT_FOUND
   -1 for SERVER_ERROR
*/
int item_delete(char *key, size_t nkey)
{
    int ret;
    ret = remove(key);
    if (!ret) {
        return 0;
    } else {
        //fprintf(stderr, "file `%s' failed to delete: %s\n", key, strerror(errno));
        if (errno == ENOENT)
            return 1;
        else
            return -1;
    }
}
