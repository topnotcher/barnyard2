/*
** Copyright (C) 2000,2001,2002 Carnegie Mellon University
**
**     Author: Jed Pickel <jed@pickel.net>
** Maintainer: Roman Danyliw <rdd@cert.org>, <roman@danyliw.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

**
**    Special thanks to: Rusell Fuleton <russell.fulton@gmail.com> for helping us stress test
**                       this in production for us.
**

*/



/* NOTE: -elz this file is a mess and need some cleanup */
/* $Id$ */

#ifndef __SPO_DATABASE_H__
#define __SPO_DATABASE_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>
#include <inttypes.h>
#include <stdio.h>

#include "barnyard2.h"
#include "debug.h"
#include "decode.h"
#include "map.h"
#include "plugbase.h"
#include "parser.h"
#include "rules.h"
#include "unified2.h"
#include "util.h"
#include "khash.h"

#include "output-plugins/spo_database_cache.h"


#define DB_DEBUG 0x80000000


#ifdef ENABLE_POSTGRESQL
# include <libpq-fe.h>
#endif

#ifdef ENABLE_MYSQL
# if defined(_WIN32) || defined(_WIN64)
#  include <windows.h>
# endif
# include <mysql.h>
# include <mysqld_error.h>
# include <errmsg.h>
#endif

#include "map.h"
#include "plugbase.h"

#ifndef MAX_SQL_QUERY_OPS
#define MAX_SQL_QUERY_OPS 50 /* In case we get a IP packet with 40 options */
#endif  /* MAX_SQL_QUERY_OPS */


/******** Data Types  **************************************************/
/* enumerate the supported databases */
enum db_types_en
{
    DB_ENUM_MIN_VAL = 0,
    DB_UNDEFINED  = 0,
    DB_MYSQL      = 1,
    DB_POSTGRESQL = 2,
    DB_ENUM_MAX_VAL = 3 /* This value has to be updated if a new dbms is inserted in the enum 
			         This is used for different function pointers used by the module depending on operation mode
			      */
};
typedef enum db_types_en dbtype_t;

/* ------------------------------------------ 
   DATABASE CACHE Structure and objects
   ------------------------------------------ */

/* 
   All those object could be referenced by one prototype and all
   call to allocation and list manipulation could be generalized, but
   for clarity and the purpose of this code (existance timeline), this was not done.
   
   Here is a breif cache layout.
   dbSystemObj
   						\
    dbReferenceObj <------------------ \
    \				       |
      dbSignatureCacheObj              /
       \---[dbReferenceObj * array] __/
       
    dbSignatureReferenceObj
									
*/

#ifndef MAX_SIGLOOKUP
#define MAX_SIGLOOKUP 255
#endif /* MAX_SIGLOOKUP */

/* ------------------------------------------
 * REFERENCE OBJ 
 ------------------------------------------ */
typedef struct _dbReferenceObj
{
    u_int32_t ref_id;
    u_int32_t system_id; /* used by fetch for match else refer to parent.*/
    char ref_tag[REF_TAG_LEN]; 
    struct _cacheSystemObj *parent;
    
} dbReferenceObj;

typedef struct _cacheReferenceObj
{
    dbReferenceObj obj;
    u_int32_t flag; /* Where its at */
    struct _cacheReferenceObj *next;
    
} cacheReferenceObj;
/* ------------------------------------------
 * REFERENCE OBJ 
 ------------------------------------------ */

/* ------------------------------------------
 * SYSTEM OBJ 
 ------------------------------------------ */
typedef struct _dbSystemObj
{
    u_int32_t db_ref_system_id;
    char name[SYSTEM_NAME_LEN];
    char url[SYSTEM_URL_LEN];
    cacheReferenceObj *refList;

} dbSystemObj;

typedef struct _cacheSystemObj
{
    dbSystemObj obj;
    u_int32_t flag; /* Where its at */
    struct _cacheSystemObj *next;
    
} cacheSystemObj;
/* ------------------------------------------
 * SYSTEM OBJ 
 ------------------------------------------ */

/* ------------------------------------------
 * SIGNATUREREFERENCE OBJ
 ------------------------------------------ */
typedef struct _dbSignatureReferenceObj
{
    u_int32_t db_ref_id;
    u_int32_t db_sig_id;
    u_int32_t ref_seq;
    
} dbSignatureReferenceObj;


typedef struct _cacheSignatureReferenceObj
{
    dbSignatureReferenceObj obj;
    u_int32_t flag; /* Where its at */
    struct _cacheSignatureReferenceObj *next;
    
} cacheSignatureReferenceObj;
/* ------------------------------------------
 * SIGNATUREREFERENCE OBJ
 ------------------------------------------ */

/* -----------------------------------------
 * CLASSIFICATION OBJ
 ------------------------------------------ */
typedef struct _dbClassificationObj
{
    u_int32_t sig_class_id;
    u_int32_t db_sig_class_id;
    char sig_class_name[CLASS_NAME_LEN];
    
} dbClassificationObj;

typedef struct _cacheClassificationObj
{
    dbClassificationObj obj;
    u_int32_t flag; /* Where its at */

    struct _cacheClassificationObj *next;
    
} cacheClassificationObj;
/* ------------------------------------------
 * CLASSIFICATION OBJ
 ------------------------------------------ */

/* ------------------------------------------
 * SIGNATURE OBJ
 ------------------------------------------ */
typedef struct _dbSignatureObj
{
    u_int32_t db_id;
    sig_sid_t sid;
    sig_gid_t gid;
    sig_rev_t rev;
    sig_class_id_t class_id;
    sig_priority_id_t priority_id;
    char message[SIG_MSG_LEN];
    
    /* Eliminate alot of useless lookup */
    cacheReferenceObj *ref[MAX_REF_OBJ]; /* Used for backward lookup */
    u_int32_t ref_count;                 /* Used for count on ref's  */
    /* Eliminate alot of useless lookup */    

} dbSignatureObj;

//kh_dbSigCacheNode_t... khash_t(dbSigCacheNode)
//Store the dbSignatureObjs by SID 
KHASH_MAP_INIT_INT(dbSigCacheNode, dbSignatureObj)

//store kh_dbSigCacheNode_t by GID
KHASH_MAP_INIT_INT(dbSigCache, khash_t(dbSigCacheNode)*)
/* ------------------------------------------
 * SIGNATURE OBJ
 ------------------------------------------ */

/* ------------------------------------------
 * Used for lookup in case multiple signature 
 * with same sid:gid couple exist but have different
 * rev,class and priority 
 ------------------------------------------ */

/* ------------------------------------------
   Main cache entry point (used by DatabaseData->mc)
 ------------------------------------------ */
typedef struct _masterCache
{
    cacheClassificationObj *cacheClassificationHead;
    khash_t(dbSigCache) * cacheSignatureHead;
    cacheSystemObj *cacheSystemHead;
    cacheSignatureReferenceObj *cacheSigReferenceHead;
} MasterCache;
/* ------------------------------------------
   Main cache entry point (used by DatabaseData->mc)
 ------------------------------------------ */

/* ------------------------------------------ 
   DATABASE CACHE Structure and objects
   ------------------------------------------ */

/* Replace dynamic query node */
typedef struct _SQLQueryList
{
    u_int32_t query_total;
    u_int32_t query_count;
    char **query_array;
    
} SQLQueryList;
/* Replace dynamic query node */


/*  Databse Reliability  */ 
typedef struct _dbReliabilityHandle
{

    u_int32_t dbConnectionCount;    /* Count of effective reconnection */
    u_int32_t dbConnectionLimit;    /* Limit or reconnection try */
    u_int32_t dbLimitReachFailsafe; /* Limit of time we wrap the reconnection try */
    u_int32_t dbConnectionStat;   /* Database Connection status (barnyard2) */
    u_int32_t dbReconnectedInTransaction;
    
    struct timespec dbReconnectSleepTime;    /* Sleep time (milisec) before attempting a reconnect */
    
    u_int8_t checkTransaction; /* If set , we are in transaction */
    u_int8_t transactionCallFail; /* if(checkTransaction) && error set ! */
    u_int8_t transactionErrorCount; /* Number of transaction fail for a single transaction (Reset by sucessfull commit)*/
    u_int8_t transactionErrorThreshold; /* Consider the transaction threshold to be the same as reconnection maxiumum */
     
    u_int8_t disablesigref; /* Allow user to prevent generation and creation of signature reference table */
    
    struct _DatabaseData *dbdata; /* Pointer to parent structure used for call clarity */
    
#ifdef ENABLE_MYSQL
    /* Herited from shared data globals */
    char     *ssl_key;
    char     *ssl_cert;
    char     *ssl_ca;
    char     *ssl_ca_path;
    char     *ssl_cipher;
    /* Herited from shared data globals */

    unsigned long pThreadID; /* Used to store thread information and know if we "reconnected automaticaly" */
    my_bool mysql_reconnect; /* We will handle it via the api. */
#endif /* ENABLE_MYSQL */

#ifdef ENABLE_POSTGRESQL
    /* Herited from shared data globals */
    char     *ssl_mode;
    /* Herited from shared data globals */
#endif
    /* Set by dbms specific setup function */
    u_int32_t (*dbConnectionStatus)(struct _dbReliabilityHandle *);
} dbReliabilityHandle;
/*  Databse Reliability  */

typedef struct _DatabaseData
{
    u_short  dbtype_id;
    char  *facility;
    char  *password;
    char  *user;
    char  *port;
    char  *sensor_name;
    int    encoding;
    int    detail;
    int    ignore_bpf;
    int    tz;
    int    DBschema_version;

    char     *dbname;
    char     *host;
    int       sid;
    int       cid;
    int       reference;
    int       use_ssl;
    
    /* Some static allocated buffers, they might need some cleanup before release */
    char timestampHolder[SMALLBUFFER]; /* For timestamp conversion .... */
    char PacketDataNotEscaped[MAX_QUERY_LENGTH];
    char PacketData[MAX_QUERY_LENGTH];
    /* Some static allocated buffers, they might need some cleanup before release */
    
    /* Used for generic queries if you need consequtives queries uses SQLQueryList*/
    char *SQL_SELECT; 
    char *SQL_INSERT; 
    
    u_int32_t SQL_SELECT_SIZE;
    u_int32_t SQL_INSERT_SIZE;
    /* Used for generic queries if you need consequtives queries uses SQLQueryList*/


    SQLQueryList SQL; 
    MasterCache mc;
    
#ifdef ENABLE_POSTGRESQL
    PGconn * p_connection;
    PGresult * p_result;

#ifdef HAVE_PQPING
    char p_pingString[1024];
#endif
#endif
#ifdef ENABLE_MYSQL
    MYSQL * m_sock;
    MYSQL_RES * m_result;
    MYSQL_ROW m_row;
#endif
    char *args;
    
/*  Databse Reliability  */ 
/*
  Defining an array of dbReliabilityHandle will enlarge the structure memory footprint 
  but it will enable support for compilation with multiple dbms. Be sure to update DB_ENUM_MAX_VAL
  if you add a specific database support like some NoSQL *winks*.
*/
    struct _dbReliabilityHandle dbRH[DB_ENUM_MAX_VAL]; 
/*  Databse Reliability  */     
    
} DatabaseData;


/******** Constants  ***************************************************/
#define KEYWORD_POSTGRESQL   "postgresql"
#define KEYWORD_MYSQL        "mysql"

#define KEYWORD_HOST         "host"
#define KEYWORD_PORT         "port"
#define KEYWORD_USER         "user"
#define KEYWORD_PASSWORD     "password"
#define KEYWORD_DBNAME       "dbname"
#define KEYWORD_SENSORNAME   "sensor_name"
#define KEYWORD_ENCODING     "encoding"
    #define KEYWORD_ENCODING_HEX      "hex"
    #define KEYWORD_ENCODING_BASE64   "base64"
    #define KEYWORD_ENCODING_ASCII    "ascii"
#define KEYWORD_DETAIL       "detail"
    #define KEYWORD_DETAIL_FULL  "full"
    #define KEYWORD_DETAIL_FAST  "fast"
#define KEYWORD_IGNOREBPF    "ignore_bpf"
#define KEYWORD_IGNOREBPF_NO   "no"
#define KEYWORD_IGNOREBPF_ZERO "0"
#define KEYWORD_IGNOREBPF_YES  "yes"
#define KEYWORD_IGNOREBPF_ONE  "1"

#define KEYWORD_CONNECTION_LIMIT "connection_limit"
#define KEYWORD_RECONNECT_SLEEP_TIME "reconnect_sleep_time"
#define KEYWORD_DISABLE_SIGREFTABLE "disable_signature_reference_table"

#define KEYWORD_MYSQL_RECONNECT "mysql_reconnect"

#ifdef ENABLE_MYSQL
#   define KEYWORD_SSL_KEY     "ssl_key"
#   define KEYWORD_SSL_CERT    "ssl_cert"
#   define KEYWORD_SSL_CA      "ssl_ca"
#   define KEYWORD_SSL_CA_PATH "ssl_ca_path"
#   define KEYWORD_SSL_CIPHER  "ssl_cipher"
#endif

#ifdef ENABLE_POSTGRESQL
#   define KEYWORD_SSL_MODE  "ssl_mode"
#   define KEYWORD_SSL_MODE_DISABLE "disable"
#   define KEYWORD_SSL_MODE_ALLOW   "allow"
#   define KEYWORD_SSL_MODE_PREFER  "prefer"
#   define KEYWORD_SSL_MODE_REQUIRE "require"
#endif

#define LATEST_DB_SCHEMA_VERSION 108




void DatabaseSetup(void);


/******** Prototypes  **************************************************/
/* NOTE: -elz prototypes will need some cleanup before release */
DatabaseData *InitDatabaseData(char *args);

int db_fmt_escape(DatabaseData * db, char * buf, size_t buf_size, char * fmt, ...);

void DatabaseInit(char *);
void DatabaseInitFinalize(int unused, void *arg);
void ParseDatabaseArgs(DatabaseData *data);
void Database(Packet *, void *, uint32_t, void *);
void SpoDatabaseCleanExitFunction(int, void *);
void SpoDatabaseRestartFunction(int, void *);
void InitDatabase(void);
void Connect(DatabaseData *);
void DatabasePrintUsage(void);

int Insert(char *, DatabaseData *,u_int32_t);
int Select(char *, DatabaseData *,u_int32_t *);
int UpdateLastCid(DatabaseData *, int, int);
int GetLastCid(DatabaseData *, int,u_int32_t *);
int CheckDBVersion(DatabaseData *);

u_int32_t BeginTransaction(DatabaseData * data);
u_int32_t CommitTransaction(DatabaseData * data);
u_int32_t RollbackTransaction(DatabaseData * data);


u_int32_t checkDatabaseType(DatabaseData *data);
u_int32_t checkTransactionState(dbReliabilityHandle *pdbRH);
u_int32_t checkTransactionCall(dbReliabilityHandle *pdbRH);
u_int32_t  dbReconnectSetCounters(dbReliabilityHandle *pdbRH);
u_int32_t MYSQL_ManualConnect(DatabaseData *dbdata);

void resetTransactionState(dbReliabilityHandle *pdbRH);
void setTransactionState(dbReliabilityHandle *pdbRH);
void setTransactionCallFail(dbReliabilityHandle *pdbRH);

u_int32_t getReconnectState(dbReliabilityHandle *pdbRH);
void setReconnectState(dbReliabilityHandle *pdbRH,u_int32_t reconnection_state);

void DatabaseCleanSelect(DatabaseData *data);
void DatabaseCleanInsert(DatabaseData *data);

u_int32_t ConvertDefaultCache(Barnyard2Config *bc,DatabaseData *data);
u_int32_t CacheSynchronize(DatabaseData *data);
u_int32_t cacheEventClassificationLookup(cacheClassificationObj *iHead,u_int32_t iClass_id);
u_int32_t SignatureCacheInsertObj(dbSignatureObj *iSigObj,MasterCache *iMasterCache);
u_int32_t SignatureLookupDbCache(MasterCache * mc, dbSignatureObj * lookup);
u_int32_t SignaturePopulateDatabase(DatabaseData  *data,dbSignatureObj *sig,int inTransac);
u_int32_t SignatureLookupDatabase(DatabaseData *data,dbSignatureObj *sObj);
u_int32_t SignatureLookup(DatabaseData * data, dbSignatureObj * lookup);
void MasterCacheFlush(DatabaseData *data,u_int32_t flushFlag);

u_int32_t dbConnectionStatusPOSTGRESQL(dbReliabilityHandle *pdbRH);
u_int32_t dbConnectionStatusMYSQL(dbReliabilityHandle *pdbRH);

#endif  /* __SPO_DATABASE_H__ */
