/*
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
*/

/*
 *    Theses caches are built by combining existing caches from the snort map files and config files,
 *    The goal is to reduce the number of database interaction to a minimum so the output plugins 
 *    is more performant especially under heavy load of events.
 *
 *   
 *    Note that the default schema compatibility is kept intact
 *    Maintainers : The Barnyard2 Team <firnsy@gmail.com> <beenph@gmail.com> - 2011-2012
 *
 *    Special thanks to: Rusell Fuleton <russell.fulton@gmail.com> for helping us stress test
 *                       this in production for us.
 *
 */

#include "output-plugins/spo_database.h"
#include "output-plugins/spo_database_cache.h"

/* LOOKUP FUNCTIONS */
u_int32_t cacheClassificationLookup(dbClassificationObj *iLookup,cacheClassificationObj *iHead);
u_int32_t dbClassificationLookup(dbClassificationObj *iLookup,cacheClassificationObj *iHead);
/* LOOKUP FUNCTIONS */


/* CLASSIFICATION FUNCTIONS */
u_int32_t ClassificationPullDataStore(DatabaseData *data, dbClassificationObj **iArrayPtr,u_int32_t *array_length);
u_int32_t ClassificationCacheUpdateDBid(dbClassificationObj *iDBList,u_int32_t array_length,cacheClassificationObj **cacheHead);
u_int32_t ClassificationPopulateDatabase(DatabaseData  *data,cacheClassificationObj *cacheHead);
u_int32_t ClassificationCacheSynchronize(DatabaseData *data,cacheClassificationObj **cacheHead);
/* CLASSIFICATION FUNCTIONS */

/* SIGNATURE FUNCTIONS */
static u_int32_t SignatureLookupCache(dbSignatureObj * lookup);
static u_int32_t dbSignatureObjEquals(dbSignatureObj const * const sig1,dbSignatureObj const * const sig2);
static u_int32_t SignatureCacheLazyInit(MasterCache * mc, khash_t(dbSigCacheNode) ** cache, sig_gid_t gid);

/* SIGNATURE FUNCTIONS */


/* SIGNATURE REFERENCE FUNCTIONS */
static u_int32_t SignatureInsertReferences(DatabaseData * data, dbSignatureObj * sig);
static u_int32_t SignatureInsertReference(DatabaseData * data, u_int32_t db_sig_id, int seq, ReferenceNode * ref);
static u_int32_t ReferenceSystemLookupDbCache(MasterCache *mc, dbSystemObj * lookup);
static u_int32_t ReferenceSystemCacheInsertObj(dbSystemObj * sys, MasterCache * mc );
static u_int32_t DbReferenceSystemLookup(DatabaseData * data, dbSystemObj * lookup);
static u_int32_t ReferenceSystemLookupDatabase(DatabaseData * data, dbSystemObj * lookup);
static u_int32_t ReferenceSystemPopulateDatabase(DatabaseData * data, dbSystemObj * sys);
static u_int32_t ReferenceLookup(DatabaseData * data, dbReferenceObj * ref);
static u_int32_t ReferencePopulateDatabase(DatabaseData * data, dbReferenceObj * ref);
static u_int32_t ReferenceLookupDatabase(DatabaseData * data, dbReferenceObj * lookup);
/* SIGNATURE REFERENCE FUNCTIONS */


/* Init FUNCTIONS */
u_int32_t ConvertClassificationCache(ClassType **iHead, MasterCache *iMasterCache,DatabaseData *data);
/* Init FUNCTIONS */

/* Return largest string lenght */
static inline u_int32_t glsl(char *a,char *b) {
	u_int32_t alen = 0;
	u_int32_t blen = 0;

	alen = strlen(a);
	blen = strlen(b);

	return (alen >= blen) ? alen : blen;
}

#if DEBUG
u_int32_t file_reference_object_count = 0;
u_int32_t file_system_object_count = 0;
u_int32_t file_signature_object_count = 0;
u_int32_t file_classification_object_count = 0;
u_int32_t file_sigref_object_count = 0;

u_int32_t db_reference_object_count = 0;
u_int32_t db_system_object_count = 0;
u_int32_t db_signature_object_count = 0;
u_int32_t db_classification_object_count = 0;
u_int32_t db_sigref_object_count = 0;

u_int32_t inserted_reference_object_count = 0;
u_int32_t inserted_system_object_count = 0;
u_int32_t inserted_signature_object_count = 0;
u_int32_t inserted_classification_object_count = 0;
u_int32_t inserted_sigref_object_count = 0;
#endif


/**
 * @TODO
 */
static u_int32_t dbSignatureObjEquals(dbSignatureObj const * const sig1,dbSignatureObj const * const sig2) {
	if (sig1->sid != sig2->sid)
		return 0;
	else if (sig1->gid != sig2->gid)
		return 0;
	else if (sig1->rev != sig2->rev)
		return 0;
	else if (sig1->priority_id != sig2->priority_id)
		return 0;
	else if (sig1->class_id != sig2->class_id)
		return 0;

	return 1;
}

/**
 * Lookup a signature in the DB cache.
 *
 * @param iMasterCache the master database cache
 * @param lookup the signature to lookup 
 *
 * @return 0 if the signature is found; 1 for not found/error
 *
 * Side effects: lookup->db_id is set to the id of the sig in the DB.
 */
u_int32_t SignatureLookupDbCache(MasterCache * mc, dbSignatureObj * lookup) { 
	if (mc == NULL || lookup == NULL)
		return 1;

	khash_t(dbSigCacheNode) * cache = NULL;

	if (SignatureCacheLazyInit(mc, &cache, lookup->gid) || cache == NULL)
		return 1;

	khint_t k = kh_get(dbSigCacheNode, cache, lookup->sid);

	if (k == kh_end(cache)) {
		return 1;
	} else {
		if (dbSignatureObjEquals(&kh_value(cache,k), lookup)) {
			lookup->db_id = kh_value(cache, k).db_id;
			return 0;
		} else {
			return 1;
		}
	}
}

u_int32_t cacheEventClassificationLookup(cacheClassificationObj *iHead,u_int32_t iClass_id)
{
    
    if(iHead == NULL)
    {
	return 0;
    }
    
    while(iHead != NULL)
    {
	if(iHead->obj.sig_class_id == iClass_id)
	{
	    return iHead->obj.db_sig_class_id;
	}
	
	iHead = iHead->next;
    }
    
    return 0;
}

/** 
 * Lookup for dbClassificationObj in cacheClassificationObj 
 * 
 * @param iLookup 
 * @param iHead 
 * 
 * @return 
 * 0 NOT FOUND
 * 1 FOUND
 */
u_int32_t cacheClassificationLookup(dbClassificationObj *iLookup,cacheClassificationObj *iHead)
{
    if( (iLookup == NULL))
    {
	/* XXX */
        FatalError("database [%s()], Called with dbClassiciationObj[0x%x] cacheClassificationObj [0x%x] \n",
                   __FUNCTION__,
                   iLookup,
                   iHead);
    }
	
    if(iHead == NULL) 
    {
	return 0;
    }
    
    while(iHead != NULL)
    {
	if( (memcmp(iLookup,&iHead->obj,sizeof(dbClassificationObj)) == 0))
	{
	    /* Found */
	    return 1;
	}
	
	iHead = iHead->next;
    }
    
    return 0;
}

/** 
 * Lookup for dbClassificationObj in cacheClassificationObj 
 * @note Used in context db->internaCache lookup (if found remove CACHE_INTERNAL_ONLY and set CACHE_BOTH flag)
 * 
 * @param iLookup 
 * @param iHead 
 * 
 * @return 
 * 0 NOT FOUND
 * 1 FOUND
 */
u_int32_t dbClassificationLookup(dbClassificationObj *iLookup,cacheClassificationObj *iHead)
{
    if( (iLookup == NULL))
    {
        /* XXX */
        FatalError("database [%s()], Called with dbReferenceObj[0x%x] cacheClassificationObj [0x%x] \n",
                   __FUNCTION__,
                   iLookup,
                   iHead);
    }
    
    if(iHead == NULL)
    {
	return 0;
    }
    
    while(iHead != NULL)
    {
	if( (strncasecmp(iLookup->sig_class_name,iHead->obj.sig_class_name,
			 glsl(iLookup->sig_class_name,iHead->obj.sig_class_name)) == 0))
	{
            /* Found */
	    if(  iHead->flag & CACHE_INTERNAL_ONLY)
            {
                iHead->flag ^= (CACHE_INTERNAL_ONLY | CACHE_BOTH);
            }
            else
            {
                iHead->flag ^= CACHE_BOTH;
            }
	    iHead->obj.db_sig_class_id = iLookup->db_sig_class_id;
            return 1;
        }
	
        iHead = iHead->next;
    }
    
    return 0;
}

static u_int32_t SignatureCacheLazyInit(MasterCache * mc, khash_t(dbSigCacheNode) ** cache, sig_gid_t gid) {

	if (mc == NULL)
		return 1;

	khint_t k;
	int ret;

	if (mc->cacheSignatureHead == NULL)
		mc->cacheSignatureHead = kh_init(dbSigCache);

	//see if the dbSigCacheNode exists for this gid.
	k = kh_get(dbSigCache,mc->cacheSignatureHead, gid);
	if (k == (kh_end(mc->cacheSignatureHead))) {
		k = kh_put(dbSigCache, mc->cacheSignatureHead, gid, &ret);

		if (ret == -1) {
			return 1;

		//@TODO should this handle ret == 2? 
		//ret == 1 is expected? 
		//0 should never happen due to previous check
		//2 should never happen either
		} else {
			khash_t(dbSigCacheNode) * node = kh_init(dbSigCacheNode);
			kh_value(mc->cacheSignatureHead, k) = node;
			*cache = node;
		}
	} else {
		*cache = kh_value(mc->cacheSignatureHead,k);
	}

	return 0;
}

u_int32_t SignatureCacheInsertObj(dbSignatureObj *iSigObj,MasterCache * mc) {
	dbSignatureObj * cacheSigObj = NULL;
	khash_t(dbSigCacheNode) * cache = NULL;

	if (mc == NULL || iSigObj == NULL)
		return 1;

	if (SignatureCacheLazyInit(mc, &cache, iSigObj->gid) || cache == NULL)
		return 1;	

	khint_t k;
	int ret;
	k = kh_get(dbSigCacheNode, cache, iSigObj->sid);

	//this sid is in not present in the cache
	if (k == kh_end(cache)) {
		k = kh_put(dbSigCacheNode, cache, iSigObj->sid, &ret);

		if (ret == -1) {
			return 1;
		}
	} 

	//either it was already present, or we added the key; 
	//either way we just overwrite what is there.
	cacheSigObj = &kh_value(cache, k);

	memcpy(cacheSigObj,iSigObj,sizeof(dbSignatureObj));

	return 0;
}

/** 
 * This function will convert the classification cache. 
 * 
 * @param iHead 
 * @param iMasterCache 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t ConvertClassificationCache(ClassType **iHead, MasterCache *iMasterCache,DatabaseData *data)
{
    ClassType *cNode = NULL;
    cacheClassificationObj *TobjNode = NULL;
    cacheClassificationObj LobjNode;
    
    if( (iHead == NULL) ||
	(iMasterCache == NULL) ||
	(iMasterCache->cacheClassificationHead != NULL) ||
	(data == NULL))
    {
	/* XXX */
	return 1;
    }
    
    if( (cNode = *iHead) == NULL)
    {
	LogMessage("[%s()], No classification was found in the classification file,\n"
                   "\t make sure that you have valid records in your database (sig_class) table, else this might result in complete signature logging. \n",
		   __FUNCTION__);
	return 0;
    }
    
    while(cNode != NULL)
    {
	
	memset(&LobjNode,'\0',sizeof(cacheClassificationObj));
	
	LobjNode.obj.sig_class_id = cNode->id;

	/* 
	   -- config classification:shortname,short description,priority
	   NOTE: -elz i wongly assumed , short description was logged, while it 
	   was actually shortname that should have been logged, this is why
	   this part of the code is now commented :)
	   so using cNode->type instead of cNode->name
	*/
	
	if(cNode->type != NULL)
	{
	    strncpy(LobjNode.obj.sig_class_name,cNode->type,CLASS_NAME_LEN);
	    LobjNode.obj.sig_class_name[CLASS_NAME_LEN-1] = '\0'; //safety.
	    
	    if( (snort_escape_string_STATIC(LobjNode.obj.sig_class_name,CLASS_NAME_LEN,data)))
	    {
		FatalError("database [%s()], Failed a call to snort_escape_string_STATIC() for string : \n"
			   "[%s], Exiting. \n",
			   __FUNCTION__,
			   LobjNode.obj.sig_class_name);
	    }
	    
	}
	else
	{
	    snprintf(LobjNode.obj.sig_class_name,CLASS_NAME_LEN,
		     "[%s] id:[%u]",
		     "UNKNOWN SNORT CLASSIFICATION",
		     LobjNode.obj.sig_class_id);
	}



	if( (cacheClassificationLookup(&LobjNode.obj,iMasterCache->cacheClassificationHead) == 0))
	{
	    if( (TobjNode = SnortAlloc(sizeof(cacheClassificationObj))) == NULL)
	    {
		/* XXX */
		return 1;
	    }
	    
	    memcpy(TobjNode,&LobjNode,sizeof(cacheClassificationObj));
	    
	    
	    TobjNode->flag ^= CACHE_INTERNAL_ONLY;
	    
	    TobjNode->next = iMasterCache->cacheClassificationHead;
	    iMasterCache->cacheClassificationHead = TobjNode;
	    
	    cNode = cNode->next;
#if DEBUG
	    file_classification_object_count++;
#endif
	}
    }
    
    return 0;
}


/***********************************************************************************************CLASSIFICATION API*/

/** 
 * Fetch Classification from database
 * 
 * @param data 
 * @param iArrayPtr 
 * @param array_length 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t ClassificationPullDataStore(DatabaseData *data, dbClassificationObj **iArrayPtr,u_int32_t *array_length)
{

    
    
#if  (defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL))    
    u_int32_t curr_row = 0;
    u_int32_t queryColCount =0;
#endif /* (defined(ENABLE_MYSQL) || defined(ENABLE_POSTGRESQL)) */


#ifdef ENABLE_ODBC
    dbClassificationObj tClassObj = {0};
    SQLSMALLINT col_count = 0;
#endif /* ENABLE_ODBC */
    
#ifdef ENABLE_MYSQL
    int result = 0;
#endif

#ifdef ENABLE_POSTGRESQL
    char *pg_val = NULL;
    u_int32_t curr_col = 0;
    int num_row = 0;
    u_int8_t pgStatus = 0;
#endif /* ENABLE_POSTGRESQL */

    if( (data == NULL) ||
        ( ( iArrayPtr == NULL )  && ( *iArrayPtr != NULL )) ||
        ( array_length == NULL))
    { 
	/* XXX */
	LogMessage("[%s()], Call failed DataBaseData[0x%x] dbClassificationObj **[0x%x] u_int32_t *[0x%x] \n",
		   __FUNCTION__,
		   data,
		   iArrayPtr,
		   array_length);
	return 1;
    }
    
    
    DatabaseCleanSelect(data);
    if( (SnortSnprintf(data->SQL_SELECT, MAX_QUERY_LENGTH,
                       SQL_SELECT_ALL_CLASSIFICATION)!=  SNORT_SNPRINTF_SUCCESS))
    {
        FatalError("database [%s()], Unable to allocate memory for query, bailing ...\n",
		   __FUNCTION__);
    }
    
    if(checkTransactionCall(&data->dbRH[data->dbtype_id]))
    {
        /* A This shouldn't happen since we are in failed transaction state */
        /* XXX */
        return 1;
    }
    
    if( (data->dbRH[data->dbtype_id].dbConnectionStatus(&data->dbRH[data->dbtype_id])))
    {
        /* XXX */
        FatalError("database [%s()], Select Query[%s] failed check to dbConnectionStatus()\n",
                   __FUNCTION__,
                   data->SQL_SELECT);
    }

    switch(data->dbtype_id)
    {
	
#ifdef ENABLE_MYSQL
	
    case DB_MYSQL:

        result = mysql_query(data->m_sock,data->SQL_SELECT);

        switch(result)
        {
        case 0:

            if( (data->m_result = mysql_store_result(data->m_sock)) == NULL)
            {
                /* XXX */
                LogMessage("[%s()], Failed call to mysql_store_result \n",
                           __FUNCTION__);
                return 1;
            }
            else
            {
		
                MYSQL_ROW row = NULL;
                my_ulonglong num_row = 0;
                unsigned int i = 0;
		
                if( (num_row = mysql_num_rows(data->m_result)) > 0)
                {
                    if( (*iArrayPtr = SnortAlloc( (sizeof(dbClassificationObj) * num_row))) == NULL)
		    {
			mysql_free_result(data->m_result);
			data->m_result = NULL;
			FatalError("database [%s()]: Failed call to sigCacheRawAlloc() \n",
				   __FUNCTION__);
		    }
		}
		else
		{

		    /* XXX */
		    if(iArrayPtr != NULL)
		    {
			free(*iArrayPtr);
			*iArrayPtr = NULL;
		    }
                    mysql_free_result(data->m_result);
                    data->m_result = NULL;
                    LogMessage("[%s()]: No Classification found in database ... \n",
                               __FUNCTION__);
		    return 0;
                }
		
		*array_length = num_row;
		
		queryColCount = mysql_num_fields(data->m_result);
		
                if(queryColCount != NUM_ROW_CLASSIFICATION)
                {
                    /* XXX */
                    free(*iArrayPtr);
		    *iArrayPtr = NULL;
                    mysql_free_result(data->m_result);
                    data->m_result = NULL;
                    LogMessage("[%s()] To many column returned by query [%u]...\n",
                               __FUNCTION__,
                               queryColCount);
                    return 1;
                }
		
                while ((curr_row < num_row) &&
                       (row = mysql_fetch_row(data->m_result)))
                {

		    dbClassificationObj *cPtr = &(*iArrayPtr)[curr_row];
		    
                    for(i = 0; i < queryColCount; i++)
                    {
                        unsigned long *lengths={0};
			
                        if( (lengths = mysql_fetch_lengths(data->m_result)) == NULL)
                        {
                            free(*iArrayPtr);
			    *iArrayPtr = NULL;
                            mysql_free_result(data->m_result);
                            data->m_result = NULL;
                            FatalError("database [%s()], mysql_fetch_lengths() call failed .. \n",
                                       __FUNCTION__);
                        }
			
                        if(row[i])
			{
                            switch (i)
                            {
                            case 0:
                                cPtr->db_sig_class_id = strtoul(row[i],NULL,10);
                                break;
				
                            case 1:
                                strncpy(cPtr->sig_class_name,row[i],CLASS_NAME_LEN);
				cPtr->sig_class_name[CLASS_NAME_LEN-1] = '\0'; //safety

				if( (snort_escape_string_STATIC(cPtr->sig_class_name,CLASS_NAME_LEN,data)))
				{
				    FatalError("database [%s()], Failed a call to snort_escape_string_STATIC() for string : \n"
					       "[%s], Exiting. \n",
					       __FUNCTION__,
					       cPtr->sig_class_name);
				}


                                break;
				
                            default:
                                /* XXX */
                                /* Should bail here... */
                                break;
                            }
			}
		    }
		    
		    
                    curr_row++;
                }
		                
                mysql_free_result(data->m_result);
                data->m_result = NULL;
                return 0;
            }
            break;
	    
	    
        case CR_COMMANDS_OUT_OF_SYNC:
        case CR_SERVER_GONE_ERROR:
        case CR_UNKNOWN_ERROR:
        default:
	    
            if(checkTransactionState(data->dbRH))
            {
                LogMessage("[%s()]: Failed executing with error [%s], in transaction will Abort. \n Failed QUERY: [%s] \n",
                           __FUNCTION__,
                           mysql_error(data->m_sock),
                           data->SQL_SELECT);
                return 1;
            }
	    
            LogMessage("[%s()]: Failed exeuting query [%s] , will retry \n",
                       __FUNCTION__,
                       data->SQL_SELECT);
	    break;
	    
        }
	
        /* XXX */
        return 1;
        break;
#endif /* ENABLE_MYSQL */
	    
#ifdef ENABLE_POSTGRESQL
    case DB_POSTGRESQL:
	
	data->p_result = PQexec(data->p_connection,data->SQL_SELECT);
	
	pgStatus = PQresultStatus(data->p_result);
	switch(pgStatus)
	    {
		
	    case PGRES_TUPLES_OK:
		
		if( (num_row = PQntuples(data->p_result)))
		{

		    *array_length = num_row;
		    
		    if( (queryColCount = PQnfields(data->p_result)) !=  NUM_ROW_CLASSIFICATION)
		    {
			LogMessage("[%s()] To many column returned by query [%u]...\n",
				   __FUNCTION__,
				   queryColCount);
			PQclear(data->p_result);
			data->p_result = NULL;
			return 1;
		    }
		    
		    
		    if( (*iArrayPtr = SnortAlloc( (sizeof(dbClassificationObj) * num_row))) == NULL)
		    {
			if(data->p_result)
			{
			    PQclear(data->p_result);
			    data->p_result = NULL;
			}
			FatalError("database [%s()]: Failed call to sigCacheRawAlloc() \n",
				   __FUNCTION__);
		    }
		    
		    for(curr_row = 0 ; curr_row < num_row ; curr_row++)
		    {
			dbClassificationObj *cPtr = &(*iArrayPtr)[curr_row];
			
			for(curr_col = 0 ; curr_col < queryColCount ; curr_col ++)
			{
			    pg_val = NULL;
			    if( (pg_val = PQgetvalue(data->p_result,curr_row,curr_col)) == NULL)
			    {
				/* XXX */
				/* Something went wrong */
				PQclear(data->p_result);
				data->p_result = NULL;
				return 1;
			    }		
			    
			    switch(curr_col)
			    {
			    case 0:
				cPtr->db_sig_class_id = strtoul(pg_val,NULL,10);
				break;
			    case 1:
				strncpy(cPtr->sig_class_name,pg_val,CLASS_NAME_LEN);
				cPtr->sig_class_name[CLASS_NAME_LEN-1] = '\0'; //safety

				if( (snort_escape_string_STATIC(cPtr->sig_class_name,CLASS_NAME_LEN,data)))
                                {
                                    FatalError("database [%s()], Failed a call to snort_escape_string_STATIC() for string : \n"
                                               "[%s], Exiting. \n",
                                               __FUNCTION__,
                                               cPtr->sig_class_name);
                                }


				break;
			    default:
				/* We should bail here*/
				break;
			    }
			}
		    }
		}
		else
		{
		    *array_length = 0;
		}
		
		
		if(data->p_result)
		{
		    PQclear(data->p_result);
		    data->p_result = NULL;
		}
		
		return 0;
		break;
		
	    default:
		if(PQerrorMessage(data->p_connection)[0] != '\0')
		{
		    ErrorMessage("ERROR database: postgresql_error: %s\n",
				 PQerrorMessage(data->p_connection));
		    return 1;
		}
		break;
	    }
	    
	    return 1;
	    break;
	    
#endif /* ENABLE_POSTGRESQL */
	    
	    
#ifdef ENABLE_ODBC
	case DB_ODBC:

	    if(SQLAllocHandle(SQL_HANDLE_STMT,data->u_connection, &data->u_statement) == SQL_SUCCESS)
	    {
		if(SQLExecDirect(data->u_statement,(ODBC_SQLCHAR *)data->SQL_SELECT, SQL_NTS) == SQL_SUCCESS)
		{
		    if( SQLNumResultCols(data->u_statement,&col_count) == SQL_SUCCESS)
		    {
			if(col_count == NUM_ROW_CLASSIFICATION)
			{
			    if(SQLRowCount(data->u_statement, &data->u_rows) != SQL_SUCCESS)
			    {
				ODBCPrintError(data,SQL_HANDLE_STMT);
				FatalError("[%s()]: SQLRowCount() call failed \n",
					   __FUNCTION__);
			    }
			    
				if(data->u_rows)
				{
				    if( (*iArrayPtr = SnortAlloc( (sizeof(dbClassificationObj) * data->u_rows))) == NULL)
				    {
					goto ODBCError;
				    }
				    
				    *array_length = data->u_rows;

				}
				else
				{
				    /* We have no records */
				    *array_length = 0;
				    return 0;
				}
				
			    }
			    else
			    {
				FatalError("[%s()]: The number of column returned does not match [%u] \n",
					   __FUNCTION__,
					   NUM_ROW_CLASSIFICATION);
			    }
		    }
		    else
		    {
			LogMessage("[%s()]: SQLNumResultCols() call failed \n",
				   __FUNCTION__);
			ODBCPrintError(data,SQL_HANDLE_STMT);
			goto ODBCError;
		    }
		    
		}
		else
		{
		    LogMessage("[%s()]: SQLExecDirect() call failed \n",
			       __FUNCTION__);
			ODBCPrintError(data,SQL_HANDLE_STMT);
			goto ODBCError;
			
		}
	    }
	    else
	    {
		LogMessage("[%s()]: SQLAllocStmt() call failed \n",
			   __FUNCTION__);
		ODBCPrintError(data,SQL_HANDLE_STMT);
		goto ODBCError;
	    }
	    
	    SQLINTEGER col1_len = 0;
	    SQLINTEGER col2_len = 0;
	    
	    /* Bind template object */
	    if( SQLBindCol(data->u_statement,1,SQL_C_LONG,&tClassObj.db_sig_class_id,sizeof(u_int32_t),&col1_len) != SQL_SUCCESS)
	    {
		LogMessage("[%s()]: SQLBindCol() call failed \n",
			   __FUNCTION__);
		ODBCPrintError(data,SQL_HANDLE_STMT);
		goto ODBCError;
	    }
	    
	    if( SQLBindCol(data->u_statement,2,SQL_C_CHAR,&tClassObj.sig_class_name,(sizeof(char) * CLASS_NAME_LEN) ,&col2_len) != SQL_SUCCESS)
	    {
		LogMessage("[%s()]: SQLBindCol() call failed \n",
			   __FUNCTION__);
		ODBCPrintError(data,SQL_HANDLE_STMT);
		goto ODBCError;
	    }
	    
	    for(curr_row = 0; curr_row < data->u_rows;curr_row++)
	    {
		dbClassificationObj *cPtr = &(*iArrayPtr)[curr_row];
		
                /* fetch */
		if( SQLFetch(data->u_statement) != SQL_SUCCESS)
		{
		    LogMessage("[%s()]: SQLFetch error on record [%u] \n",
			       __FUNCTION__,
			       curr_row+1);
		    ODBCPrintError(data,SQL_HANDLE_STMT);
		    goto ODBCError;
		}
		else
		{
		    if( (col1_len == SQL_NO_TOTAL || col1_len == SQL_NULL_DATA) ||
			(col2_len == SQL_NO_TOTAL || col2_len == SQL_NULL_DATA))
		    {
			FatalError("[%s()] Seem's like we have some null data ...\n",
				   __FUNCTION__);
		    }
		    
		    
		    /* Copy object */
		    if( (memcpy(cPtr,&tClassObj,sizeof(dbClassificationObj))) != cPtr)
		    {
			FatalError("[%s()] : memcpy error ..\n",
				   __FUNCTION__);
		    }
		    
		    /* Clear temp obj */
		    memset(&tClassObj,'\0',sizeof(dbClassificationObj));
		}
	    }

	    SQLFreeHandle(SQL_HANDLE_STMT,data->u_statement);
	    return 0;

    ODBCError:
	    SQLFreeHandle(SQL_HANDLE_STMT,data->u_statement);
	    return 1;
	    

	    break;
#endif /* ENABLE_ODBC */
	    
#ifdef ENABLE_ORACLE
    case DB_ORACLE:
	LogMessage("[%s()], is not yet implemented for DBMS configured\n",
		   __FUNCTION__);
	
	break;
#endif /* ENABLE_ORACLE */
	
	
#ifdef ENABLE_MSSQL
    case DB_MSSQL:
	LogMessage("[%s()], is not yet implemented for DBMS configured\n",
                   __FUNCTION__);
	break;
#endif /* ENABLE_MSSQL */
	    
    default:
	
	LogMessage("[%s()], is not yet implemented for DBMS configured\n",
		   __FUNCTION__);
	break;
	
	return 1;
    }
    
    /* XXX */
    return 1;
}
    



	   

/** 
 *  Merge internal Classification cache with database data, detect difference, tag known node for database update
 * 
 * @param iDBList 
 * @param array_length 
 * @param cacheHead 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t ClassificationCacheUpdateDBid(dbClassificationObj *iDBList,u_int32_t array_length,cacheClassificationObj **cacheHead)
{


    cacheClassificationObj *TobjNode = NULL;    
    dbClassificationObj *cObj = NULL;

    int x = 0;

    if( ((iDBList == NULL) ||
	 (array_length == 0) ||
	 (cacheHead == NULL)))
    {
	/* XXX */
	return 1;
    }


    /* Set default db object classification id as invocation require */
    for(x = 0 ; x < array_length ; x++)
    {
	cObj = &iDBList[x];
	cObj->sig_class_id = x+1;
    }
    
    for(x = 0 ; x < array_length ; x++)
    {
	cObj = &iDBList[x];
	
	if( (dbClassificationLookup(cObj,*cacheHead)) == 0 )
	{
	    /* Element not found, add the db entry to the list. */
	    
	    if( (TobjNode = SnortAlloc(sizeof(cacheClassificationObj))) == NULL)
	    {
		/* XXX */
		return 1;
	    }
	    
	    memcpy(&TobjNode->obj,cObj,sizeof(dbClassificationObj));
	    TobjNode->flag ^= CACHE_DATABASE_ONLY;
	    
	    if(*cacheHead == NULL)
	    {
		*cacheHead = TobjNode;
	    }
	    else
	    {
		TobjNode->next = *cacheHead;
		*cacheHead = TobjNode;
	    }
	}
    }

    return 0;
}


/** 
 *  Populate the sig_class table with record that are not present in the database.
 * 
 * @param data 
 * @param cacheHead 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t ClassificationPopulateDatabase(DatabaseData  *data,cacheClassificationObj *cacheHead)
{
    u_int32_t db_class_id;
    
    if( (data == NULL) ||
	(cacheHead == NULL))
    {
	/* XXX */
	return 1;
    }
	
    if(checkTransactionCall(&data->dbRH[data->dbtype_id]))
    {
        /* A This shouldn't happen since we are in failed transaction state */
        /* XXX */
        return 1;
    }
    
    if( (data->dbRH[data->dbtype_id].dbConnectionStatus(&data->dbRH[data->dbtype_id])))
    {
        /* XXX */
        FatalError("database [%s()], Select Query[%s] failed check to dbConnectionStatus()\n",
                   __FUNCTION__,
                   data->SQL_SELECT);
    }

    BeginTransaction(data);
    
    while(cacheHead != NULL)
    {
	if(cacheHead->flag & CACHE_INTERNAL_ONLY)
	{
	    
#if DEBUG
            inserted_classification_object_count++;
#endif

	    /* DONE at object insertion
	      if( (snort_escape_string_STATIC(cacheHead->obj.sig_class_name,CLASS_NAME_LEN,data)))
	      {
	      FatalError("database [%s()], Failed a call to snort_escape_string_STATIC() for string : \n"
	      "[%s], Exiting. \n",
	      __FUNCTION__,
	      cacheHead->obj.sig_class_name);
	      }
	    */
	    
	    DatabaseCleanInsert(data);

	    if( (SnortSnprintf(data->SQL_INSERT, MAX_QUERY_LENGTH,
			       SQL_INSERT_CLASSIFICATION,
			       cacheHead->obj.sig_class_name)) !=  SNORT_SNPRINTF_SUCCESS)
	    {
		/* XXX */
		goto TransactionFail;
	    }


	    if( (SnortSnprintf(data->SQL_SELECT, MAX_QUERY_LENGTH,
			       SQL_SELECT_SPECIFIC_CLASSIFICATION,
			       cacheHead->obj.sig_class_name)) !=  SNORT_SNPRINTF_SUCCESS)
	    {
		/* XXX */
		    goto TransactionFail;
	    }
	
	    if(Insert(data->SQL_INSERT,data,1))
	    {
		/* XXX */
		goto TransactionFail;
	    }
	    
	    if(Select(data->SQL_SELECT,data,&db_class_id))
	    {
		/* XXX */
		goto TransactionFail;
	    }
	    
	    cacheHead->obj.db_sig_class_id = db_class_id;


	}
	cacheHead = cacheHead->next;


    }

    CommitTransaction(data);
    
    return 0;
    
TransactionFail:
    RollbackTransaction(data);
    return 1;
}

/** 
 * Wrapper function for classification cache synchronization
 * 
 * @param data 
 * @param cacheHead 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t ClassificationCacheSynchronize(DatabaseData *data,cacheClassificationObj **cacheHead)
{
    dbClassificationObj *dbClassArray = NULL;
    u_int32_t array_length = 0;
    
    if( (data == NULL) ||
	(cacheHead == NULL))
    {
	/* XXX */
       	return 1;
    }
    
    if( (ClassificationPullDataStore(data,&dbClassArray,&array_length)))
    {
	/* XXX */
	return 1;
    }

    
#if DEBUG
    db_classification_object_count=array_length;
#endif
    
    if( array_length > 0 )
    {
	if( (ClassificationCacheUpdateDBid(dbClassArray,array_length,cacheHead)) )
	{
	    /* XXX */
	    if( dbClassArray != NULL)
	    {
		free(dbClassArray);
		dbClassArray = NULL;
		array_length = 0;
	    }
	
	    LogMessage("[%s()], Call to ClassificationCacheUpdateDBid() failed \n",
		       __FUNCTION__);
	    return 1;
	}
	
	if(dbClassArray != NULL)
	{
	    free(dbClassArray);
	    dbClassArray = NULL;
	}
	array_length = 0;
    }
    
    
    if(*cacheHead == NULL)
    {
	LogMessage("\n[%s()]: Make sure that your (config classification_config argument in your barnyard2 configuration file) or --classification or -C argument point \n"
		   "\t to a file containing at least some valid classification or that that your database sig_class table contain data\n\n",
		   __FUNCTION__);
	return 1;
    }
    
    if(*cacheHead != NULL)
    {
	if(ClassificationPopulateDatabase(data,*cacheHead))
	{
	    LogMessage("[%s()], Call to ClassificationPopulateDatabase() failed \n",
		       __FUNCTION__);
	    
	    return 1;
	}
    }
    
    /* out list will behave now */
    return 0;
}

/***********************************************************************************************CLASSIFICATION API*/

/***********************************************************************************************SIGNATURE API*/

/**
 * Lookup a signature in the sid-msg.map cache. If the signature is found, this
 * function has the side effect of populating lookup->msg.
 *
 * @return 0 found
 * @return 1 not found / error
 * 
 * Side effects: When found, lookup->message is populated with the message.
 */
static u_int32_t SignatureLookupCache(dbSignatureObj * lookup) {
	if (lookup == NULL)
		return 1;

	SigNode * node = GetSigByGidSid(lookup->gid, lookup->sid, lookup->rev);

	//@TODO think about this
	//@TODO previously this checked priority/class_id too. Think about this too.
	if (node->source_file != SOURCE_GEN_RUNTIME) {
		strncpy(lookup->message, node->msg, SIG_MSG_LEN); 
		return 0;
	} else {
		return 1;
	}
}


/** 
 * Lookup the database for a specific signature, without looking for signature message.
 * 
 * @param data 
 * @param sObj 
 * 
 * @return 
 * 0 OK (Found)
 * 1 ERROR (Not Found)
 */
u_int32_t SignatureLookupDatabase(DatabaseData *data,dbSignatureObj *sObj)
{

    u_int32_t db_sig_id = 0;

    if( (data == NULL) ||
	(sObj == NULL))
    {
	/* XXX */
	return 1;
    }

    if(checkTransactionCall(&data->dbRH[data->dbtype_id]))
    {
        /* A This shouldn't happen since we are in failed transaction state */
        /* XXX */
        return 1;
    }

    if( (data->dbRH[data->dbtype_id].dbConnectionStatus(&data->dbRH[data->dbtype_id])))
    {
        /* XXX */
        FatalError("database [%s()], Select Query[%s] failed check to dbConnectionStatus()\n",
                   __FUNCTION__,
                   data->SQL_SELECT);
    }
    
    DatabaseCleanSelect(data);
    if( (SnortSnprintf(data->SQL_SELECT, MAX_QUERY_LENGTH,
		       SQL_SELECT_SPECIFIC_SIGNATURE_WITHOUT_MESSAGE,
		       sObj->sid,
		       sObj->gid,
		       sObj->rev,
		       sObj->class_id,
		       sObj->priority_id)) !=  SNORT_SNPRINTF_SUCCESS)
    {
	/* XXX */
	return 1;
    }
    
#if DEBUG
    DEBUG_WRAP(DebugMessage(DB_DEBUG,"[%s()] Signature was not found in cache, looking for existance in the database:\n"
			    "\t if this message occur to often, make sure your sid-msg.map and gen-msg.map file are up to date.\n"
			    "\t Executing [%s]\n",
			    __FUNCTION__,
			    data->SQL_SELECT));
#endif
    
    if(Select(data->SQL_SELECT,data,&db_sig_id))
    {
	/* XXX */
	return 1;
    }
    
    if(db_sig_id == 0)
    {
	
#if DEBUG
	DEBUG_WRAP(DebugMessage(DB_DEBUG,"[%s()]: A lookup received a result but a result of 0 shouldn't be returned,\n"
				"\t this shouldn't happen for sid[%u] sid[%u] rev[%u] class_id[%u] priority_id[%u] \n",
				__FUNCTION__,
				sObj->sid,
				sObj->gid,
				sObj->rev,
				sObj->class_id,
				sObj->priority_id));
#endif
	return 1;
    }
    
    /* Found */
    sObj->db_id = db_sig_id;
    return 0;
}


/** 
 *  Populate the signature table with record that are not present in the database.
 * 
 * @param data 
 * @param cacheHead 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t SignaturePopulateDatabase(DatabaseData  *data,dbSignatureObj * sig,int inTransac)
{
	u_int32_t db_sig_id = 0;


	if( (data == NULL) || (sig == NULL))
		return 1;

	if(checkTransactionCall(&data->dbRH[data->dbtype_id])) {
		/* A This shouldn't happen since we are in failed transaction state */
		/* XXX */
		return 1;
	}

	if( (data->dbRH[data->dbtype_id].dbConnectionStatus(&data->dbRH[data->dbtype_id]))) {
		/* XXX */
		FatalError("database [%s()], Select Query[%s] failed check to dbConnectionStatus()\n",
				__FUNCTION__,
				data->SQL_SELECT);
	}

	if(inTransac == 0) {
		if( (BeginTransaction(data)))
			return 1;
	}

	/* This condition block is a shortcut in the signature insertion code.
	 ** Preventing signature that have not been under "revision" (rev == 0) to be inserted in the database.
	 ** It will also prevent the code to take wrong execution path downstream.
	 ** @TODO: remove flag field?? ((cacheHead->flag & CACHE_INTERNAL_ONLY) && 
	 */
	if((sig->gid != 1 && sig->gid != 3) || ((sig->gid == 1 || sig->gid == 3) && sig->rev != 0)) {
		/* This condition block is a shortcut in the signature insertion code.
		 ** Preventing signature that have not been under "revision" (rev == 0) to be inserted in the database.
		 ** It will also prevent the code to take wrong execution path downstream.
		 */

#if DEBUG
		inserted_signature_object_count++;
#endif 

		DatabaseCleanInsert(data);


		if((SnortSnprintf(data->SQL_INSERT, MAX_QUERY_LENGTH,
						SQL_INSERT_SIGNATURE,
						sig->sid,
						sig->gid,
						sig->rev,
						sig->class_id,
						sig->priority_id,
						sig->message)) !=  SNORT_SNPRINTF_SUCCESS)
		{
			/* XXX */
			goto TransactionFail;
		}

		DatabaseCleanSelect(data);

		if( (SnortSnprintf(data->SQL_SELECT, MAX_QUERY_LENGTH,
						SQL_SELECT_SPECIFIC_SIGNATURE,
						sig->sid,
						sig->gid,
						sig->rev,
						sig->class_id,
						sig->priority_id,
						sig->message)) !=  SNORT_SNPRINTF_SUCCESS)
		{
			/* XXX */
			goto TransactionFail;
		}

		if(Insert(data->SQL_INSERT,data,1))
		{
			/* XXX */
			goto TransactionFail;
		}

		if(Select(data->SQL_SELECT,data,&db_sig_id))
		{
			/* XXX */
			goto TransactionFail;
		}

		sig->db_id = db_sig_id;
	}

	//Assumption: This is a new signature insertion, so the references also
	//need to be inserted.
	if (SignatureInsertReferences(data, sig))
		goto TransactionFail;


	if(inTransac == 0) {
		if(CommitTransaction(data)) {
			return 1;
		}
	}

	return 0;

TransactionFail:
	if( inTransac == 0) {
		RollbackTransaction(data);
	}

	return 1;    
}

/**
 * Insert a signature's references.
 *
 * @param data 
 * @param sig signature to insert references for.
 *
 * @return 0 on success; 1 on error
 */
static u_int32_t SignatureInsertReferences(DatabaseData * data, dbSignatureObj * sig) {
	SigNode * sn = GetSigByGidSid(sig->gid, sig->sid, sig->rev);

	if (sn == NULL || sn->source_file == SOURCE_GEN_RUNTIME)
		return 0;

	ReferenceNode * cur = sn->refs;

	int seq = 1;
	while (cur != NULL) {
		//@TODO do I even care about errors here?
		if (SignatureInsertReference(data, sig->db_id, seq, cur))
			return 1;

		seq++;
		cur = cur->next;
	}

	return 0;
}

/**
 * Insert a single reference for a given signature, also inserting
 * reference_system if necessary.
 *
 * @param data
 * @param db_sig_id The ID# of the signature in the database
 * @param seq Ordinal number representing the position of this reference in the
 *        signature's reference list.
 * @param ref The Reference to insert.
 *
 * @return 0 on success; 1 on error
 */
static u_int32_t SignatureInsertReference(DatabaseData * data, u_int32_t db_sig_id, int seq, ReferenceNode * ref) {
	static dbSystemObj dbSys;
	static dbReferenceObj dbRef;

	memset(&dbSys, 0, sizeof dbSys);
	memset(&dbRef, 0, sizeof dbRef);

	if (ref->system == NULL)
		return 1;

	//@TODO it seems like <-- what were you saying here??
	strncpy(dbSys.name, ref->system->name, SYSTEM_NAME_LEN);
	strncpy(dbSys.url, ref->system->url, SYSTEM_URL_LEN);
	//NOTE: this returns the db ID.
	if (DbReferenceSystemLookup(data, &dbSys) == 0)
		return 1;


	strncpy(dbRef.ref_tag, ref->id, REF_TAG_LEN-1); 
	dbRef.ref_tag[REF_TAG_LEN-1] = '\0';
	dbRef.system_id = dbSys.db_ref_system_id;
	//this returns the db id.
	if (ReferenceLookup(data, &dbRef) == 0)
		return 1;
	
	int res = SnortSnprintf(data->SQL_INSERT, MAX_QUERY_LENGTH, SQL_INSERT_SIGREF, dbRef.ref_id, db_sig_id, seq);

	if (res != SNORT_SNPRINTF_SUCCESS)
		return 1; 

	if (Insert(data->SQL_INSERT, data, 1))
		return 1;

	return 0;
}

/**
 * Lookup a reference system in the db cache.
 *
 * @param mc
 * @param lookup
 *
 * @return 0 on success; 1 on error
 *
 * Side effects: If the system is found in the cache, lookup->db_ref_system_id
 * is updated.
 */
static u_int32_t ReferenceSystemLookupDbCache(MasterCache *mc, dbSystemObj * lookup) {
	if (mc == NULL || lookup == NULL)
		return 1;

	cacheSystemObj * cur = mc->cacheSystemHead;	

	while (cur != NULL) {
		if (strncmp(cur->obj.name, lookup->name, SYSTEM_NAME_LEN) == 0
				&& strncmp(cur->obj.url, lookup->url, SYSTEM_URL_LEN) == 0) {

			lookup->db_ref_system_id = cur->obj.db_ref_system_id;
			return 0;
		}

		cur = cur->next;
	}

	return 1;
}

/**
 * Insert a reference system into the DB cache.
 * 
 * @param sys The system to insert
 * @param mc The master cache
 * 
 * @return 0 on success; 1 on error
 * @TODO the order of arguments is opposite ReferenceSystemLookupDbCache
 */
static u_int32_t ReferenceSystemCacheInsertObj(dbSystemObj * sys, MasterCache * mc ) {
	cacheSystemObj * cache;

	if (sys == NULL || mc == NULL)
		return 1;

	if ((cache = SnortAlloc(sizeof(*cache))) == NULL)
		return 1;

	memcpy(&cache->obj, sys, sizeof(cache->obj));
	cache->next = mc->cacheSystemHead;
	mc->cacheSystemHead = cache;

	return 0;
}

/**
 * Lookup a reference system id.
 *
 * @param data
 * @param lookup The reference system (name,url) to lookup
 *
 * @return A database ID number (>0) on success; 0 on error.
 *
 * Side effects: If the reference system does not exist in the database, it
 * will be added. In all successful cases, lookup->db_ref_system_id will be
 * populated.
 *
 * @TODO fucking return values. SO FUCKING INCONSISTENT
 * ... it was done this way to be consistent with SignatureLookup.
 * Return the databse id on success; 0 on error.
 * @TODO prefixed with DB due to name collision... Should do this for all of them probably
 */
static u_int32_t DbReferenceSystemLookup(DatabaseData * data, dbSystemObj * lookup) {
	u_int32_t db_ref_system_id;

	if (data == NULL || lookup == NULL)
		return 0;

	if (ReferenceSystemLookupDbCache(&data->mc, lookup) == 0) {
		db_ref_system_id = lookup->db_ref_system_id;
	} else if (ReferenceSystemLookupDatabase(data, lookup) == 0) {
		db_ref_system_id = lookup->db_ref_system_id;	

		if (ReferenceSystemCacheInsertObj(lookup, &data->mc)) {
			//@TODO fuck it if it doesn't cache
		}
	} else {
		if (ReferenceSystemPopulateDatabase(data,lookup)) {
			return 0;
		}
		
		if (ReferenceSystemCacheInsertObj(lookup,&data->mc)) {
			//@TODO fuck it
		}

		db_ref_system_id = lookup->db_ref_system_id;
	}

	return db_ref_system_id;
}

/** 
 * Lookup a reference system ID in the database.
 *
 * @param data
 * @param lookup
 * 
 * @return 0 on success (found); 1 on error (or not found)
 */
static u_int32_t ReferenceSystemLookupDatabase(DatabaseData * data, dbSystemObj * lookup) {
	u_int32_t db_ref_system_id = 0;
	int res;

	if (data == NULL || lookup == NULL)
		return 1;
	
	res = SnortSnprintf(data->SQL_SELECT, MAX_QUERY_LENGTH, 
			SQL_SELECT_SPECIFIC_REFERENCE_SYSTEM, lookup->name, lookup->url);

	if (res != SNORT_SNPRINTF_SUCCESS)
		return 1; 

	if (Select(data->SQL_SELECT,data, &db_ref_system_id))
		return 1;

	if (db_ref_system_id == 0)
		return 1;

	lookup->db_ref_system_id = db_ref_system_id;

	return 0;
}

/**
 * Insert a reference system into the database. 
 * 
 * @param data
 * @param sys
 *
 * @return 1 on error | 0 on success
 *
 * Side Effects: When successful, sys->db_ref_system_id will be populated with
 * the id# of the inserted row.
 */
static u_int32_t ReferenceSystemPopulateDatabase(DatabaseData * data, dbSystemObj * sys) {

	if (sys == NULL)
		return 1;

	//@TODO this escaping seems like a mess
	//@TODO make a function to escape and query. 
	if (snort_escape_string_STATIC(sys->name, SYSTEM_NAME_LEN, data))
		return 1;

	if (snort_escape_string_STATIC(sys->url, SYSTEM_URL_LEN, data))
		return 1;

	if (SnortSnprintf(data->SQL_INSERT, MAX_QUERY_LENGTH, 
				SQL_INSERT_SPECIFIC_REFERENCE_SYSTEM, 
				sys->name, sys->url) != SNORT_SNPRINTF_SUCCESS)	
		return 1;

	if (Insert(data->SQL_INSERT, data, 1)) 
		return 1;

	return ReferenceSystemLookupDatabase(data, sys);
}

/**
 * Lookup the DB id of a reference (system,tag). 
 *
 * @param data
 * @param ref The reference to find in the DB.
 *
 * @return database ID on success; 0 on failure
 * 
 * Side effects: If not found in the DB, the reference is inserted. ref->ref_id
 * will be poplulated.
 */
static u_int32_t ReferenceLookup(DatabaseData * data, dbReferenceObj * ref) {
	if (data == NULL || ref == NULL)
		return 0;

	if (ReferenceLookupDatabase(data,ref) != 0) {
		if (ReferencePopulateDatabase(data,ref)) {
			return 0;
		}
	} 

	return ref->ref_id;
}

/**
 * Insert a reference into the database.
 *
 * @param data
 * @param ref The reference to insert.
 *
 * @return 0 on success ; 1 on failure
 *
 * Side Effects: ref->ref_id will be populated if successful.
 */
static u_int32_t ReferencePopulateDatabase(DatabaseData * data, dbReferenceObj * ref) {
	if (data == NULL || ref == NULL)
		return 1;

	//@TODO this god fucking damn escaping again
	if (snort_escape_string_STATIC(ref->ref_tag, REF_TAG_LEN, data))
		return 1;

	if (SnortSnprintf(data->SQL_INSERT, MAX_QUERY_LENGTH, 
				SQL_INSERT_SPECIFIC_REF, 
				ref->system_id, ref->ref_tag) != SNORT_SNPRINTF_SUCCESS)	
		return 1;

	if (Insert(data->SQL_INSERT, data, 1)) 
		return 1;

	return ReferenceLookupDatabase(data, ref);
}

/**
 * Lookup the database ID of a reference.
 *
 * @param data
 * @param lookup a dbReferenceObj populated with the system_id and ref_tag to lookup.
 *
 * @return 0 on success ; 1 on failure
 *
 * Side Effects: If found, lookup->ref_id is populated with the database ID.
 */
static u_int32_t ReferenceLookupDatabase(DatabaseData * data, dbReferenceObj * lookup) {
	u_int32_t db_ref_id = 0;
	int res;

	if (data == NULL || lookup == NULL)
		return 1;
	
	res = SnortSnprintf(data->SQL_SELECT, MAX_QUERY_LENGTH, 
			SQL_SELECT_SPECIFIC_REF, lookup->system_id, lookup->ref_tag);

	if (res != SNORT_SNPRINTF_SUCCESS)
		return 1; 

	if (Select(data->SQL_SELECT,data, &db_ref_id))
		return 1;

	if (db_ref_id == 0)
		return 1;

	lookup->ref_id = db_ref_id;

	return 0;
}

/**
 * Lookup the database ID for a given signature. First, check the database
 * cache for the exact (sid,gid,rev,class,priority). Failing that, check the
 * database (if found: cache). Failing that, consult the sid-msg.map. Failing
 * that: create a new sig in the DB with message "Snort Alert [gid:sid:rev]"
 * @TODO: should this be put in the DB cache? probably. It will end up there
 * if the sig hits again.
 *
 * @param data
 * @param lookup a dbSignatureObj containing the parameters to lookup. 
 *
 * @return The id number of the signature row in the database or 0 on error.
 */
u_int32_t SignatureLookup(DatabaseData * data, dbSignatureObj * lookup) {
	u_int32_t db_sig_id = 0;

	if (SignatureLookupDbCache(&data->mc, lookup) == 0) {
		db_sig_id = lookup->db_id;
	} else if (SignatureLookupDatabase(data,lookup) == 0) {
			db_sig_id = lookup->db_id;

		if (SignatureCacheInsertObj(lookup,&data->mc)) {
			//intentionally not returning here: the data may not be cached
			//locally, but we did populate the signature ID
			//@TODO
		}
	} else {
		//returns 1 if not found.
		if (SignatureLookupCache(lookup) != 0) {
			if (SnortSnprintf(lookup->message,SIG_MSG_LEN,"Snort Alert [%u:%u:%u]",
						lookup->gid,lookup->sid,lookup->rev)) {
				return 0;
			}
		}

		//@TODO: This inTransac is a bad time.
		if (SignaturePopulateDatabase(data,lookup,1)) {
			LogMessage("[%s()]: ERROR inserting new signature \n",
					__FUNCTION__);
			return 0;
		}

		if (SignatureCacheInsertObj(lookup,&data->mc)) {
			/* XXX */
			LogMessage("[%s()]: ERROR inserting object in the cache list .... \n",
					__FUNCTION__);
			return 0;
		}

		db_sig_id = lookup->db_id;
	}

	return db_sig_id;
}

/***********************************************************************************************SIGREF API*/


/***********************************************************************************************SIGREF API*/


/** 
 * Entry point function that convert existing cache to a form used by the spo_database
 * (only initialize with internal data)
 * 
 * @param bc 
 * @param data 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t ConvertDefaultCache(Barnyard2Config *bc,DatabaseData *data) {
    if (bc == NULL|| data == NULL) {
		FatalError("database [%s()], received a NULL argument : Barnyard2Config [0x%x] or DatabaseData [0x%x]  \n",
			__FUNCTION__,
			bc,
			data);
    }
    
    if ((ConvertClassificationCache(&bc->classifications,&data->mc,data))) {
		return 1;
    }

    return 0;
}



/** 
 * Flush caches.
 * bye bye my love
 * 
 * @param data 
 */
void MasterCacheFlush(DatabaseData *data,u_int32_t flushFlag)
{

    cacheClassificationObj *MCcacheClassification;
    cacheSignatureReferenceObj *MCcacheSigReference;
    cacheReferenceObj *MCcacheReference;
    cacheSystemObj *MCcacheSystem;
    
    void *holder;
    void *holder2;

    if(data == NULL)
    {
	/* XXX */
	return ;
    }


	/* Just clean the array's. */
	/* @TODO why is this not a separate function? */
	/* @TODO I deleted sig ref caching from this. */
	if( (data->mc.cacheSignatureHead != NULL) && (flushFlag & CACHE_FLUSH_SIGNATURE)) {
		khint_t k;

		for (k = kh_begin(data->mc.cacheSignatureHead); k != kh_end(data->mc.cacheSignatureHead); ++k) {
			if (kh_exist(data->mc.cacheSignatureHead,k)) {
				kh_destroy(dbSigCacheNode, kh_value(data->mc.cacheSignatureHead,k));
			}
		}

		kh_destroy(dbSigCache, data->mc.cacheSignatureHead);
		data->mc.cacheSignatureHead = NULL;

	}

    if( (data->mc.cacheClassificationHead!= NULL) &&
	(flushFlag & CACHE_FLUSH_CLASSIFICATION))
    {
	MCcacheClassification = data->mc.cacheClassificationHead;
	
	while( MCcacheClassification != NULL)
	{
	    holder = (void *)MCcacheClassification->next;
	    free(MCcacheClassification);
	    MCcacheClassification = (cacheClassificationObj *)holder;	
	}
	
	data->mc.cacheClassificationHead = NULL;
    }


    if( ( data->mc.cacheSigReferenceHead != NULL) &&
	(flushFlag & CACHE_FLUSH_SIGREF))
    {
	MCcacheSigReference = data->mc.cacheSigReferenceHead;
	
	while( MCcacheSigReference!= NULL)
	{
	    holder = (void *)MCcacheSigReference->next;
	    free(MCcacheSigReference);
	    MCcacheSigReference	= (cacheSignatureReferenceObj *)holder;	
	}
	
	data->mc.cacheSigReferenceHead = NULL;
    }
    
    if( (data->mc.cacheSystemHead != NULL) &&
	(flushFlag & CACHE_FLUSH_SYSTEM_REF))
    {
	MCcacheSystem = data->mc.cacheSystemHead;
	
	while( MCcacheSystem != NULL)
	{
	    holder = (void *)MCcacheSystem->next;

	    if(MCcacheSystem->obj.refList != NULL)
	    {
		MCcacheReference = MCcacheSystem->obj.refList;
		
		while( MCcacheReference != NULL)
		{
		    holder2 = (void *)MCcacheReference->next;
		    free(MCcacheReference);
		    MCcacheReference = (cacheReferenceObj *)holder2;
		}
		
		MCcacheSystem->obj.refList = NULL;
		
	    }

	    free(MCcacheSystem);
	    MCcacheSystem = (cacheSystemObj *)holder;	
	}
	
	data->mc.cacheSystemHead = NULL;
    }
    
    return;
    
}



/** 
 * Synchronize caches (internal from files and cache from database
 * 
 * @param data 
 * 
 * @return 
 * 0 OK
 * 1 ERROR
 */
u_int32_t CacheSynchronize(DatabaseData *data)
{
    if(data == NULL)
    {
	/* XXX */
	return 1;
    }
    
    //Classification Synchronize
    if( (ClassificationCacheSynchronize(data,&data->mc.cacheClassificationHead)))
    {
	/* XXX */
	LogMessage("[%s()], ClassificationCacheSynchronize() call failed. \n",
		   __FUNCTION__);
	return 1;
    }
    
#if DEBUG

    DEBUG_WRAP(DebugMessage(DB_DEBUG,"================================================"
			    "===============================\n"));
    DEBUG_WRAP(DebugMessage(DB_DEBUG,"[%s()], sleeping 5 second so you can look at cache statistics \n",
			    __FUNCTION__));
    DEBUG_WRAP(DebugMessage(DB_DEBUG,"================================================"
			    "===============================\n"));


    DEBUG_WRAP(DebugMessage(DB_DEBUG,"[Signature]: [file : %u] [db: %u] [new database insertion: %u] \n",
			    file_signature_object_count,
			    db_signature_object_count,
			    inserted_signature_object_count));
    
    DEBUG_WRAP(DebugMessage(DB_DEBUG,"[Classification]: [file : %u] [db: %u] [new database insertion: %u] \n",
			    file_classification_object_count,
			    db_classification_object_count,
			    inserted_classification_object_count));

    DEBUG_WRAP(DebugMessage(DB_DEBUG,"[System]: [file : %u] [db: %u] [new database insertion: %u] \n",
			    file_system_object_count,
			    db_system_object_count,
			    inserted_system_object_count));
    
    DEBUG_WRAP(DebugMessage(DB_DEBUG,"[Reference]: [file : %u] [db: %u] [new database insertion: %u] \n",
			    file_reference_object_count,
			    db_reference_object_count,
			    inserted_reference_object_count));
    
    DEBUG_WRAP(DebugMessage(DB_DEBUG,"[Signature Reference]: [file : %u] [db: %u] [new database insertion: %u] \n",
			    file_sigref_object_count,
			    db_sigref_object_count,
			    inserted_sigref_object_count));

    DEBUG_WRAP(DebugMessage(DB_DEBUG,"================================================"
			    "===============================\n\n"));

    sleep(5);

#endif

    
    // Since we do not need reference and sig_reference clear those cache (free memory) and clean signature reference list and count 
    //MasterCacheFlush(data,CACHE_FLUSH_SYSTEM_REF|CACHE_FLUSH_SIGREF|CACHE_FLUSH_SIGREF);
    // Since we do not need reference and sig_reference clear those cache (free memory) and clean signature reference list and count
    
    return 0;
}


