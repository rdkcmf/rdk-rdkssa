/*
 * Copyright 2020 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
*/

/**
 * ssacli   -   cli interface to call ssa functions on behalf of a script
 *
 * Supports the invocation of any number of ssa API's up to the string capacity of the library, which is 4K
 *  Each API is invoked by denoting the Provider using a keyword, followed by an attribute string that are 
 *  the inputs to the API (see rdkssa.h for more info)
 *
 *  Delimiters:
 *      Each API=ProviderAttributeString is delimited by {} brackets
 *      Each Attribute or Name=Value string in the ProviderAttributeString is delimited by commas ","
 *
 *  Example:
 *      ssacli "{STORE=path/to/cred,DST=my/place/to/store} {IDENT=MACADDR} {CA=CREATE=my/path/to/store,EXPIR=3y,..}
 *
 *  Note:  with some simple parsing the same pattern as the providers themselves can/should be used to process the
 *  series of {} strings and ProviderAttributeStrings.
 *  Note2: The character set permitted for ANY and ALL inputs to the ssa handlers is limited, see rdkssa.h
 *
 */

#include "rdkssa.h"
#include "safec_lib.h"
// after error reporting, exit or not?
#define DO_EXIT 1
#define DONT_EXIT 0

static rdkssaStatus_t handleError( rdkssaStatus_t err, int doExit );

/**
 * cliCheck      -       Rudimentary enforcer of input syntax
 */
static void cliCheck( int argc, char *argv[]  )
{
    if ( argc < 2 ) {
        RDKSSA_LOG_ERROR("syntax: ssacli \"{cmds}\" ...\n");
        exit( 1 );
    }
}

/**
 * cleanupVector        -       free everything of an allocated array of pointers to allocation memory
 */
static void cleanupVector( const char ***v )
{
    rdkssaCleanupVector( (char ***)v ); // this is allocated space so it's not really a const
}

/**
 * parseProvCmds    -       The (attribute | name=value),... portion of the provider command string
 *
 * According to the rules, each attrib is separated by ',' and the list terminates with '}'
 * When '}' is found, parsing stops!  
 *
 * Returns a vector of strings if successful, NULL if failures due to syntax or some other weirdness
 */
static const char **parseProvCmds( const char *provCmds )
{
    RDKSSA_LOG_DEBUG( "parseProvCmds [%s]\n", provCmds?provCmds:"NULL" );
    // argument check
    if ( provCmds == NULL ) {
        RDKSSA_LOG_ERROR( "null argument\n" );
        return NULL;
    }
    char **newVector = calloc( (MAX_SUPPORTED_ATTRIBUTES+1), sizeof(char *) );
    if ( newVector == NULL ) {
        RDKSSA_LOG_ERROR( "vector allocation failure\n" );
        return NULL;
    }

    int strIx=0;
    const char *delim;
    const char *value;
    const char *str = provCmds;  /* I don't like to eat input args */
    do {
        delim = strchr( str, ATTRIB_DELIM ); /* is there a comma separator? */
        if ( delim == NULL ) {
            delim = strchr( str, COMMAND_TAIL );
            if ( delim == NULL ) {
                RDKSSA_LOG_ERROR( "missing terminator '}'\n" );
                goto theCleaners;
            }
        }
        value = strchr( str, VALUE_DELIM ); /* is there a equal sign? */
        if ( value != NULL ) {
            value++;
            // value can be < delim (value there) or value>delim (eq not in this attr)
            // but value != delim
            if ( value == delim ) {
                RDKSSA_LOG_ERROR( "missing value\n" );
                goto theCleaners;
            }
        }
        int attrlen = delim-str;
        newVector[strIx] = malloc( attrlen+1 );
        errno_t  rc = -1;

        if ( newVector[strIx] == NULL ) {
            RDKSSA_LOG_ERROR( "malloc failure\n" );
            goto theCleaners;
        }
        rc = strncpy_s( newVector[strIx], attrlen+1 , str, attrlen );
        ERR_CHK(rc);
        newVector[strIx][attrlen] = '\0';
        RDKSSA_LOG_INFO( "attrib = %s\n",newVector[strIx] );
        strIx++;
        str=delim+1;
    } while ( *delim != COMMAND_TAIL && strIx < MAX_SUPPORTED_ATTRIBUTES );
    if ( strIx >= MAX_SUPPORTED_ATTRIBUTES ) {
        RDKSSA_LOG_ERROR( "too many attribs in provCmds\n" );
        goto theCleaners;
    }

#ifdef RDKSSA_DEBUG_ENABLED
    int i;
    RDKSSA_LOG_DEBUG( "Here's what the parser brought home:\n");
    for(i=0; i<MAX_SUPPORTED_ATTRIBUTES; i++) {
        if ( newVector[i] != NULL ) { RDKSSA_LOG_DEBUG( "(%d) : %s\n", i, newVector[i] ); }
    }
#endif // RDKSSA_DEBUG_ENABLED  
    return (const char **)newVector;

theCleaners:
    rdkssaCleanupVector( &newVector );
    return NULL;
}

/**
 * Provider call table. Look up provider label and call the associated function.
 *
 * STOR
 * CA
 * IDENT
 * MOUNT
 */

typedef rdkssaStatus_t (*provWrapperFunc)( const char *provAPIname, const char *vector[] );
static  rdkssaStatus_t callStorProvider( const char *provAPIname, const char *vector[] );
static  rdkssaStatus_t callCAProvider( const char *provAPIname, const char *vector[] );
static  rdkssaStatus_t callIdentProvider( const char *provAPIname, const char *vector[] );
static  rdkssaStatus_t callMountProvider( const char *provAPIname, const char *vector[] );


static struct {
		const char *provname;
		const provWrapperFunc providerWrapper;
} providerWrapperTable[] = {
	{ "STOR", callStorProvider },
	{ "CA", callCAProvider },
	{ "IDENT", callIdentProvider },
	{ "MOUNT", callMountProvider },
	{ NULL, NULL }
};

/**
 * callProvider -	Called from main, iterating over argv, selecting the target provider
 *
 * theProv		=	The name string of a supported provder
 * provCmds		=	pointer either to the provider name if no attribute vector expected, or 
 *					pointer to first char of name=value,... sets to be parsed into the provider's vector.
 * returns		=	result of either a parse error, or provider's status
 */
static rdkssaStatus_t callProvider( const char *theProv, const char *provCmds )
{
	int i;
	rdkssaStatus_t retStatus;
	if ( provCmds == NULL ) {
		RDKSSA_LOG_ERROR( "null pointer error processing arguments\n");
		return rdkssaBadPointer;
	}

	/* theProv has already been length-checked */
	for(i=0;providerWrapperTable[i].providerWrapper != NULL;i++) {
		if ( strcmp( providerWrapperTable[i].provname, theProv ) == 0 ) {
			break;
		}
	}
	
	if ( providerWrapperTable[i].providerWrapper == NULL ) {
		return rdkssaProviderNotFound;
	}
	provWrapperFunc selectedProvider = providerWrapperTable[i].providerWrapper;
	
	RDKSSA_LOG_DEBUG( "callProvider [%s] with %s\n", theProv, provCmds?provCmds:"NULL" );

	const char **cmdVector = parseProvCmds( provCmds );
	if ( cmdVector == NULL ) {
		RDKSSA_LOG_ERROR( "syntax or other error processing provCmds: %s\n",provCmds);
		return rdkssaSyntaxError;
	}

	const char *cmd = cmdVector[0];
	if(cmd == NULL) {
		RDKSSA_LOG_ERROR( "NULL atribute, check input string header \n");
		cleanupVector( &cmdVector );
		return rdkssaBadPointer;
	}
	// check if cmd too long
	if ( strnlen( cmd, MAX_ATTRIBUTE_NAME_LENGTH+1 ) > MAX_ATTRIBUTE_NAME_LENGTH ) {
		RDKSSA_LOG_ERROR( "syntax or other error processing provCmds: %s\n",provCmds);
		cleanupVector( &cmdVector );
		return rdkssaSyntaxError;
	}
	RDKSSA_LOG_DEBUG( "cmd: %s\n", cmd );
	const char **provAttributex = cmdVector+1;
	retStatus=selectedProvider( cmd, provAttributex );
	cleanupVector( &cmdVector );
	return retStatus;
}	

/**
 * callCAProvider   -       handle "CA="
 *   CA=CREAT rdkssaCACreatePKCS12
 *   CA=CHECK rdkssaCACheckValidity
 *   CA=UPDATE rdkssaCAUpdatePKCS12

 */
static rdkssaStatus_t callCAProvider( const char *apiName, const char *apiVector[] )
{
	return rdkssaNYIError;
}

/**
 * callStorProvider -       handle "STOR="
 */
static rdkssaStatus_t callStorProvider( const char *apiName, const char *apiVector[] )
{
	return rdkssaNYIError;
}


/**
* callIdenProvider -       handle "IDENT="
*/
static rdkssaStatus_t callIdentProvider( const char *apiName, const char *apiVector[] )
{
	return rdkssaNYIError;
}

/**
 * callMountProvider - 		handle "MOUNT="
 *
 * The default OSS implementation of the Mount provider only supports
 * MOUNT API with attributes:
 *  MOUNTPOINT=<mountpoint>
 *  PATH=<path> attributes.
 *
 * UNMOUNT API, and KEY=, PARTITION= are not supported at this time.
 *
 * if they are supported in the future via the Cli, additional logic is needed here to handle 
 */
static rdkssaStatus_t callMountProvider( const char *apiName, const char *apiVector[] )
{
		RDKSSA_LOG_DEBUG( "Calling provider: %s\n", apiName );
		if ( strcmp( apiName, "MOUNT" ) == 0 ) {
			return rdkssaMount(NULL, apiVector);
		} 
		return rdkssaNYIError;
}



/**
 * processCmd       -       Given a string from the input, process one or more commands
 *
 * Syntax rules:
 * no leading or trailing spaces should be present, I don't feel like writing the trim stuff.
 * command string must be {enclosed in curly brackets}
 * the expected format is one of:
 * {providerid=attributestring,...}
 * providerid : "STOR" | "CA"  | "IDENT"    - (other provider labels to be added)
 * attributestring : attrib  |  name=value
 *
 * Calls helper functions to parse the command string 
 */
static rdkssaStatus_t processCmd( const char *cmdStr )
{
    RDKSSA_LOG_INFO( "processCmd [%s]\n", cmdStr?cmdStr:"NULL" );

    if ( cmdStr == NULL ) {
        RDKSSA_LOG_ERROR( "null pointer error processing cmd\n");
        return rdkssaBadPointer;
    }

    const char *charp=cmdStr;

    if(MAX_ATTRIBUTE_NAME_LENGTH < strnlen(cmdStr, MAX_ATTRIBUTE_NAME_LENGTH+1)){
        RDKSSA_LOG_ERROR( "Atribute Request is longer than expected %lu \n",(unsigned long)strnlen(cmdStr, MAX_ATTRIBUTE_NAME_LENGTH+1));
        return rdkssaBadLength;
    }

    if ( *charp++ != COMMAND_HEAD ) {
        return handleError( rdkssaSyntaxError, DONT_EXIT ); 
    }

    // call provider based on cmd, strip off cmd if value given
    rdkssaStatus_t rc = rdkssaSyntaxError; 
    RDKSSA_LOG_DEBUG("Parsing provider name from [%s]\n", charp);

	char provName[MAX_ATTRIBUTE_NAME_LENGTH];	// length check already done
	char *cp = provName;
	while( (*cp = *charp) != '\0' && *charp != '=' ) {	// copy up to = or eostring
		cp++;charp++;
	}
	*cp = 0;
	/* If there is no =xxxx, the provider name and command string are the same for the next call */ 
	if ( *charp == '=' ) {
		charp++;
	} else {
		charp = provName;
	}
	rc = callProvider( provName, charp );
	
    RDKSSA_LOG_DEBUG("processCmd Ret rc =[%d]\n", rc);
    return rc;
}

/**
 * handleError      -       Given an error code, print and optionally exit
 */
static rdkssaStatus_t handleError( rdkssaStatus_t err, int doExit )
{
    if ( err == rdkssaOK ) return rdkssaOK;
    char *msg="unknown";

    switch( err ) {
        case rdkssaGeneralFailure:
                msg = "general failure"; break;
        case rdkssaBadPointer:
                msg = "bad pointer"; break;
        case rdkssaAttributeNotFound:
                msg = "attribute not found"; break;
        case rdkssaSyntaxError:
                msg = "syntax error"; break;
        case rdkssaBadLength:
                msg = "bad length"; break;
        case rdkssaValidityError:
                msg = "expired"; break;
            /* more here */
        case rdkssaNYIError:
                msg = "NYI"; break;
        default:
                msg = "UNK"; break;
    }

    RDKSSA_LOG_ERROR( "%s - error\n", msg);
    fprintf(stderr, "%s - error \n", msg);
    if ( doExit == DO_EXIT ) {
        exit( err );
    }
    return err;
}

// main operational
int climain( int argc, char *argv[] )
{
    RDKSSA_LOG_DEBUG( "climain\n" );
    cliCheck( argc, argv );
    // for each argument, pass it to parseCmd
    int num;
    rdkssaStatus_t stat = rdkssaOK;
    for ( num=1; num<argc; num++ ) {
        stat = processCmd( argv[num] );
        if ( stat != rdkssaOK ) {
            return handleError( stat, DO_EXIT );
            // does not return
        }
    }
    return stat;
}


// Put this here to avoid using Unit Test Features in operational code
#if defined(UNIT_TESTS)
#include "unit_tests.h"
#endif

int utmain_cli( int argc, char *argv[] );

int main( int argc, char *argv[] )
{
#if defined(UNIT_TESTS)
    return utmain_cli( argc, argv );
#else
    return climain( argc, argv );
#endif
}


#if defined(UNIT_TESTS)
// unit test stubs
rdkssaStatus_t rdkssaStorageAccess ( rdkssa_blobptr_t apiBlobPtr, const char * const apiAttributes[]) {
    return rdkssaOK;
}
rdkssaStatus_t rdkssaMount ( rdkssa_blobptr_t apiBlobPtr, const char * const apiAttributes[]) {
    return rdkssaOK;
}
rdkssaStatus_t rdkssaCACreatePKCS12 ( rdkssa_blobptr_t apiBlobPtr, const char * const apiAttributes[]) {
    return rdkssaOK;
}
rdkssaStatus_t rdkssaCACheckValidity ( rdkssa_blobptr_t apiBlobPtr, const char * const apiAttributes[]) {
    return rdkssaOK;
}
rdkssaStatus_t rdkssaCAUpdatePKCS12 ( rdkssa_blobptr_t apiBlobPtr, const char * const apiAttributes[]) {
    return rdkssaOK;
}
rdkssaStatus_t rdkssaGetIdentityAttribute ( rdkssa_blobptr_t apiBlobPtr, const char * const apiAttributes[]) {
    apiBlobPtr = calloc( 1, 1 );
    return rdkssaOK;
}
// ut stub -- copy of real for memory cleanup
void rdkssaCleanupVector( char ***v ) {
    if ( *v == NULL ) return; // nothing to do
    char ***vctr = (char ***)v;
    int i;
    for( i=0; i<MAX_SUPPORTED_ATTRIBUTES; i++ ) {
        if ( (*vctr)[i] !=NULL ) { free( (*vctr)[i] ); (*vctr)[i] = NULL;}
    }
    free( *vctr );
    *vctr = NULL;
}


void rdkssa_memwipe( volatile void *mem, size_t sz ) { memset( (void *)mem, 0, sz ); }
void rdkssa_memfree(void **mem, size_t sz) { if(*mem) { free((void *)*mem); } }

// function unit tests
void ut_cliCheck( void );
void ut_parseProvCmdsCleanup( void );
void ut_callProvider( void );
void ut_processCmd( void );
void ut_handleError( void );
void ut_climain( void );

// main Unit Test
int utmain_cli( int argc, char *argv[] )
{
    RDKSSA_LOG_UT("=== Unit tests CLI begin ===\n");

    ut_cliCheck( );
    ut_parseProvCmdsCleanup( );
    ut_callProvider( );
    ut_processCmd( );
    ut_handleError( );

    RDKSSA_LOG_UT("=== Unit tests CLI SUCCESS ===\n");
    return UT_OK;
}

void ut_cliCheck( void ) {

    RDKSSA_LOG_UT("cliCheck (will exit if fails)\n");
    char *t1argv[]={"ssacli","{one}","{two}"};
    //cliCheck( 1, t1argv ); // uncomment to test exit case
    cliCheck( 2, t1argv );
    cliCheck( 3, t1argv );
    RDKSSA_LOG_UT("cliCheck SUCCESS\n");
} 

void ut_parseProvCmdsCleanup( void ) {
    RDKSSA_LOG_UT("parseProvCmds/cleanupVector\n");
    const char **cmdvctr1 = NULL;
    cmdvctr1 = parseProvCmds( "{TEST}" );
    UTST( cmdvctr1 );
    UTST0( strcmp( cmdvctr1[0], "{TEST" ) );
    cleanupVector( &cmdvctr1 ); // free memory
    UTST0( cmdvctr1 );
    cleanupVector( &cmdvctr1 ); // test null vector too
    UTST0( cmdvctr1 );
    cmdvctr1 = parseProvCmds( "{VAR1=VAL1,VAR2=VAL2,VAR3=VAL3}" );
    UTST( cmdvctr1 );
    UTST0( strcmp( cmdvctr1[0], "{VAR1=VAL1" ) );
    UTST0( strcmp( cmdvctr1[1], "VAR2=VAL2" ) );
    UTST0( strcmp( cmdvctr1[2], "VAR3=VAL3" ) );
    UTST0( cmdvctr1[3] );
    cleanupVector( &cmdvctr1 ); // free memory
    cmdvctr1 = parseProvCmds( "{WHITESPACE , MOREWHTESPACE= }" ); // unexpected but not an error
    UTST( cmdvctr1 );
    UTST0( strcmp( cmdvctr1[0], "{WHITESPACE " ) );
    UTST0( strcmp( cmdvctr1[1], " MOREWHTESPACE= " ) );
    UTST0( cmdvctr1[2] );
    cleanupVector( &cmdvctr1 ); // free memory
    // error cases
    RDKSSA_LOG_UT("    expect 5 error messages\n");

    UTST0( parseProvCmds( NULL ) );
    UTST0( parseProvCmds( "error" ) );
    UTST0( parseProvCmds( "{MISSINGEND" ) );
    UTST0( parseProvCmds( "{MISSINGEND1,MISSINGEND2" ) );
    UTST0( parseProvCmds( "{MISSINGVALUE=}" ) );
    RDKSSA_LOG_UT("parseProvCmds/cleanup SUCCESS\n");
}

void ut_callProvider( void ) {
    RDKSSA_LOG_UT("callStorProvider,callCAProvider,callIdenProvider\n");
    RDKSSA_LOG_UT("callStorProvider,callCAProvider,callIdenProvider SUCCESS\n");
}

void ut_processCmd( void ) {

    RDKSSA_LOG_UT("processCmd\n");
    RDKSSA_LOG_UT("    expect 2 error messages\n");
    UTST( processCmd( NULL ) == rdkssaBadPointer );
    UTST( processCmd( "error" ) == rdkssaSyntaxError );
    RDKSSA_LOG_UT("processCmd SUCCESS\n");

}

void ut_handleError( void ) {
    RDKSSA_LOG_UT("handleError\n");
    //UTST( handleError( rdkssaGeneralFailure, DO_EXIT ) != 0 ); // uncomment to test exit case
    UTST( handleError( rdkssaOK, DO_EXIT ) == rdkssaOK );
    RDKSSA_LOG_UT("    expect 2 error messages\n");
    UTST( handleError( rdkssaGeneralFailure, DONT_EXIT ) == rdkssaGeneralFailure );
    UTST( handleError( rdkssaNYIError, DONT_EXIT ) == rdkssaNYIError );
    RDKSSA_LOG_UT("handleError SUCCESS\n");

}

#endif // unit tests
