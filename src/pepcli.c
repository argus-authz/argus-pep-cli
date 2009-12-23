/*
 * Copyright (c) 2008-2009 Members of the EGEE Collaboration.
 * See http://www.eu-egee.org/partners for details on the copyright holders.
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
 * $Id: main.c 1299 2009-10-15 15:29:34Z vtschopp $
 */
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <stdarg.h>
#include <pwd.h>
#include <unistd.h>


#ifdef HAVE_CONFIG_H
#include "config.h"  /* PACKAGE_NAME and PACKAGE_VERSION const */
#else
#define PACKAGE_VERSION "0.0.0"
#endif

#include "pep/pep.h"
#include "pep/buffer.h"
#include "pep/linkedlist.h"

// logging prototypes: log.c
void show_info(const char * format, ...);
void show_error(const char * format, ...);
void show_warn(const char * format, ...);
void show_debug(const char * format, ...);
void log_handler_pep(int level, const char * format, va_list args);


// main return codes
#define E_OK        0 // OK
#define E_MEMORY    1 // memory allocation error
#define E_OPTION    2 // invalid option
#define E_CERTCHAIN 3 // certchain file or content error
#define E_XACMLREQ  4 // XACML request error
#define E_PEPC      5 // PEP client error
#define E_CAPATH	6 // CA path directory error
#define E_CERT		7 // client cert file error
#define E_KEY		8 // client key file error
#define E_CACERT	9 // server cert file error

// program options
static struct option long_options[] = {
   // PEPd endpoint URL(s)
   {"pepd", required_argument, 0, 'p'},
   {"certchain", required_argument, 0, 'c'},
   {"subjectid", required_argument, 0, 's'},
   {"fqan",  required_argument,  0, 'f'},
   {"resourceid", required_argument, 0, 'r'},
   {"actionid", required_argument, 0, 'a'},
   {"timeout", required_argument, 0, 't'},
   {"requestcontext",  no_argument,  0, 'x'},
   {"verbose", no_argument, 0, 'v'},
   {"quiet",  no_argument,  0, 'q'},
   {"debug",  no_argument,  0, 'd'},
   {"help",  no_argument,  0, 'h'},
   {"version",  no_argument,  0, 'V'},
   // TLS trust anchors and client authentication
   {"capath", required_argument, 0, '1'},
   {"cert", required_argument, 0, '2'},
   {"key", required_argument, 0, '3'},
   {"keypasswd", required_argument, 0, '4'},
   {"cacert", required_argument, 0, '5'},
   {0, 0, 0, 0}
};

// option flags (global, used by log.c)
int verbose= 0;
int debug= 0;
int quiet= 0;

// option intern
static int req_context= 0;
static long timeout= -1;
static char * certchain_filename= NULL;
static char * certchain= NULL;
static char * subjectid= NULL;
static char * resourceid= NULL;
static char * actionid= NULL;
static char * capath_directory= NULL;
static char * cacert_filename= NULL;
static char * cert_filename= NULL;
static char * key_filename= NULL;
static char * key_password= NULL;


// PEM cert delimiters for certchain
static const char CERT_BEGIN[]= "-----BEGIN CERTIFICATE-----";
static const char CERT_END[]= "-----END CERTIFICATE-----";

// PEM RSA private key delimiters
static const char KEY_RSA_BEGIN[]= "-----BEGIN RSA PRIVATE KEY-----";
static const char KEY_RSA_END[]= "-----END RSA PRIVATE KEY-----";
// PEM DSA private key delimiters
static const char KEY_DSA_BEGIN[]= "-----BEGIN DSA PRIVATE KEY-----";
static const char KEY_DSA_END[]= "-----END DSA PRIVATE KEY-----";
// PEM encrypted private key Proc-Type header
static const char KEY_PROCTYPE_ENCRYPTED[]= "Proc-Type: 4,ENCRYPTED";

// special ObligationId: x-posix-account-map
static const char X_POSIX_ACCOUNT_MAP[]= "x-posix-account-map";

/**
 * Checks if a file or directory exists and is readable.
 *
 * @param filename the name of the file or directory to check
 * @retun 1 (true) if exists and readable, 0 (false) otherwise
 */
static int file_is_readable(const char * filename) {
	int fexists= 0;
	FILE * file= fopen(filename,"r");
	if (file==NULL) {
		show_error("%s: %s", filename, strerror(errno));
		fexists= 0;
	}
	else
		fexists= 1;
	fclose(file);
	return fexists;
}

/**
 * Checks if the PEM encoded private key is encrypted.
 *
 * @param keyfile the file name of the PEM encoded private key
 * @retun 1 (true) if the private key is encrypted, 0 (false) otherwise
 */
static int key_is_encrypted(const char * keyfile) {
	int encrypted= 0;
	char line[1024];
	FILE * file= fopen(keyfile,"r");
	if (file==NULL) {
		show_error("%s: %s", keyfile, strerror(errno));
	}
	else {
		while(fgets(line,1024,file) != NULL) {
			if (strncmp(KEY_PROCTYPE_ENCRYPTED,line,strlen(KEY_PROCTYPE_ENCRYPTED)) == 0) {
				show_debug("key %s is encrypted", keyfile);
				encrypted= 1;
				break;
			}
		}
	}
	fclose(file);
	return encrypted;

}

/**
 * Reads the certificate file and returns the content as a buffer.
 * The returned buffer must be freed by the calling application.
 * Only the CERTIFICATE content will be included.
 *
 * @param filename The proxy or certificate file containing the cert chain
 */
static char * read_certchain(const char * filename) {
	char line[1024];
	FILE * file= fopen(filename,"r");
	if (file==NULL) {
		show_error("failed to open certchain file: %s: %s", filename, strerror(errno));
		return NULL;
	}
	BUFFER * cert_buffer= buffer_create(1024);
	if (cert_buffer==NULL) {
		show_error("can not create buffer");
		return NULL;
	}
	int cert_part= 0;
	while(fgets(line,1024,file) != NULL) {
		if (strncmp(CERT_BEGIN,line,strlen(CERT_BEGIN)) == 0) {
			cert_part= 1; // begin
			// show_debug("certificate begin");
		}
		if (cert_part) {
			buffer_write(line,sizeof(char),strlen(line),cert_buffer);
		}
		if (strncmp(CERT_END,line,strlen(CERT_END)) == 0) {
			cert_part= 0; // end
			// show_debug("certificate end");
		}
	}
	fclose(file);

	size_t size= buffer_length(cert_buffer);
	// show_debug("buffer length: %d",(int)size);
	char * certchain= calloc(size+1,sizeof(char));
	if (certchain==NULL) {
		show_error("can not allocate buffer %d bytes: %s",size,strerror(errno));
		buffer_delete(cert_buffer);
		return NULL;
	}
	// copy
	if (buffer_read(certchain,sizeof(char),size,cert_buffer)==BUFFER_ERROR) {
		show_error("failed to copy certificate content to buffer");
		buffer_delete(cert_buffer);
		free(certchain);
		return NULL;
	}

	buffer_delete(cert_buffer);
	// check empty certchain
	if (strlen(certchain)<=0) {
		show_warn("certchain file: %s does not contain certificate",certchain_filename);
		free(certchain);
		return NULL;
	}
	return certchain;
}

/**
 * Creates a XACML Subject subject-id.
 * @param x509dn The user DN (RFC2253 format)
 * @return pointer to the XACML Subject created or @c NULL on error.
 */
static xacml_subject_t * create_xacml_subject_id(const char * x500dn) {
	if (x500dn==NULL) return NULL;
	// Subject id
	xacml_subject_t * subject= xacml_subject_create();
	if (subject==NULL) {
		show_error("can not allocate XACML Subject");
		return NULL;
	}
	xacml_attribute_t * subject_attr_id= xacml_attribute_create(XACML_SUBJECT_ID);
	if (subject_attr_id==NULL) {
		show_error("can not allocate XACML Subject/Attribute: %s",XACML_SUBJECT_ID);
		xacml_subject_delete(subject);
		return NULL;
	}
	xacml_attribute_setdatatype(subject_attr_id,XACML_DATATYPE_X500NAME);
	xacml_attribute_addvalue(subject_attr_id,x500dn);
	xacml_subject_addattribute(subject,subject_attr_id);
	return subject;
}

/**
 * Creates a XACML Subject cert-chain
 * @param certchain the PEM blocks of the certificate chain
 * @return pointer to the XACML Subject created or @c NULL on error.
 */
static xacml_subject_t * create_xacml_subject_certchain(const char * certchain) {
	if (certchain==NULL) return NULL;
	// Subject cert-chain
	xacml_subject_t * subject= xacml_subject_create();
	if (subject==NULL) {
		show_error("can not allocate XACML Subject");
		return NULL;
	}
	xacml_attribute_t * subject_attr_id= xacml_attribute_create(XACML_AUTHZINTEROP_SUBJECT_CERTCHAIN);
	if (subject_attr_id==NULL) {
		show_error("can not allocate XACML Subject/Attribute: %s",XACML_AUTHZINTEROP_SUBJECT_CERTCHAIN);
		xacml_subject_delete(subject);
		return NULL;
	}
	xacml_attribute_setdatatype(subject_attr_id,XACML_DATATYPE_BASE64BINARY);
	xacml_attribute_addvalue(subject_attr_id,certchain);
	xacml_subject_addattribute(subject,subject_attr_id);
	return subject;
}

/**
 * Creates a XACML Subject with AuthZ Interop @b voms-primary-fqan and @b voms-fqan Attributes
 * @param fqans_list the list of FQANs, the first one in the list is the voms-primary-fqan.
 * @return pointer to the XACML Subject created or @c NULL on empty FQANs list or on error.
 */
static xacml_subject_t * create_xacml_subject_voms_fqans(linkedlist_t * fqans_list) {
	if (fqans_list==NULL) return NULL;
	// empty list
	size_t fqans_l= llist_length(fqans_list);
	if (fqans_l<1) return NULL;

	xacml_subject_t * subject= xacml_subject_create();
	if (subject==NULL) {
		show_error("can not allocate XACML Subject");
		return NULL;
	}
	int i= 0;
	// all FQANs are voms-fqan Attributes
	xacml_attribute_t * voms_fqan= xacml_attribute_create(XACML_AUTHZINTEROP_SUBJECT_VOMS_FQAN);
	if (voms_fqan==NULL) {
		show_error("can not allocate XACML Subject/Attribute: %s",XACML_AUTHZINTEROP_SUBJECT_VOMS_FQAN);
		xacml_subject_delete(subject);
		return NULL;
	}
	xacml_attribute_setdatatype(voms_fqan,XACML_DATATYPE_STRING);
	for (i= 0; i<fqans_l; i++) {
		char * fqan= (char *)llist_get(fqans_list,i);
		if (fqan==NULL) {
			show_error("NULL pointer in FQANs list at: %d",i);
			xacml_subject_delete(subject);
			return NULL;
		}
		xacml_attribute_addvalue(voms_fqan,fqan);
		if (i==0) {
			// fist FQAN is the voms-primary-fqan Attribute
			xacml_attribute_t * voms_primary_fqan= xacml_attribute_create(XACML_AUTHZINTEROP_SUBJECT_VOMS_PRIMARY_FQAN);
			if (voms_primary_fqan==NULL) {
				show_error("can not allocate XACML Subject/Attribute: %s",XACML_AUTHZINTEROP_SUBJECT_VOMS_PRIMARY_FQAN);
				xacml_subject_delete(subject);
				return NULL;
			}
			xacml_attribute_setdatatype(voms_primary_fqan,XACML_DATATYPE_STRING);
			xacml_attribute_addvalue(voms_primary_fqan,fqan);
			xacml_subject_addattribute(subject,voms_primary_fqan);
		}
	}
	xacml_subject_addattribute(subject,voms_fqan);
	return subject;
}

/**
 * Merges the attributes of the first XACML Subject into the second Subject.
 * WARNING: the attributes values are not copied, only the attributes pointers.
 *
 * @param from_subject The XACML Subject to copy from, can be NULL.
 * @param to_subject The XACML Subject to copy attributes into, can NOT be NULL.
 * @return 0 or a negative int on error.
 */
static int merge_xacml_subject_attrs_into(xacml_subject_t * from_subject, xacml_subject_t * to_subject) {
	if (to_subject==NULL) {
		show_error("destination XACML Subject is NULL");
		return -1;
	}
	if (from_subject==NULL) {
		return 0;
	}
	size_t l= xacml_subject_attributes_length(from_subject);
	int i= 0;
	for(i= 0; i<l; i++) {
		xacml_attribute_t * attr= xacml_subject_getattribute(from_subject,i);
		if (xacml_subject_addattribute(to_subject,attr)!=PEP_XACML_OK) {
			show_error("failed to merge attribute %d into Subject",i);
			return -2;
		}
	}
	return 0;
}

/**
 * Create a XACML Resource with an resource-id Attribute.
 * @param resourceid The Resource identifier
 * @return pointer to the XACML Resource created or @c NULL on error.
 */
static xacml_resource_t * create_xacml_resource_id(const char * resourceid) {
	if (resourceid==NULL) return NULL;
	xacml_resource_t * resource= xacml_resource_create();
	if (resource==NULL) {
		show_error("can not allocate XACML Resource");
		return NULL;
	}
	xacml_attribute_t * resource_attr_id= xacml_attribute_create(XACML_RESOURCE_ID);
	if (resource_attr_id==NULL) {
		show_error("can not allocate XAMCL Resource/Attribute: %s",XACML_RESOURCE_ID);
		xacml_resource_delete(resource);
		return NULL;
	}
	xacml_attribute_addvalue(resource_attr_id,resourceid);
	xacml_resource_addattribute(resource,resource_attr_id);
	return resource;
}

/**
 * Create a XACML Action with action-id Attribute.
 * @param actionid The Action identifier
 * @return pointer to the XACML Action created or @c NULL on error.
 */
static xacml_action_t * create_xacml_action_id(const char * actionid) {
	if (actionid==NULL) return NULL;
	xacml_action_t * action= xacml_action_create();
	if (action==NULL) {
		show_error("can not allocate XACML Action");
		return NULL;
	}
	xacml_attribute_t * action_attr_id= xacml_attribute_create(XACML_ACTION_ID);
	if (action_attr_id==NULL) {
		show_error("can not allocate XACML Action/Attribute: %s",XACML_ACTION_ID);
		xacml_action_delete(action);
		return NULL;
	}
	xacml_attribute_addvalue(action_attr_id,actionid);
	xacml_action_addattribute(action,action_attr_id);
	return action;
}

/**
 * Creates a XACML Request with a Subject, a Resource and a Action.
 */
static xacml_request_t * create_xacml_request(xacml_subject_t * subject, xacml_resource_t * resource, xacml_action_t * action) {
	// Request (Subject, Resource, Action)
	xacml_request_t * request= xacml_request_create();
	if (request==NULL) {
		show_error("can not allocate XACML Request");
		xacml_subject_delete(subject);
		xacml_resource_delete(resource);
		xacml_action_delete(action);
		return NULL;
	}
	if (subject!=NULL) {
		xacml_request_addsubject(request,subject);
	}
	if (resource!=NULL) {
		xacml_request_addresource(request,resource);
	}
	if (action!=NULL) {
		xacml_request_setaction(request,action);
	}
	return request;
}

/**
 * Returns the string representation of the decision.
 */
static const char * decision_str(int decision) {
    switch(decision) {
    case 0:
        return "Deny";
        break;
    case 1:
        return "Permit";
        break;
    case 2:
        return "Indeterminate";
        break;
    case 3:
        return "Not Applicable";
        break;
    default:
        return "Deny (Unknown!?!)";
        break;
    }
}

/**
 * Shows a XACML request. NULL values are not displayed.
 */
static int show_xacml_request(xacml_request_t * request) {
	if (request == NULL) {
		show_error("show_request: request is NULL");
		return 1;
	}
	size_t subjects_l= xacml_request_subjects_length(request);
	show_info("request: %d subjects", (int)subjects_l);
	int i= 0;
	for (i= 0; i<subjects_l; i++) {
		xacml_subject_t * subject= xacml_request_getsubject(request,i);
		const char * category= xacml_subject_getcategory(subject);
		if (category)
			show_info("request.subject[%d].category= %s", i, category);
		size_t attrs_l= xacml_subject_attributes_length(subject);
		show_info("request.subject[%d]: %d attributes", i, (int)attrs_l);
		int j= 0;
		for(j= 0; j<attrs_l; j++) {
			xacml_attribute_t * attr= xacml_subject_getattribute(subject,j);
			const char * attr_id= xacml_attribute_getid(attr);
			if (attr_id)
				show_info("request.subject[%d].attribute[%d].id= %s", i,j,attr_id);
			const char * attr_datatype= xacml_attribute_getdatatype(attr);
			if (attr_datatype)
				show_info("request.subject[%d].attribute[%d].datatype= %s", i,j,attr_datatype);
			const char * attr_issuer= xacml_attribute_getissuer(attr);
			if (attr_issuer)
				show_info("request.subject[%d].attribute[%d].issuer= %s", i,j,attr_issuer);
			size_t values_l= xacml_attribute_values_length(attr);
			//show_info("request.subject[%d].attribute[%d]: %d values", i,j,(int)values_l);
			int k= 0;
			for (k= 0; k<values_l; k++) {
				const char * attr_value= xacml_attribute_getvalue(attr,k);
				show_info("request.subject[%d].attribute[%d].value[%d]= %s", i,j,k,attr_value);
			}
		}
	}
	size_t resources_l= xacml_request_resources_length(request);
	show_info("request: %d resources", (int)resources_l);
	for (i= 0; i<resources_l; i++) {
		xacml_resource_t * resource= xacml_request_getresource(request,i);
		const char * res_content= xacml_resource_getcontent(resource);
		if (res_content)
			show_info("request.resource[%d].content= %s", i, res_content);
		size_t attrs_l= xacml_resource_attributes_length(resource);
		show_info("request.resource[%d]: %d attributes", i, (int)attrs_l);
		int j= 0;
		for(j= 0; j<attrs_l; j++) {
			xacml_attribute_t * attr= xacml_resource_getattribute(resource,j);
			const char * attr_id= xacml_attribute_getid(attr);
			if (attr_id)
				show_info("request.resource[%d].attribute[%d].id= %s", i,j,attr_id);
			const char * attr_datatype= xacml_attribute_getdatatype(attr);
			if (attr_datatype)
				show_info("request.resource[%d].attribute[%d].datatype= %s", i,j,attr_datatype);
			const char * attr_issuer= xacml_attribute_getissuer(attr);
			if (attr_issuer)
				show_info("request.resource[%d].attribute[%d].issuer= %s", i,j,attr_issuer);
			size_t values_l= xacml_attribute_values_length(attr);
			//show_info("request.resource[%d].attribute[%d]: %d values", i,j,(int)values_l);
			int k= 0;
			for (k= 0; k<values_l; k++) {
				const char * attr_value= xacml_attribute_getvalue(attr,k);
				if (attr_value)
					show_info("request.resource[%d].attribute[%d].value[%d]= %s", i,j,k,attr_value);
			}
		}
	}
	int j= 0;
	xacml_action_t * action= xacml_request_getaction(request);
	if (action) {
		size_t act_attrs_l= xacml_action_attributes_length(action);
		show_info("request.action: %d attributes",(int)act_attrs_l);
		for (j= 0; j<act_attrs_l; j++) {
			xacml_attribute_t * attr= xacml_action_getattribute(action,j);
			const char * attr_id= xacml_attribute_getid(attr);
			if (attr_id)
				show_info("request.action.attribute[%d].id= %s", j,attr_id);
			const char * attr_datatype= xacml_attribute_getdatatype(attr);
			if (attr_datatype)
				show_info("request.action.attribute[%d].datatype= %s", j,attr_datatype);
			const char * attr_issuer= xacml_attribute_getissuer(attr);
			if (attr_issuer)
				show_info("request.action.attribute[%d].issuer= %s", j,attr_issuer);
			size_t values_l= xacml_attribute_values_length(attr);
			//show_info("request.action.attribute[%d]: %d values", j,(int)values_l);
			int k= 0;
			for (k= 0; k<values_l; k++) {
				const char * attr_value= xacml_attribute_getvalue(attr,k);
				if (attr_value)
					show_info("request.action.attribute[%d].value[%d]= %s",j,k,attr_value);
			}
		}
	}
	xacml_environment_t * env= xacml_request_getenvironment(request);
	if (env) {
		size_t env_attrs_l= xacml_environment_attributes_length(env);
		show_info("request.environment: %d attributes",(int)env_attrs_l);
		for (j= 0; j<env_attrs_l; j++) {
			xacml_attribute_t * attr= xacml_environment_getattribute(env,j);
			const char * attr_id= xacml_attribute_getid(attr);
			if (attr_id)
				show_info("request.environment.attribute[%d].id= %s", j,attr_id);
			const char * attr_datatype= xacml_attribute_getdatatype(attr);
			if (attr_datatype)
				show_info("request.environment.attribute[%d].datatype= %s", j,attr_datatype);
			const char * attr_issuer= xacml_attribute_getissuer(attr);
			if (attr_issuer)
				show_info("request.environment.attribute[%d].issuer= %s", j,attr_issuer);
			size_t values_l= xacml_attribute_values_length(attr);
			//show_info("request.environment.attribute[%d]: %d values", j,(int)values_l);
			int k= 0;
			for (k= 0; k<values_l; k++) {
				const char * attr_value= xacml_attribute_getvalue(attr,k);
				if (attr_value)
					show_info("request.environment.attribute[%d].value[%d]= %s",j,k,attr_value);
			}
		}
	}
	return 0;
}

/**
 * Shows a XACML response.
 */
static int show_xacml_response(xacml_response_t * response) {
	if (response == NULL) {
		show_error("show_response: response is NULL");
		return 1;
	}
	size_t results_l= xacml_response_results_length(response);
	show_info("response: %d results", (int)results_l);
	int i= 0;
	for(i= 0; i<results_l; i++) {
		xacml_result_t * result= xacml_response_getresult(response,i);
		show_info("response.result[%d].decision= %s", i, decision_str(xacml_result_getdecision(result)));

		show_info("response.result[%d].resourceid= %s", i, xacml_result_getresourceid(result));
		xacml_status_t * status= xacml_result_getstatus(result);
		show_info("response.result[%d].status.message= %s", i, xacml_status_getmessage(status));
		xacml_statuscode_t * statuscode= xacml_status_getcode(status);
		show_info("response.result[%d].status.code.value= %s", i, xacml_statuscode_getvalue(statuscode));
		xacml_statuscode_t * subcode= xacml_statuscode_getsubcode(statuscode);
		if (subcode != NULL) {
			show_info("response.result[%d].status.code.subcode.value= %s", i, xacml_statuscode_getvalue(subcode));
		}
		size_t obligations_l= xacml_result_obligations_length(result);
		show_info("response.result[%d]: %d obligations", i, (int)obligations_l);
		int j=0;
		for(j= 0; j<obligations_l; j++) {
			xacml_obligation_t * obligation= xacml_result_getobligation(result,j);
			show_info("response.result[%d].obligation[%d].id= %s",i,j, xacml_obligation_getid(obligation));
			show_info("response.result[%d].obligation[%d].fulfillOn= %s",i,j, decision_str(xacml_obligation_getfulfillon(obligation)));
			size_t attrs_l= xacml_obligation_attributeassignments_length(obligation);
			show_info("response.result[%d].obligation[%d]: %d attribute assignments",i,j,(int)attrs_l);
			int k= 0;
			for (k= 0; k<attrs_l; k++) {
				xacml_attributeassignment_t * attr= xacml_obligation_getattributeassignment(obligation,k);
				show_info("response.result[%d].obligation[%d].attributeassignment[%d].id= %s",i,j,k,xacml_attributeassignment_getid(attr));
				size_t values_l= xacml_attributeassignment_values_length(attr);
				int l= 0;
				for (l= 0; l<values_l; l++) {
					show_info("response.result[%d].obligation[%d].attributeassignment[%d].value[%d]= %s",i,j,k,l,xacml_attributeassignment_getvalue(attr,l));
				}
			}
		}
	}
	return 0;
}

/**
 * Shows a human readable response.
 */
static int show_human_response(xacml_response_t * response) {
	if (response == NULL) {
		show_error("show_response: response is NULL");
		return 1;
	}
	size_t results_l= xacml_response_results_length(response);
	int i= 0;
	for (i= 0; i<results_l; i++) {
		xacml_result_t * result= xacml_response_getresult(response,i);
		const char * resource_id= xacml_result_getresourceid(result);
		if (resource_id!=NULL) {
			fprintf(stdout,"Resource: %s\n",resource_id);
		}
		xacml_decision_t decision= xacml_result_getdecision(result);
		fprintf(stdout,"Decision: %s\n", decision_str(decision));
		xacml_status_t * status= xacml_result_getstatus(result);
		xacml_statuscode_t * statuscode= xacml_status_getcode(status);
		const char * status_value= xacml_statuscode_getvalue(statuscode);
		// show status value and message only on not OK
		if (strcmp(XACML_STATUSCODE_OK,status_value)!=0) {
			fprintf(stdout,"Status: %s\n", status_value);
			const char * status_message= xacml_status_getmessage(status);
			if (status_message) {
				fprintf(stdout,"Status message: %s\n",status_message);
			}
		}
		size_t obligations_l= xacml_result_obligations_length(result);
		if (obligations_l==0i && decision==XACML_DECISION_PERMIT) {
			fprintf(stdout,"No Obligation received\n");
		}
		int j, k, l;
		for (j= 0; j<obligations_l; j++) {
			xacml_obligation_t * obligation= xacml_result_getobligation(result,j);
			xacml_fulfillon_t fulfillon= xacml_obligation_getfulfillon(obligation);
			if (fulfillon == decision) {
				const char * obligation_id= xacml_obligation_getid(obligation);
				size_t attrs_l= xacml_obligation_attributeassignments_length(obligation);
				if (strcmp(XACML_AUTHZINTEROP_OBLIGATION_SECONDARY_GIDS,obligation_id)==0 && attrs_l>0) {
					fprintf(stdout,"Secondary GIDs=");
				}
				else if (strcmp(X_POSIX_ACCOUNT_MAP,obligation_id)==0) {
					fprintf(stdout,"Obligation(%s): Application should do the POSIX account mapping\n",X_POSIX_ACCOUNT_MAP);
				}
				for (k= 0; k<attrs_l; k++) {
					xacml_attributeassignment_t * attr= xacml_obligation_getattributeassignment(obligation,k);
					const char * attr_id= xacml_attributeassignment_getid(attr);
					size_t values_l= xacml_attributeassignment_values_length(attr);
					for (l= 0; l<values_l; l++) {
						const char * value= xacml_attributeassignment_getvalue(attr,l);
						if (strcmp(XACML_AUTHZINTEROP_OBLIGATION_UIDGID,obligation_id)==0) {
							if (strcmp(XACML_AUTHZINTEROP_OBLIGATION_ATTR_POSIX_UID,attr_id)==0) {
								fprintf(stdout,"UID=%s\n",value);
							}
							else if (strcmp(XACML_AUTHZINTEROP_OBLIGATION_ATTR_POSIX_GID,attr_id)==0) {
								fprintf(stdout,"GID=%s\n",value);
							}
						}
						else if (strcmp(XACML_AUTHZINTEROP_OBLIGATION_SECONDARY_GIDS,obligation_id)==0) {
							if (strcmp(XACML_AUTHZINTEROP_OBLIGATION_ATTR_POSIX_GID,attr_id)==0) {
								fprintf(stdout,"%s ",value);
								if (k==(attrs_l - 1))
									fprintf(stdout,"\n");
							}
						}
						else if (strcmp(XACML_AUTHZINTEROP_OBLIGATION_USERNAME,obligation_id)==0) {
							if (strcmp(XACML_AUTHZINTEROP_OBLIGATION_ATTR_USERNAME,attr_id)==0) {
								fprintf(stdout,"Username=%s\n",value);
							}
						}
						else {
							fprintf(stdout,"Obligation(%s): %s=%s\n",obligation_id,attr_id,value);
						}
					}
				}
			}
		}


	}
	return 0;
}

static void show_version() {
	fprintf(stdout,"PEP-C CLI v." PACKAGE_VERSION ", PEP-C library v.%s\n",pep_version());
}

/**
 * Shows help
 */
static void show_help() {
    show_version();
	fprintf(stdout,"Usage:\n");
    fprintf(stdout,"    pepcli --pepd <URL> --certchain <FILE> [options...]\n");
	fprintf(stdout,"    pepcli --pepd <URL> --subjectid <DN> [options...]\n");
	fprintf(stdout,"\n");
	fprintf(stdout,"Submit a XACML Request to the PEPd and show the XACML Response.\n");
	fprintf(stdout,"\n");
	fprintf(stdout,"Options:\n");
	fprintf(stdout," -p|--pepd <URL>         PEPd endpoint URL. Add multiple --pepd options for failover.\n");
	fprintf(stdout," -c|--certchain <FILE>   XACML Subject cert-chain: proxy or X509 file.\n");
	fprintf(stdout," -s|--subjectid <DN>     XACML Subject identifier: user DN (format RFC2253).\n");
	fprintf(stdout," -f|--fqan <FQAN>        XACML Subject voms-primary-fqan and voms-fqan\n");
	fprintf(stdout,"                         Add multiple --fqan options for secondary FQANs.\n");
	fprintf(stdout," -r|--resourceid <URI>   XACML Resource identifier.\n");
	fprintf(stdout," -a|--actionid <URI>     XACML Action identifier.\n");
	fprintf(stdout," -t|--timeout <SEC>      Connection timeout in second (default 30s).\n");
	fprintf(stdout," -x|--requestcontext     Show effective XACML Request context.\n");
	fprintf(stdout," -v|--verbose            Verbose.\n");
	fprintf(stdout," -q|--quiet              Turn off output.\n");
	fprintf(stdout," -d|--debug              Show debug information.\n");
	fprintf(stdout," -h|--help               This help.\n");
	fprintf(stdout," -V|--version            Display version and exit.\n");
	fprintf(stdout,"TLS options:\n");
	fprintf(stdout," --capath <DIR>          Directory containing the server PEM encoded CA certificates.\n");
	fprintf(stdout," --cacert <FILE>         Server PEM encoded CA certificate filename.\n");
	fprintf(stdout," --cert <FILE>           Client PEM encoded certificate filename.\n");
	fprintf(stdout," --key <FILE>            Client PEM encoded private key filename.\n");
	fprintf(stdout," --keypasswd <PASSWD>    Password of the client private key\n");
	fprintf(stdout,"                         If the --keypasswd is omitted and the private key is encrypted,\n");
	fprintf(stdout,"                         then you will be prompted for the password.\n");

}

/**
 * Main: pepcli
 */
int main(int argc, char **argv) {
	linkedlist_t * pepds= llist_create();
	if (pepds==NULL) {
		show_error("Can not allocate PEPd url list.");
		exit(E_MEMORY);
	}
	linkedlist_t * fqans= llist_create();
	if (fqans==NULL) {
		show_error("Can not allocate FQAN list.");
		llist_delete(pepds);
		exit(E_MEMORY);
	}
	// parse arguments
	int c;
	while ((c= getopt_long(argc, argv, "dqvp:s:t:r:a:c:f:xhV1:2:3:4:5:", long_options, NULL)) != -1) {
		switch(c) {
		case 'd':
			debug= 1;
			show_debug("debug set.");
			break;
		case 'q':
			quiet= 1;
			show_debug("quiet set.");
			break;
		case 'v':
			show_debug("verbose set.");
			verbose= 1;
			break;
		case 'x':
			show_debug("show effective Request context.");
			req_context= 1;
			break;
		case 'p':
			show_debug("pepd: %s",optarg);
			// add url to list
			if (strlen(optarg) > 0) {
				llist_add(pepds,optarg);
			}
			break;
		case 'f':
			show_debug("fqan: %s",optarg);
			// add fqan to list
			if (strlen(optarg) > 0) {
				llist_add(fqans,optarg);
			}
			break;
		case 's':
			show_debug("subjectid: %s",optarg);
			if (strlen(optarg) > 0) {
				subjectid= optarg;
			}
			break;
		case 'c':
			show_debug("certchain: %s",optarg);
			if (strlen(optarg) > 0) {
				certchain_filename= optarg;
			}
			break;
		case 'r':
			show_debug("resourceid: %s",optarg);
			if (strlen(optarg) > 0) {
				resourceid= optarg;
			}
			break;
		case 'a':
			show_debug("actionid: %s",optarg);
			if (strlen(optarg) > 0) {
				actionid= optarg;
			}
			break;
		case 't':
			show_debug("timeout: %s",optarg);
			timeout= (int)strtol(optarg,NULL,10);
			if (errno == EINVAL || errno == ERANGE || timeout <= 0) {
				timeout= -1;
				show_warn("timeout %s can not be converted. Using default.",optarg);
			}
			break;
		case 'h':
			show_help();
			exit(E_OK);
			break;
		case 'V':
			show_version();
			exit(E_OK);
			break;
		case '1':
			show_debug("capath: %s",optarg);
			if (strlen(optarg) > 0) {
				capath_directory= optarg;
			}
			break;
		case '2':
			show_debug("cert: %s",optarg);
			if (strlen(optarg) > 0) {
				cert_filename= optarg;
			}
			break;
		case '3':
			show_debug("key: %s",optarg);
			if (strlen(optarg) > 0) {
				key_filename= optarg;
			}
			break;
		case '4':
			show_debug("keypasswd: %s",optarg);
			if (strlen(optarg) > 0) {
				key_password= optarg;
			}
			break;
		case '5':
			show_debug("cacert: %s",optarg);
			if (strlen(optarg) > 0) {
				cacert_filename= optarg;
			}
			break;
		case '?':
            // getopt_long already printed an error message.
			exit(E_OPTION);
			break;
		default:
			break;
		}
	}

	// check mandatory options: --pepd URL (--certchain FILE|--subjectid ID)
	size_t pepds_l= llist_length(pepds);
	if (pepds_l<1) {
		show_error("the mandatory option -p|--pepd <URL> is missing");
		//show_help();
		exit(E_OPTION);
	}
    if (certchain_filename==NULL && subjectid==NULL) {
		show_error("one of the mandatory option -c|--certchain <FILE> or -s|--subjectid <DN> is missing");
		//show_help();
		exit(E_OPTION);        
    }
    // mutually exclusive
    if (certchain_filename!=NULL && subjectid!=NULL) {
		show_error("the mandatory options -c|--certchain <FILE> or -s|--subjectid <DN> are mutually exclusive");
		//show_help();
		exit(E_OPTION);        
    }

    // TLS: check that --cert AND --key are both entered
    if (cert_filename!=NULL && key_filename==NULL) {
    	show_error("TLS option --cert <FILE> requires option --key <FILE>");
    	exit(E_OPTION);
    }
    if (key_filename!=NULL && cert_filename==NULL) {
    	show_error("TLS option --key <FILE> requires option --cert <FILE>");
    	exit(E_OPTION);
    }

    // check files options (exists and readable)
    if (certchain_filename!=NULL && !file_is_readable(certchain_filename)) {
		show_error("the -c|--certchain %s does not exist or is not readable",cert_filename);
		exit(E_CERTCHAIN);
    }
    if (cacert_filename!=NULL && !file_is_readable(cacert_filename)) {
		show_error("the --cacert %s does not exist or is not readable",cacert_filename);
		exit(E_CACERT);
    }
    if (capath_directory!=NULL && !file_is_readable(capath_directory)) {
		show_error("the --capath %s does not exist or is not readable",capath_directory);
		exit(E_CAPATH);
    }
    if (cert_filename!=NULL && !file_is_readable(cert_filename)) {
		show_error("the --cert %s does not exist or is not readable",cert_filename);
		exit(E_CERT);
    }
    if (key_filename!=NULL && !file_is_readable(key_filename)) {
		show_error("the --key %s does not exist or is not readable",key_filename);
		exit(E_KEY);
    }

    // check private key encryption password
    if (key_filename!=NULL && key_is_encrypted(key_filename)) {
    	// prompt for key passwd if not given as parameter
		if (key_password==NULL) {
			key_password= getpass("Key password: ");
			if (strlen(key_password)==0) {
				show_error("key is encrypted, empty password not valid");
				exit(E_KEY);
			}
		}
    }

	// show parameters
	int i= 0;
	for(i= 0; i<pepds_l; i++) {
		show_info("pepd: %s",(char *)llist_get(pepds,i));
	}
	if (subjectid!=NULL) {
		show_info("subjectid: %s", subjectid);
	}
	if (certchain_filename!=NULL) {
		show_info("certchain: %s", certchain_filename);
	}
	if (resourceid!=NULL) {
		show_info("resourceid: %s", resourceid);
	}
	if (actionid!=NULL) {
		show_info("actionid: %s",actionid);
	}
	size_t fqans_l= llist_length(fqans);
	for (i= 0; i<fqans_l; i++) {
		char * fqan= (char *)llist_get(fqans,i);
		if (i==0)
			show_info("fqan: %s (primary)",fqan);
		else
			show_info("fqan: %s",fqan);
	}
	// show TLS options
	if (cacert_filename!=NULL) {
		show_info("cacert: %s", cacert_filename);
	}
	if (capath_directory!=NULL) {
		show_info("capath: %s", capath_directory);
	}
	if (cert_filename!=NULL) {
		show_info("cert: %s", cert_filename);
	}
	if (key_filename!=NULL) {
		show_info("key: %s", key_filename);
		if (key_password!=NULL) {
			show_info("key passwd: %d chars",(int)strlen(key_password));
		}
	}

	// read certchain file
	if (certchain_filename!=NULL) {
		show_debug("read certchain from: %s",certchain_filename);
		certchain= read_certchain(certchain_filename);
		if (certchain==NULL) {
			show_error("certchain %s not found or doesn't contain certificate",certchain_filename);
			exit(E_CERTCHAIN);
		}
		show_debug("certchain:[\n%s]", certchain);
	}

	// PEP client
	show_debug("create PEP client...");
	pep_error_t pep_rc= pep_initialize();
	if (pep_rc!=PEP_OK) {
		show_error("failed to init PEP client: %s", pep_strerror(pep_rc));
	    pep_destroy();
		exit(E_PEPC);
	}
	//
	// PEP client options
	//
	// verbose and debug
	pep_setoption(PEP_OPTION_LOG_HANDLER,log_handler_pep);
	if (debug) {
		pep_setoption(PEP_OPTION_LOG_LEVEL,PEP_LOGLEVEL_DEBUG);
	}
	else if (verbose && !quiet) {
		pep_setoption(PEP_OPTION_LOG_LEVEL,PEP_LOGLEVEL_INFO);
	}
	// endpoint urls
	for(i=0; i<pepds_l; i++) {
		char * url= llist_get(pepds,i);
		show_debug("set PEPd url: %s",url);
		pep_rc= pep_setoption(PEP_OPTION_ENDPOINT_URL,url);
		if (pep_rc!=PEP_OK) {
			show_error("failed to set PEPd url: %s: %s",url,pep_strerror(pep_rc));
	        pep_destroy();
			exit(E_PEPC);
		}
	}
	// connection timeout
	if (timeout>0) {
		show_debug("set PEP-C client timeout: %d",timeout);
		pep_rc= pep_setoption(PEP_OPTION_ENDPOINT_TIMEOUT, timeout);
		if (pep_rc!=PEP_OK) {
			show_warn("failed to set PEP client timeout: %d: %s",timeout,pep_strerror(pep_rc));
		}
	}

	// TLS/SSL trust anchors and client authentication
	if (capath_directory==NULL && cacert_filename==NULL) {
		// no SSL validation
		show_debug("no CA cert or path: PEPd SSL validation disabled");
		pep_rc= pep_setoption(PEP_OPTION_ENDPOINT_SSL_VALIDATION, 0);
		if (pep_rc!=PEP_OK) {
			show_warn("failed to disable PEPd SSL validation: %s",pep_strerror(pep_rc));
		}
	}
	else {
		// enable SSL validation + CApath trust anchors
		show_debug("enabling PEPd SSL validation");
		pep_rc= pep_setoption(PEP_OPTION_ENDPOINT_SSL_VALIDATION, 1);
		if (pep_rc!=PEP_OK) {
			show_error("failed to enable PEPd SSL validation: %s",pep_strerror(pep_rc));
		}
	}

	if (capath_directory!=NULL) {
		show_debug("setting server trust anchors CA path: %s",capath_directory);
		pep_rc= pep_setoption(PEP_OPTION_ENDPOINT_SERVER_CAPATH,capath_directory);
		if (pep_rc!=PEP_OK) {
			show_error("failed to set server CA path: %s: %s",capath_directory,pep_strerror(pep_rc));
		}
	}
	if (cacert_filename!=NULL) {
		show_debug("setting server trust anchor certificate: %s",cacert_filename);
		pep_rc= pep_setoption(PEP_OPTION_ENDPOINT_SERVER_CERT,cacert_filename);
		if (pep_rc!=PEP_OK) {
			show_error("failed to set server cert: %s: %s",cacert_filename,pep_strerror(pep_rc));
		}
	}
	if (cert_filename!=NULL && key_filename!=NULL) {
		show_debug("enabling TLS client authN: %s, %s",cert_filename,key_filename);
		pep_rc= pep_setoption(PEP_OPTION_ENDPOINT_CLIENT_CERT,cert_filename);
		if (pep_rc!=PEP_OK) {
			show_error("failed to set client cert: %s: %s",cert_filename,pep_strerror(pep_rc));
		}
		pep_rc= pep_setoption(PEP_OPTION_ENDPOINT_CLIENT_KEY,key_filename);
		if (pep_rc!=PEP_OK) {
			show_error("failed to set client key: %s: %s",key_filename,pep_strerror(pep_rc));
		}
		if (key_password!=NULL) {
			pep_rc= pep_setoption(PEP_OPTION_ENDPOINT_CLIENT_KEYPASSWORD,key_password);
			if (pep_rc!=PEP_OK) {
				show_error("failed to set client key password: %s (%s): %s",key_password,key_filename,pep_strerror(pep_rc));
			}
		}
	}

	show_debug("create XACML subject");
	xacml_subject_t * subject= xacml_subject_create();
	// subject-id, cert-chain and VOMS FQANs are all one Subject!!!
	xacml_subject_t * subject_id= create_xacml_subject_id(subjectid);
	merge_xacml_subject_attrs_into(subject_id,subject);
	xacml_subject_t * subject_certchain= create_xacml_subject_certchain(certchain);
	merge_xacml_subject_attrs_into(subject_certchain,subject);
	xacml_subject_t * subject_voms_fqan= create_xacml_subject_voms_fqans(fqans);
	merge_xacml_subject_attrs_into(subject_voms_fqan,subject);
	// resource-id and action-id
	xacml_resource_t * resource= create_xacml_resource_id(resourceid);
	xacml_action_t * action= create_xacml_action_id(actionid);
	show_debug("create XACML request");
	xacml_request_t * request= create_xacml_request(subject,resource,action);
	if (request==NULL) {
		show_error("failed to create XACML request");
		exit(E_XACMLREQ);
	}

	// submit request
	show_info("authorize XACML request");
	xacml_response_t * response= NULL;
	pep_rc= pep_authorize(&request,&response);
	if (pep_rc!=PEP_OK) {
		show_error("failed to authorize XACML request: %s",pep_strerror(pep_rc));
	    pep_destroy();
		exit(E_PEPC);
	}
    if (!quiet) {
        if (req_context) {
            show_xacml_request(request);
        }
        show_xacml_response(response);
        show_human_response(response);
    }

	// clean up
	pep_destroy();
	xacml_request_delete(request);
	xacml_response_delete(response);
	llist_delete(pepds);
	llist_delete(fqans);
	if (certchain!=NULL) free(certchain);

	//show_info("done.");

	exit(E_OK);
}
