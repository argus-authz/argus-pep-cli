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
 * $Id: log.c 1299 2009-10-15 15:29:34Z vtschopp $
 */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

extern int debug;
extern int verbose;
extern int quiet;

/*
 * local logging handler
 */
static void _vfprintf(FILE * fd, const char * level, const char * format, va_list args) {
	int BUFFER_SIZE= 1024;
	char BUFFER[BUFFER_SIZE];
	memset(BUFFER,0,BUFFER_SIZE);
	size_t size= BUFFER_SIZE;
	strncat(BUFFER,level,size);
	size= size - strlen(BUFFER);
	strncat(BUFFER,": ",size);
	size= size - strlen(BUFFER);
	strncat(BUFFER,format,size);
	size= size - strlen(BUFFER);
	strncat(BUFFER,"\n",size);
	vfprintf(fd,BUFFER,args);
}

/*
 * Logs an INFO message on stdout
 */
void show_info(const char * format, ...) {
	if (verbose && !quiet) {
		va_list args;
		va_start(args,format);
		_vfprintf(stdout,"pepcli",format,args);
		va_end(args);
	}
}

/*
 * Logs an ERROR message on stderr
 */
void show_error(const char * format, ...) {
	va_list args;
	va_start(args,format);
	_vfprintf(stderr,"pepcli:ERROR",format,args);
	va_end(args);
}

/*
 * Logs a WARN message on stderr
 */
void show_warn(const char * format, ...) {
	va_list args;
	va_start(args,format);
	_vfprintf(stderr,"pepcli:WARN",format,args);
	va_end(args);
}

/*
 * Logs an DEBUG message on stdout
 */
void show_debug(const char * format, ...) {
	if (debug) {
		va_list args;
		va_start(args,format);
		_vfprintf(stdout,"pepcli:DEBUG",format,args);
		va_end(args);
	}
}

/*
 * PEP-C library logging callback function
 */
void log_handler_pep(int level, const char * format, va_list args) {
	if (verbose || debug) {
		switch (level) {
		case 0:
			fprintf(stderr,"libpep-c:ERROR: ");
			vfprintf(stderr,format,args);
			fprintf(stderr,"\n");
			break;
		case 1:
			fprintf(stderr,"libpep-c:WARN: ");
			vfprintf(stderr,format,args);
			fprintf(stderr,"\n");
			break;
		case 2:
			fprintf(stderr,"libpep-c: ");
			vfprintf(stderr,format,args);
			fprintf(stderr,"\n");
			break;
		default:
			// all other message are debug!?!
			if (debug) {
				fprintf(stderr,"libpep-c:DEBUG: ");
				vfprintf(stderr,format,args);
				fprintf(stderr,"\n");
			}
			break;
		}
	}
}
