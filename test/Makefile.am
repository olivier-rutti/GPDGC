AM_LDFLAGS = -no-install
LDADD = ../src/libgpdgc.la

bin_PROGRAMS = gpdgc_instance_test generate_process_key

gpdgc_instance_test_SOURCES = src/main.c
gpdgc_instance_test_CFLAGS  = -W -Wall -ansi -pedantic -std=c99 $(GLIB_CFLAGS)\
							  -I../src
gpdgc_instance_test_LFLAGS  = $(GCRYPT_LIBS) $(GLIB_LIBS)
gpdgc_instance_test_LDFLAGS = -no-install

generate_process_key_SOURCES = src/keygen.c
generate_process_key_CFLAGS  = -W -Wall -ansi -pedantic -std=c99 $(GLIB_CFLAGS)
generate_process_key_LFLAGS  = $(GCRYPT_LIBS) $(GLIB_LIBS)
generate_process_key_LDFLAGS = -no-install

lib_LTLIBRARIES = libmalicious.la libfakedecider.la libcorrupted.la

libmalicious_la_SOURCES   = src/behaviors/malicious.c 
libmalicious_la_CFLAGS    =  -W -Wall -ansi -std=c99 $(GLIB_CFLAGS) \
							 -I../src -DG_LOG_DOMAIN=\"GPDGC\"
libmalicious_la_LFLAGS    = $(GLIB_LIBS) $(GCRYPT_LIBS) $(LD_LIBS)
libfakedecider_la_SOURCES = src/behaviors/fakedecider.c 
libfakedecider_la_CFLAGS  =  -W -Wall -ansi -std=c99 $(GLIB_CFLAGS) \
							 -I../src -DG_LOG_DOMAIN=\"GPDGC\"
libfakedecider_la_LFLAGS  = $(GLIB_LIBS) $(GCRYPT_LIBS) $(LD_LIBS)
libcorrupted_la_SOURCES   = src/behaviors/corrupted.c 
libcorrupted_la_CFLAGS    =  -W -Wall -ansi -std=c99 $(GLIB_CFLAGS) \
							 -I../src -DG_LOG_DOMAIN=\"GPDGC\"
libcorrupted_la_LFLAGS    = $(GLIB_LIBS) $(GCRYPT_LIBS) $(LD_LIBS)
