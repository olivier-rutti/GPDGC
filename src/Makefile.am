lib_LTLIBRARIES = libgpdgc.la
libgpdgc_la_SOURCES = common.c common.h message.c message.h \
					  heardof.c heardof.h consensus.c consensus.h \
                      broadcast.c broadcast.h process.c process.h \
                      server.c server.h client.c gpdgc.h

libgpdgc_la_CFLAGS = -W -Wall -ansi -pedantic -std=c99 $(GLIB_CFLAGS) \
					 -DG_LOG_DOMAIN=\"GPDGC\"
libgpdgc_la_LFLAGS = $(PTHREAD_LIBS) $(GCRYPT_LIBS) $(GLIB_LIBS)
libgpdgc_la_LDFLAGS = -version-info \
	@LIBGPDGC_LT_MAJOR@:@LIBGPDGC_LT_MINOR@:@LIBGPDGC_LT_REVISION@
