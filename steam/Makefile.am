libdir          = $(plugindir)
lib_LTLIBRARIES = steam.la

steam_la_CFLAGS = \
	$(BITLBEE_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(LIBGCRYPT_CFLAGS) \
	$(PROTOBUF_C_CFLAGS) \
	$(ZLIB_CFLAGS)

steam_la_LDFLAGS = \
	$(BITLBEE_LIBS) \
	$(GLIB_LIBS) \
	$(LIBGCRYPT_LIBS) \
	$(PROTOBUF_C_LIBS) \
	$(ZLIB_LIBS)

steam_la_SOURCES  = \
	steam.pb-c.c \
	steam.c \
	steam-crypt.c \
	steam-msg.c \
	steam-msgs.c \
	steam-net.c \
	steam-user.c \
	steam-util.c

# Build the library as a module
steam_la_LDFLAGS += -module -avoid-version

# Remove the generated protobuf sources
CLEANFILES = *.pb-c.*

%.pb-c.c %.pb-c.h: %.proto
	$(AM_V_GEN)$(PROTOC_C) -I$(dir $^) --c_out=$(dir $^) $^
