# openuf — OpenWrt SDK package Makefile
#
# Compilar con debug:
#   make package/openuf/compile DEBUG=1
include $(TOPDIR)/rules.mk

PKG_NAME    := openuf
PKG_VERSION := 0.4.0
PKG_RELEASE := 1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/openuf
  SECTION   := net
  CATEGORY  := Network
  TITLE     := openUF — UniFi bridge daemon for OpenWrt
  DEPENDS   := +libmbedtls +libuci +libjson-c +kmod-tun
  URL       := https://github.com/openuf/openuf
endef

define Package/openuf/description
  Emulates a UniFi U6 IW access point, allowing OpenWrt to be managed
  by a UniFi Network controller.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

TARGET_CFLAGS  += -I$(STAGING_DIR)/usr/include
TARGET_LDFLAGS += -lmbedtls -lmbedcrypto -luci -ljson-c

# Soporte DEBUG=1 desde la linea de comandos del SDK
ifeq ($(DEBUG),1)
  TARGET_CFLAGS += -DOPENUF_DEBUG -g -O0
endif

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_LDFLAGS) \
		-o $(PKG_BUILD_DIR)/openuf \
		$(PKG_BUILD_DIR)/main.c \
		$(PKG_BUILD_DIR)/config.c \
		$(PKG_BUILD_DIR)/state.c \
		$(PKG_BUILD_DIR)/crypto.c \
		$(PKG_BUILD_DIR)/http.c \
		$(PKG_BUILD_DIR)/announce.c \
		$(PKG_BUILD_DIR)/inform.c \
		$(PKG_BUILD_DIR)/wlan.c \
		$(PKG_BUILD_DIR)/sysinfo.c \
		$(PKG_BUILD_DIR)/clients.c \
		$(PKG_BUILD_DIR)/lldp.c \
		$(PKG_BUILD_DIR)/models.c
endef

define Package/openuf/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/openuf $(1)/usr/sbin/openuf
	$(INSTALL_DIR) $(1)/etc/openuf
	$(INSTALL_CONF) ./files/openuf.conf $(1)/etc/openuf/openuf.conf
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/openuf.init $(1)/etc/init.d/openuf
endef

$(eval $(call BuildPackage,openuf))
