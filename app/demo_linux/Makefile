#===============================================================================
# export variable
#===============================================================================
ifeq ($(CFG_HI_EXPORT_FLAG),)
SAMPLE_DIR ?= $(shell cd $(CURDIR) && /bin/pwd)
endif
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#       variable
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
objects :=
iface = interface
app = sample_app
libsec = securec
objects += $(iface) $(libsec) $(app)
objects_clean:=$(addsuffix _clean,$(objects))
#===============================================================================
# rules
# #===============================================================================
.PHONY: all clean install uninstall
all: $(objects)

clean: $(objects_clean)

#==================================================================
#                          modules
#==================================================================
.PHONY: $(objects) $(objects_clean) $(libsec) $(iface) $(app)

$(libsec):
	$(AT)make -C $(libsec) all

$(iface):$(libsec)
	$(AT)make -C $(iface) all

$(app):$(libsec) $(iface)
	$(AT)make -C $(app) all

$(objects_clean):
	$(AT)make -C  $(SAMPLE_DIR)/$(patsubst %_clean,%,$@) clean

wifi: securec
sample_wifi: securec wifi
