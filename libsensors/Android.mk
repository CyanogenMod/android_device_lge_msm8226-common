ifneq ($(filter g2m w5 w55ds w7 jagnm jag3gds, $(TARGET_DEVICE)),)
include $(all-subdir-makefiles)
endif
