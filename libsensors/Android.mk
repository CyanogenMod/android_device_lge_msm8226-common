ifneq ($(filter g2m jag3ds jagnm w5 w7 , $(TARGET_DEVICE)),)
include $(all-subdir-makefiles)
endif
