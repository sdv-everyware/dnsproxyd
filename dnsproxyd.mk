# dnsproxyd for an SDV Media product: inherit this file from the product makefile and
# import /product/etc/init/dnsproxyd.rc from the product's root init.

PRODUCT_PACKAGES += dnsproxyd
PRODUCT_PRIVATE_SEPOLICY_DIRS += vendor/sdv-everyware/dnsproxyd/sepolicy/private
