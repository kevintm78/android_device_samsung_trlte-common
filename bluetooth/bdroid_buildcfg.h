/*
 * Copyright (C) 2012 The Android Open Source Project
 * Copyright (C) 2014 The CyanogenMod Project <http://www.cyanogenmod.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _BDROID_BUILDCFG_H
#define _BDROID_BUILDCFG_H

#pragma push_macro("PROPERTY_VALUE_MAX")

#include <cutils/properties.h>
#include <string.h>

static inline const char* BtmGetDefaultName()
{
    char product_device[PROPERTY_VALUE_MAX];
    property_get("ro.product.device", product_device, "");

    if (strstr(product_device, "trlte"))
        return "Samsung Galaxy Note 4";
    if (strstr(product_device, "tblte"))
        return "Samsung Galaxy Note Edge";

    // Fallback to ro.product.model
    return "";
}

#undef PROPERTY_VALUE_MAX

#define BTM_DEF_LOCAL_NAME BtmGetDefaultName()

#define BTA_DISABLE_DELAY 1000 /* in milliseconds */
#define BTE_BLE_STACK_CONF_FILE "/etc/bluetooth/bt_stack.conf"
#define BLE_VND_INCLUDED   TRUE     /* Enable WBS */
#define BTIF_HF_WBS_PREFERRED TRUE  /* Use WBS    */

#pragma pop_macro("PROPERTY_VALUE_MAX")

#endif
