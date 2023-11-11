/*
 *  Copyright (c) 2014, Oculus VR, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#define RAKNET_VERSION "4.081"
#define RAKNET_VERSION_NUMBER 5.00
#define RAKNET_VERSION_NUMBER_INT 500

#define RAKNET_DATE "11/11/2023"

// What compatible protocol version RakNet is using. When this value changes, it indicates this version of RakNet cannot connection to an older version.
// ID_INCOMPATIBLE_PROTOCOL_VERSION will be returned on connection attempt in this case
#define RAKNET_PROTOCOL_VERSION 6
