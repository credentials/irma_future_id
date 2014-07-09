/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 2000-2003
 *  David Corcoran <corcoran@linuxnet.com>
 * Copyright (C) 2002-2009
 *  Ludovic Rousseau <ludovic.rousseau@free.fr>
 *
 * $Id: hotplug.h 5434 2010-12-08 14:13:21Z rousseau $
 */

/**
 * @file
 * @brief This provides a search API for hot pluggble devices.
 */

#ifndef __hotplug_h__
#define __hotplug_h__

#ifndef PCSCLITE_HP_DROPDIR
#define PCSCLITE_HP_DROPDIR		"/usr/local/pcsc/drivers/"
#endif

#define PCSCLITE_HP_MANUKEY_NAME	"ifdVendorID"
#define PCSCLITE_HP_PRODKEY_NAME	"ifdProductID"
#define PCSCLITE_HP_NAMEKEY_NAME	"ifdFriendlyName"
#define PCSCLITE_HP_LIBRKEY_NAME	"CFBundleExecutable"
#define PCSCLITE_HP_CPCTKEY_NAME	"ifdCapabilities"
#define PCSCLITE_HP_CFBUNDLE_NAME	"CFBundleName"

#define PCSCLITE_HP_BASE_PORT		0x200000

	LONG HPSearchHotPluggables(void);
	ULONG HPRegisterForHotplugEvents(void);
	LONG HPStopHotPluggables(void);
	void HPReCheckSerialReaders(void);

#endif
