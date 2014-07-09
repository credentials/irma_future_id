// stdafx.h : Includedatei f�r Standardsystem-Includedateien
// oder h�ufig verwendete projektspezifische Includedateien,
// die nur in unregelm��igen Abst�nden ge�ndert werden.
//


#ifndef ECA_STDAFX_H
#define ECA_STDAFX_H



// --------------------------------------------------------------------------
// Platform: Windows
  
// �ndern Sie folgende Definitionen f�r Plattformen, die �lter als die unten angegebenen sind.
// In MSDN finden Sie die neuesten Informationen �ber die entsprechenden Werte f�r die unterschiedlichen Plattformen.
# ifndef WINVER				// Lassen Sie die Verwendung spezifischer Features von Windows XP oder sp�ter zu.
#  define WINVER 0x0501		// �ndern Sie dies in den geeigneten Wert f�r andere Versionen von Windows.
# endif

# ifndef _WIN32_WINNT		// Lassen Sie die Verwendung spezifischer Features von Windows XP oder sp�ter zu.                   
#  define _WIN32_WINNT 0x0501	// �ndern Sie dies in den geeigneten Wert f�r andere Versionen von Windows.
# endif						

# ifndef _WIN32_WINDOWS		// Lassen Sie die Verwendung spezifischer Features von Windows 98 oder sp�ter zu.
#  define _WIN32_WINDOWS 0x0410 // �ndern Sie dies in den geeigneten Wert f�r Windows Me oder h�her.
# endif

# ifndef _WIN32_IE			// Lassen Sie die Verwendung spezifischer Features von IE 6.0 oder sp�ter zu.
#  define _WIN32_IE 0x0600	// �ndern Sie dies in den geeigneten Wert f�r andere Versionen von IE.
# endif

# define WIN32_LEAN_AND_MEAN		// Selten verwendete Teile der Windows-Header nicht einbinden.

# define _CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES 1
# define _INSERT_KEY_EVENTS


#ifdef UNDER_CE
	#define STRSAFE_NO_DEPRECATE
	struct _CONTEXT;
	struct CONTEXT;
	typedef struct _CONTEXT *PCONTEXT;
	#pragma comment(lib, "Coredll.lib")
	#include "excpt.h"
	#define _EXP_CTAPI

#endif


// --------------------------------------------------------------------------
// common for all systems


#include <string.h>
#include "ntstatus.h"

#include "cjeca32.h"
#include "PCSC10.h"
#include "Debug.h"
#include "RSCTCriticalSection.h"
#include "BaseCommunication.h"
#ifdef _WINDOWS
	#ifdef UNDER_CE
		#include "USBCommunicationCe.h"
	#else
		#include "USBCommunication.h"
		#include "SerialCommunication.h"
	#endif
#endif

#include "BaseReader.h"
#include "CCIDReader.h"
#include "EC30Reader.h"
#include "ECAReader.h"
#include "SECReader.h"
#include "ECFReader.h"
#include "ECPReader.h"
#include "ECRReader.h"
#include "ECBReader.h"
#include "ECMReader.h"
#include "EFBReader.h"
#include "RFSReader.h"
#include "RFKReader.h"
#include "PPAReader.h"
#include "CPTReader.h"
#include "Reader.h"







#endif

