/*
 * oddly_ioctl.h - interface between OddlyDrv.sys and its user-mode engine.
 *
 * ABI version 2. The Go engine keeps a copy of these numbers in
 * internal/intercept/intercept_windows.go; change both together and bump
 * ODDLY_ABI_VERSION when the layout changes.
 *
 * All integers are little-endian. Usable from kernel and user mode.
 */
#ifndef ODDLY_IOCTL_H
#define ODDLY_IOCTL_H

#define ODDLY_ABI_VERSION     2

#define ODDLY_DEVICE_NT       L"\\Device\\OddlyDrv"
#define ODDLY_DEVICE_DOS      L"\\DosDevices\\Global\\OddlyDrv"
#define ODDLY_DEVICE_WIN32    "\\\\.\\OddlyDrv"

/* CTL_CODE(FILE_DEVICE_UNKNOWN, fn, METHOD_BUFFERED, access) */
#define IOCTL_ODDLY_GET_VERSION  0x00226400u  /* fn 0x900, read        out: UINT32            */
#define IOCTL_ODDLY_SET_POLICY   0x0022E404u  /* fn 0x901, read|write  in:  ODDLY_POLICY blob */
#define IOCTL_ODDLY_GET_STATS    0x00226408u  /* fn 0x902, read        out: ODDLY_STATS       */

#define ODDLY_FLAG_ENABLED     0x1u   /* redirect at all                              */
#define ODDLY_FLAG_APPS_ONLY   0x2u   /* only applications on the include list        */
#define ODDLY_FLAG_IPV6        0x4u   /* redirect IPv6 connections too                */
#define ODDLY_FLAG_BLOCK_QUIC  0x8u   /* block UDP/443 of traffic that is redirected  */

#define ODDLY_MAX_PIDS       32
#define ODDLY_MAX_NETS       256
#define ODDLY_MAX_APPS       128
#define ODDLY_MAX_APP_CHARS  64

#define ODDLY_NET_BYPASS   0   /* never redirect this network                     */
#define ODDLY_NET_FORCE    1   /* always redirect it (fake-IP range); sent first  */
#define ODDLY_APP_INCLUDE  0
#define ODDLY_APP_EXCLUDE  1

#pragma pack(push, 1)

/* 160 bytes, followed by NetCount ODDLY_NET and AppCount ODDLY_APP entries. */
typedef struct _ODDLY_POLICY {
    unsigned int   Size;            /* of the whole blob                             */
    unsigned int   Version;         /* ODDLY_ABI_VERSION                             */
    unsigned int   Flags;
    unsigned int   EnginePid;       /* never redirected; owner of redirected sockets */
    unsigned short Port;            /* engine's transparent listener, host order     */
    unsigned short TargetPort;      /* 0 = all, else only this destination port      */
    unsigned int   PidCount;
    unsigned int   NetCount;
    unsigned int   AppCount;
    unsigned int   ExcludePids[ODDLY_MAX_PIDS];
} ODDLY_POLICY;

/* 20 bytes. The first matching entry decides. */
typedef struct _ODDLY_NET {
    unsigned char Family;           /* 4 or 6                       */
    unsigned char Bits;             /* prefix length                */
    unsigned char Kind;             /* ODDLY_NET_*                  */
    unsigned char Pad;
    unsigned char Addr[16];         /* IPv4 uses the first 4 bytes  */
} ODDLY_NET;

/* 132 bytes. */
typedef struct _ODDLY_APP {
    unsigned char  Kind;            /* ODDLY_APP_*                                        */
    unsigned char  Pad[3];
    unsigned short Name[ODDLY_MAX_APP_CHARS]; /* lower-case image name glob (* ?), NUL-terminated */
} ODDLY_APP;

/* 40 bytes. */
typedef struct _ODDLY_STATS {
    unsigned __int64 Classified;
    unsigned __int64 Redirected;
    unsigned __int64 Bypassed;
    unsigned __int64 QuicBlocked;
    unsigned __int64 Errors;
} ODDLY_STATS;

/*
 * 48 bytes, attached to every redirected connection. The engine reads it
 * from the accepted socket with SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT.
 */
#define ODDLY_CTX_MAGIC 0x3243444Fu /* "ODC2" */
typedef struct _ODDLY_REDIRECT_CTX {
    unsigned int   Magic;
    unsigned int   Pid;             /* process that opened the connection   */
    unsigned short Family;          /* 4 or 6                               */
    unsigned short Port;            /* original destination, network order  */
    unsigned char  Addr[16];        /* original destination                 */
    unsigned char  Reserved[16];
    unsigned int   ScopeId;         /* IPv6 scope of the destination        */
} ODDLY_REDIRECT_CTX;

#pragma pack(pop)

#endif
