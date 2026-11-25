/*++
    OddlyDrv.c - OddlyProxifier WFP callout driver, ABI version 2.

    What it does
      * ALE_CONNECT_REDIRECT_V4/V6: outbound TCP connections selected by the
        policy are redirected to the engine's transparent listener. The
        original destination and the process id travel with the connection
        as a redirect context (ODDLY_REDIRECT_CTX); the engine reads it from
        the accepted socket with SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT.
      * ALE_AUTH_CONNECT_V4/V6: with ODDLY_FLAG_BLOCK_QUIC, UDP/443 of the
        same traffic is blocked so that browsers fall back to TCP.

    Safety
      * The policy belongs to the handle that set it. When that handle is
        closed - including when the engine crashes - the policy is dropped
        and the machine is back to normal.
      * Only SYSTEM and administrators can open the device.
      * Loopback, multicast and unspecified destinations, the engine itself
        and the system process are never touched.
      * All WFP objects live in a dynamic session: they disappear with the
        driver.

    Notes that cost a kernel dump each (kept from version 1)
      * FwpsAcquireClassifyHandle0 takes classifyFn's classifyContext.
      * classifyOut is set to PERMIT before FwpsApplyModifiedLayerData0.
      * A socket bound to a specific local address is redirected to that
        same address, not to loopback: a redirect across interfaces does not
        keep its redirect record.

    Build: driver\build.bat (WDK 10.0.26100, x64).
    License: MIT
--*/

#include <initguid.h>
#include <ntddk.h>
#include <wdmsec.h>
#define NDIS680
#include <ndis.h>
#include <fwpsk.h>
#include <fwpmk.h>

#include "oddly_ioctl.h"

C_ASSERT(sizeof(ODDLY_POLICY) == 160);
C_ASSERT(sizeof(ODDLY_NET) == 20);
C_ASSERT(sizeof(ODDLY_APP) == 132);
C_ASSERT(sizeof(ODDLY_STATS) == 40);
C_ASSERT(sizeof(ODDLY_REDIRECT_CTX) == 48);
C_ASSERT(FIELD_OFFSET(ODDLY_REDIRECT_CTX, ScopeId) == 44);
C_ASSERT(FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_ALE_APP_ID == 0 && FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_ALE_APP_ID == 0);
C_ASSERT(FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID == 0 && FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_APP_ID == 0);
C_ASSERT(IOCTL_ODDLY_GET_VERSION == CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_READ_DATA));
C_ASSERT(IOCTL_ODDLY_SET_POLICY == CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA));
C_ASSERT(IOCTL_ODDLY_GET_STATS == CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_READ_DATA));

/* ------------------------------------------------------------------ GUIDs */
DEFINE_GUID(ODDLY_PROVIDER_GUID,
    0xa7c3f100, 0x4e2d, 0x4b88, 0x9c, 0x51, 0x2d, 0x70, 0x81, 0x93, 0x04, 0x01);
DEFINE_GUID(ODDLY_SUBLAYER_GUID,
    0xa7c3f101, 0x6f1e, 0x4a44, 0xb2, 0x51, 0x38, 0x7d, 0x60, 0x11, 0x93, 0x05);
DEFINE_GUID(ODDLY_CALLOUT_V4_GUID,
    0xa7c3f102, 0x6f1e, 0x4a44, 0xb2, 0x51, 0x38, 0x7d, 0x60, 0x11, 0x93, 0x06);
DEFINE_GUID(ODDLY_CALLOUT_V6_GUID,
    0xa7c3f103, 0x6f1e, 0x4a44, 0xb2, 0x51, 0x38, 0x7d, 0x60, 0x11, 0x93, 0x07);
DEFINE_GUID(ODDLY_FILTER_V4_GUID,
    0xa7c3f104, 0x6f1e, 0x4a44, 0xb2, 0x51, 0x38, 0x7d, 0x60, 0x11, 0x93, 0x08);
DEFINE_GUID(ODDLY_FILTER_V6_GUID,
    0xa7c3f105, 0x6f1e, 0x4a44, 0xb2, 0x51, 0x38, 0x7d, 0x60, 0x11, 0x93, 0x09);
DEFINE_GUID(ODDLY_QUIC_CALLOUT_V4_GUID,
    0xa7c3f106, 0x6f1e, 0x4a44, 0xb2, 0x51, 0x38, 0x7d, 0x60, 0x11, 0x93, 0x0a);
DEFINE_GUID(ODDLY_QUIC_CALLOUT_V6_GUID,
    0xa7c3f107, 0x6f1e, 0x4a44, 0xb2, 0x51, 0x38, 0x7d, 0x60, 0x11, 0x93, 0x0b);
DEFINE_GUID(ODDLY_QUIC_FILTER_V4_GUID,
    0xa7c3f108, 0x6f1e, 0x4a44, 0xb2, 0x51, 0x38, 0x7d, 0x60, 0x11, 0x93, 0x0c);
DEFINE_GUID(ODDLY_QUIC_FILTER_V6_GUID,
    0xa7c3f109, 0x6f1e, 0x4a44, 0xb2, 0x51, 0x38, 0x7d, 0x60, 0x11, 0x93, 0x0d);
/* Device class for IoCreateDeviceSecure. */
DEFINE_GUID(ODDLY_DEVICE_CLASS_GUID,
    0xa7c3f10f, 0x6f1e, 0x4a44, 0xb2, 0x51, 0x38, 0x7d, 0x60, 0x11, 0x93, 0x0f);

#define ODDLY_TAG 'tOpO'

/* fwpmu.h is a user-mode header. */
#ifndef FWPM_SESSION_FLAG_DYNAMIC
#define FWPM_SESSION_FLAG_DYNAMIC 0x00000001
#endif

/* ---------------------------------------------------------------- globals */
static PDEVICE_OBJECT g_Device;
static BOOLEAN        g_SymLink;

/* g_Policy is NULL while nothing is to be redirected. Readers hold the lock
 * shared for the length of one decision; classify may run at DISPATCH_LEVEL. */
static EX_SPIN_LOCK   g_PolicyLock;
static ODDLY_POLICY  *g_Policy;
static PFILE_OBJECT   g_Owner;      /* handle that set the policy */

static volatile LONG64 g_Classified, g_Redirected, g_Bypassed, g_QuicBlocked, g_Errors;

static HANDLE g_Engine;
static HANDLE g_RedirectHandle;
static UINT32 g_CalloutIds[4];

/* --------------------------------------------------------------- matching */

/* Glob with * and ?. Both strings are NUL-terminated and lower-case. */
static BOOLEAN
OddlyGlob(_In_ const WCHAR *Pat, _In_ const WCHAR *Str)
{
    const WCHAR *star = NULL, *back = NULL;

    while (*Str) {
        if (*Pat == L'*') {
            star = Pat++;
            back = Str;
        } else if (*Pat == L'?' || *Pat == *Str) {
            Pat++;
            Str++;
        } else if (star) {
            Pat = star + 1;
            Str = ++back;
        } else {
            return FALSE;
        }
    }
    while (*Pat == L'*')
        Pat++;
    return *Pat == 0;
}

static BOOLEAN
OddlyPrefixMatch(_In_reads_bytes_(16) const UCHAR *Net, _In_reads_bytes_(16) const UCHAR *Addr, _In_ ULONG Bits)
{
    ULONG full = Bits / 8, rest = Bits % 8;

    if (full && !RtlEqualMemory(Net, Addr, full))
        return FALSE;
    if (rest) {
        UCHAR mask = (UCHAR)(0xFF << (8 - rest));
        if ((Net[full] & mask) != (Addr[full] & mask))
            return FALSE;
    }
    return TRUE;
}

/* Image name of the calling process: lower-case, without the directory. */
static VOID
OddlyImageName(
    _In_ const FWPS_INCOMING_VALUES0 *Fixed,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 *Meta,
    _Out_writes_(ODDLY_MAX_APP_CHARS) WCHAR *Name)
{
    const FWP_BYTE_BLOB *blob = NULL;
    const WCHAR *path, *base;
    ULONG chars, i, n = 0;

    Name[0] = 0;
    /* ALE_APP_ID is field 0 of all four layers this driver sits on. */
    if (Fixed->valueCount > 0 && Fixed->incomingValue[0].value.type == FWP_BYTE_BLOB_TYPE)
        blob = Fixed->incomingValue[0].value.byteBlob;
    if ((blob == NULL || blob->data == NULL || blob->size < sizeof(WCHAR)) &&
        (Meta->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_PATH))
        blob = Meta->processPath;
    if (blob == NULL || blob->data == NULL)
        return;
    path = (const WCHAR *)blob->data;
    chars = blob->size / sizeof(WCHAR);
    base = path;
    for (i = 0; i < chars && path[i]; i++) {
        if (path[i] == L'\\' || path[i] == L'/')
            base = path + i + 1;
    }
    for (; base < path + i && n < ODDLY_MAX_APP_CHARS - 1; base++) {
        WCHAR c = *base;
        if (c >= L'A' && c <= L'Z')
            c += L'a' - L'A';
        Name[n++] = c;
    }
    Name[n] = 0;
}

/* A destination that is never redirected, whatever the policy says. */
static BOOLEAN
OddlyLocalDestination(_In_ ULONG Family, _In_reads_bytes_(16) const UCHAR *a)
{
    static const UCHAR zero[16] = {0};

    if (Family == 4)
        return a[0] == 127 || a[0] == 0 || a[0] >= 224;   /* loopback, "this", multicast, broadcast */
    if (RtlEqualMemory(a, zero, 15))
        return a[15] <= 1;                                   /* :: and ::1 */
    if (a[0] == 0xFF)
        return TRUE;                                         /* multicast */
    if (RtlEqualMemory(a, zero, 10) && a[10] == 0xFF && a[11] == 0xFF)
        return a[12] == 127 || a[12] == 0 || a[12] >= 224;   /* IPv4-mapped */
    return FALSE;
}

typedef struct _ODDLY_VERDICT {
    BOOLEAN Redirect;
    BOOLEAN BlockQuic;
    ULONG   EnginePid;
    USHORT  Port;
} ODDLY_VERDICT;

/*
 * The one place that decides whether a connection belongs to the engine.
 * Port is in host order, Addr holds 4 or 16 bytes in network order.
 */
static VOID
OddlyDecide(
    _In_ const FWPS_INCOMING_VALUES0 *Fixed,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 *Meta,
    _In_ ULONG Family,
    _In_reads_bytes_(16) const UCHAR *Addr,
    _In_ USHORT Port,
    _Out_ ODDLY_VERDICT *V)
{
    const ODDLY_POLICY *p;
    const ODDLY_NET *nets;
    const ODDLY_APP *apps;
    WCHAR name[ODDLY_MAX_APP_CHARS];
    BOOLEAN haveName = FALSE, included = FALSE;
    ULONG pid, i;
    KIRQL irql;

    RtlZeroMemory(V, sizeof(*V));

    /* Without a process id the engine could not apply its rules. */
    if (!(Meta->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID))
        return;
    pid = (ULONG)Meta->processId;
    if (pid == 0 || pid == 4)
        return;
    if (OddlyLocalDestination(Family, Addr))
        return;

    irql = ExAcquireSpinLockShared(&g_PolicyLock);
    p = g_Policy;
    if (p == NULL)
        goto done;
    if (pid == p->EnginePid)
        goto done;
    if (Family == 6 && !(p->Flags & ODDLY_FLAG_IPV6))
        goto done;
    if (p->TargetPort != 0 && p->TargetPort != Port)
        goto done;
    for (i = 0; i < p->PidCount; i++) {
        if (p->ExcludePids[i] == pid)
            goto done;
    }

    V->EnginePid = p->EnginePid;
    V->Port = p->Port;
    V->BlockQuic = (p->Flags & ODDLY_FLAG_BLOCK_QUIC) != 0;

    nets = (const ODDLY_NET *)(p + 1);
    for (i = 0; i < p->NetCount; i++) {
        if (nets[i].Family == Family && OddlyPrefixMatch(nets[i].Addr, Addr, nets[i].Bits)) {
            V->Redirect = nets[i].Kind == ODDLY_NET_FORCE;
            goto done;
        }
    }

    apps = (const ODDLY_APP *)(nets + p->NetCount);
    for (i = 0; i < p->AppCount; i++) {
        if (!haveName) {
            OddlyImageName(Fixed, Meta, name);
            haveName = TRUE;
        }
        if (name[0] == 0 || !OddlyGlob(apps[i].Name, name))
            continue;
        if (apps[i].Kind == ODDLY_APP_EXCLUDE)
            goto done;
        included = TRUE;
    }
    V->Redirect = included || !(p->Flags & ODDLY_FLAG_APPS_ONLY);

done:
    ExReleaseSpinLockShared(&g_PolicyLock, irql);
}

/* Destination of the connection as WFP reports it for the layer. */
static VOID
OddlyFixedDestination(
    _In_ const FWPS_INCOMING_VALUES0 *Fixed,
    _In_ ULONG Family,
    _In_ ULONG AddrField,
    _In_ ULONG PortField,
    _Out_writes_bytes_(16) UCHAR *Addr,
    _Out_ USHORT *Port)
{
    RtlZeroMemory(Addr, 16);
    if (Family == 4) {
        UINT32 a = Fixed->incomingValue[AddrField].value.uint32;   /* host order */
        Addr[0] = (UCHAR)(a >> 24);
        Addr[1] = (UCHAR)(a >> 16);
        Addr[2] = (UCHAR)(a >> 8);
        Addr[3] = (UCHAR)a;
    } else {
        RtlCopyMemory(Addr, Fixed->incomingValue[AddrField].value.byteArray16->byteArray16, 16);
    }
    *Port = Fixed->incomingValue[PortField].value.uint16;
}

/* --------------------------------------------------------------- classify */

static VOID
OddlyRedirect(
    _In_ ULONG Family,
    _In_ const FWPS_INCOMING_VALUES0 *Fixed,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 *Meta,
    _Inout_opt_ VOID *LayerData,
    _In_opt_ const VOID *ClassifyContext,
    _In_ const FWPS_FILTER2 *Filter,
    _Inout_ FWPS_CLASSIFY_OUT0 *Out)
{
    NTSTATUS status;
    UINT64 classifyHandle = 0;
    FWPS_CONNECT_REQUEST0 *cr = NULL;
    ODDLY_REDIRECT_CTX *ctx;
    ODDLY_VERDICT v;
    UCHAR addr[16];
    USHORT port;

    if (!(Out->rights & FWPS_RIGHT_ACTION_WRITE))
        return;
    Out->actionType = FWP_ACTION_CONTINUE;
    if (LayerData == NULL || ClassifyContext == NULL || g_Policy == NULL)
        return;

    InterlockedIncrement64(&g_Classified);

    /* Our own redirect comes back here once more: leave it alone. */
    if (Meta->currentMetadataValues & FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE) {
        FWPS_CONNECTION_REDIRECT_STATE rs =
            FwpsQueryConnectionRedirectState0(Meta->redirectRecords, g_RedirectHandle, NULL);
        if (rs == FWPS_CONNECTION_REDIRECTED_BY_SELF ||
            rs == FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF) {
            InterlockedIncrement64(&g_Bypassed);
            return;
        }
    }

    if (Family == 4)
        OddlyFixedDestination(Fixed, 4, FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS,
                              FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT, addr, &port);
    else
        OddlyFixedDestination(Fixed, 6, FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_ADDRESS,
                              FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_PORT, addr, &port);

    OddlyDecide(Fixed, Meta, Family, addr, port, &v);
    if (!v.Redirect) {
        InterlockedIncrement64(&g_Bypassed);
        return;
    }

    status = FwpsAcquireClassifyHandle0((VOID *)ClassifyContext, 0, &classifyHandle);
    if (!NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_Errors);
        return;
    }
    status = FwpsAcquireWritableLayerDataPointer0(classifyHandle, Filter->filterId, 0, (PVOID *)&cr, Out);
    if (!NT_SUCCESS(status) || cr == NULL) {
        FwpsReleaseClassifyHandle0(classifyHandle);
        InterlockedIncrement64(&g_Errors);
        return;
    }

    /* Another redirector got here first and left its own context: the
     * connection is theirs. WFP frees the context; ours must come from the
     * non-paged pool. */
    ctx = NULL;
    if (cr->localRedirectContext == NULL)
        ctx = (ODDLY_REDIRECT_CTX *)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(*ctx), ODDLY_TAG);
    if (ctx == NULL) {
        FwpsApplyModifiedLayerData0(classifyHandle, cr, 0);   /* nothing was changed */
        FwpsReleaseClassifyHandle0(classifyHandle);
        InterlockedIncrement64(&g_Errors);
        return;
    }

    RtlZeroMemory(ctx, sizeof(*ctx));
    ctx->Magic = ODDLY_CTX_MAGIC;
    ctx->Pid = (ULONG)Meta->processId;
    ctx->Family = (USHORT)Family;

    if (Family == 4) {
        SOCKADDR_IN *remote = (SOCKADDR_IN *)&cr->remoteAddressAndPort;
        SOCKADDR_IN *local = (SOCKADDR_IN *)&cr->localAddressAndPort;
        ULONG target = local->sin_addr.s_addr ? local->sin_addr.s_addr : 0x0100007F; /* 127.0.0.1 */

        ctx->Port = remote->sin_port;
        RtlCopyMemory(ctx->Addr, &remote->sin_addr.s_addr, 4);

        RtlZeroMemory(&cr->remoteAddressAndPort, sizeof(cr->remoteAddressAndPort));
        remote->sin_family = AF_INET;
        remote->sin_port = RtlUshortByteSwap(v.Port);
        remote->sin_addr.s_addr = target;
    } else {
        static const UCHAR zero[16] = {0};
        SOCKADDR_IN6 *remote = (SOCKADDR_IN6 *)&cr->remoteAddressAndPort;
        SOCKADDR_IN6 *local = (SOCKADDR_IN6 *)&cr->localAddressAndPort;
        UCHAR target[16] = {0};
        ULONG scope = 0;

        ctx->Port = remote->sin6_port;
        ctx->ScopeId = remote->sin6_scope_id;
        RtlCopyMemory(ctx->Addr, remote->sin6_addr.s6_addr, 16);

        if (RtlEqualMemory(local->sin6_addr.s6_addr, zero, 16)) {
            target[15] = 1;                                  /* ::1 */
        } else {
            RtlCopyMemory(target, local->sin6_addr.s6_addr, 16);
            scope = local->sin6_scope_id;
        }
        RtlZeroMemory(&cr->remoteAddressAndPort, sizeof(cr->remoteAddressAndPort));
        remote->sin6_family = AF_INET6;
        remote->sin6_port = RtlUshortByteSwap(v.Port);
        remote->sin6_scope_id = scope;
        RtlCopyMemory(remote->sin6_addr.s6_addr, target, 16);
    }

    cr->localRedirectHandle = g_RedirectHandle;
    cr->localRedirectTargetPID = v.EnginePid;
    cr->localRedirectContext = ctx;
    cr->localRedirectContextSize = sizeof(*ctx);

    Out->actionType = FWP_ACTION_PERMIT;
    FwpsApplyModifiedLayerData0(classifyHandle, cr, FWPS_CLASSIFY_FLAG_REAUTHORIZE_IF_MODIFIED_BY_OTHERS);
    FwpsReleaseClassifyHandle0(classifyHandle);
    Out->rights &= ~FWPS_RIGHT_ACTION_WRITE;

    InterlockedIncrement64(&g_Redirected);
}

static VOID NTAPI
OddlyClassifyV4(
    _In_ const FWPS_INCOMING_VALUES0 *Fixed,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 *Meta,
    _Inout_opt_ VOID *LayerData,
    _In_opt_ const VOID *ClassifyContext,
    _In_ const FWPS_FILTER2 *Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0 *Out)
{
    UNREFERENCED_PARAMETER(FlowContext);
    OddlyRedirect(4, Fixed, Meta, LayerData, ClassifyContext, Filter, Out);
}

static VOID NTAPI
OddlyClassifyV6(
    _In_ const FWPS_INCOMING_VALUES0 *Fixed,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 *Meta,
    _Inout_opt_ VOID *LayerData,
    _In_opt_ const VOID *ClassifyContext,
    _In_ const FWPS_FILTER2 *Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0 *Out)
{
    UNREFERENCED_PARAMETER(FlowContext);
    OddlyRedirect(6, Fixed, Meta, LayerData, ClassifyContext, Filter, Out);
}

/* UDP/443 (the filter matches nothing else) of traffic that TCP would be
 * redirected for. */
static VOID
OddlyQuic(
    _In_ ULONG Family,
    _In_ const FWPS_INCOMING_VALUES0 *Fixed,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 *Meta,
    _Inout_ FWPS_CLASSIFY_OUT0 *Out)
{
    ODDLY_VERDICT v;
    UCHAR addr[16];
    USHORT port;

    if (!(Out->rights & FWPS_RIGHT_ACTION_WRITE))
        return;
    Out->actionType = FWP_ACTION_CONTINUE;
    if (g_Policy == NULL)
        return;

    if (Family == 4)
        OddlyFixedDestination(Fixed, 4, FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS,
                              FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT, addr, &port);
    else
        OddlyFixedDestination(Fixed, 6, FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS,
                              FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT, addr, &port);

    OddlyDecide(Fixed, Meta, Family, addr, port, &v);
    if (!v.Redirect || !v.BlockQuic)
        return;

    Out->actionType = FWP_ACTION_BLOCK;
    Out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    InterlockedIncrement64(&g_QuicBlocked);
}

static VOID NTAPI
OddlyQuicV4(
    _In_ const FWPS_INCOMING_VALUES0 *Fixed,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 *Meta,
    _Inout_opt_ VOID *LayerData,
    _In_opt_ const VOID *ClassifyContext,
    _In_ const FWPS_FILTER2 *Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0 *Out)
{
    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);
    OddlyQuic(4, Fixed, Meta, Out);
}

static VOID NTAPI
OddlyQuicV6(
    _In_ const FWPS_INCOMING_VALUES0 *Fixed,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 *Meta,
    _Inout_opt_ VOID *LayerData,
    _In_opt_ const VOID *ClassifyContext,
    _In_ const FWPS_FILTER2 *Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0 *Out)
{
    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);
    OddlyQuic(6, Fixed, Meta, Out);
}

static NTSTATUS NTAPI
OddlyNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    _In_ const GUID *FilterKey,
    _Inout_ FWPS_FILTER2 *Filter)
{
    UNREFERENCED_PARAMETER(NotifyType);
    UNREFERENCED_PARAMETER(FilterKey);
    UNREFERENCED_PARAMETER(Filter);
    return STATUS_SUCCESS;
}

/* -------------------------------------------------------------- WFP setup */

typedef struct _ODDLY_LAYER {
    const GUID *Callout;
    const GUID *Filter;
    const GUID *Layer;
    FWPS_CALLOUT_CLASSIFY_FN2 Classify;
    BOOLEAN Quic;
    wchar_t *Name;
} ODDLY_LAYER;

static const ODDLY_LAYER g_Layers[4] = {
    { &ODDLY_CALLOUT_V4_GUID, &ODDLY_FILTER_V4_GUID, &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
      OddlyClassifyV4, FALSE, L"OddlyProxifier TCP redirect (IPv4)" },
    { &ODDLY_CALLOUT_V6_GUID, &ODDLY_FILTER_V6_GUID, &FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
      OddlyClassifyV6, FALSE, L"OddlyProxifier TCP redirect (IPv6)" },
    { &ODDLY_QUIC_CALLOUT_V4_GUID, &ODDLY_QUIC_FILTER_V4_GUID, &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
      OddlyQuicV4, TRUE, L"OddlyProxifier QUIC block (IPv4)" },
    { &ODDLY_QUIC_CALLOUT_V6_GUID, &ODDLY_QUIC_FILTER_V6_GUID, &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
      OddlyQuicV6, TRUE, L"OddlyProxifier QUIC block (IPv6)" },
};

static NTSTATUS
OddlyAddLayer(_In_ ULONG Index)
{
    const ODDLY_LAYER *l = &g_Layers[Index];
    FWPS_CALLOUT2 sCallout = {0};
    FWPM_CALLOUT0 mCallout = {0};
    FWPM_FILTER0 filter = {0};
    FWPM_FILTER_CONDITION0 cond[2] = {0};
    NTSTATUS status;

    sCallout.calloutKey = *l->Callout;
    sCallout.classifyFn = l->Classify;
    sCallout.notifyFn = OddlyNotify;
    status = FwpsCalloutRegister2(g_Device, &sCallout, &g_CalloutIds[Index]);
    if (!NT_SUCCESS(status))
        return status;

    mCallout.calloutKey = *l->Callout;
    mCallout.displayData.name = l->Name;
    mCallout.providerKey = (GUID *)&ODDLY_PROVIDER_GUID;
    mCallout.applicableLayer = *l->Layer;
    status = FwpmCalloutAdd0(g_Engine, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status))
        return status;

    cond[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    cond[0].matchType = FWP_MATCH_EQUAL;
    cond[0].conditionValue.type = FWP_UINT8;
    cond[0].conditionValue.uint8 = l->Quic ? IPPROTO_UDP : IPPROTO_TCP;
    cond[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    cond[1].matchType = FWP_MATCH_EQUAL;
    cond[1].conditionValue.type = FWP_UINT16;
    cond[1].conditionValue.uint16 = 443;

    filter.filterKey = *l->Filter;
    filter.displayData.name = l->Name;
    filter.providerKey = (GUID *)&ODDLY_PROVIDER_GUID;
    filter.layerKey = *l->Layer;
    filter.subLayerKey = ODDLY_SUBLAYER_GUID;
    filter.weight.type = FWP_EMPTY;
    filter.numFilterConditions = l->Quic ? 2 : 1;
    filter.filterCondition = cond;
    filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
    filter.action.calloutKey = *l->Callout;
    return FwpmFilterAdd0(g_Engine, &filter, NULL, NULL);
}

static VOID
OddlyWfpCleanup(VOID)
{
    ULONG i;

    /* Closing the dynamic session removes filters, callouts, sublayer and
     * provider; only then can the callouts be unregistered. */
    if (g_Engine) {
        FwpmEngineClose0(g_Engine);
        g_Engine = NULL;
    }
    for (i = 0; i < RTL_NUMBER_OF(g_CalloutIds); i++) {
        if (g_CalloutIds[i] == 0)
            continue;
        while (FwpsCalloutUnregisterById0(g_CalloutIds[i]) == STATUS_DEVICE_BUSY) {
            LARGE_INTEGER wait;
            wait.QuadPart = -10 * 1000 * 10;   /* 10 ms: a classify is still running */
            KeDelayExecutionThread(KernelMode, FALSE, &wait);
        }
        g_CalloutIds[i] = 0;
    }
    if (g_RedirectHandle) {
        FwpsRedirectHandleDestroy0(g_RedirectHandle);
        g_RedirectHandle = NULL;
    }
}

static NTSTATUS
OddlyWfpInit(VOID)
{
    FWPM_SESSION0 session = {0};
    FWPM_PROVIDER0 provider = {0};
    FWPM_SUBLAYER0 sublayer = {0};
    BOOLEAN inTransaction = FALSE;
    NTSTATUS status;
    ULONG i;

    /* Created once: classify may run at DISPATCH_LEVEL, where this call is
     * not allowed. */
    status = FwpsRedirectHandleCreate0(&ODDLY_PROVIDER_GUID, 0, &g_RedirectHandle);
    if (!NT_SUCCESS(status))
        goto fail;

    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_Engine);
    if (!NT_SUCCESS(status))
        goto fail;

    status = FwpmTransactionBegin0(g_Engine, 0);
    if (!NT_SUCCESS(status))
        goto fail;
    inTransaction = TRUE;

    provider.providerKey = ODDLY_PROVIDER_GUID;
    provider.displayData.name = L"OddlyProxifier";
    status = FwpmProviderAdd0(g_Engine, &provider, NULL);
    if (!NT_SUCCESS(status))
        goto fail;

    sublayer.subLayerKey = ODDLY_SUBLAYER_GUID;
    sublayer.displayData.name = L"OddlyProxifier";
    sublayer.providerKey = (GUID *)&ODDLY_PROVIDER_GUID;
    sublayer.weight = 0x8000;
    status = FwpmSubLayerAdd0(g_Engine, &sublayer, NULL);
    if (!NT_SUCCESS(status))
        goto fail;

    for (i = 0; i < RTL_NUMBER_OF(g_Layers); i++) {
        status = OddlyAddLayer(i);
        if (!NT_SUCCESS(status))
            goto fail;
    }

    status = FwpmTransactionCommit0(g_Engine);
    inTransaction = FALSE;
    if (!NT_SUCCESS(status))
        goto fail;
    return STATUS_SUCCESS;

fail:
    if (inTransaction)
        FwpmTransactionAbort0(g_Engine);
    OddlyWfpCleanup();
    return status;
}

/* ----------------------------------------------------------------- policy */

static NTSTATUS
OddlyCheckPolicy(_In_reads_bytes_(Length) const ODDLY_POLICY *p, _In_ ULONG Length)
{
    const ODDLY_NET *nets;
    ULONG i;

    if (Length < sizeof(ODDLY_POLICY) || p->Size != Length)
        return STATUS_INVALID_PARAMETER;
    if (p->Version != ODDLY_ABI_VERSION)
        return STATUS_REVISION_MISMATCH;
    if (p->PidCount > ODDLY_MAX_PIDS || p->NetCount > ODDLY_MAX_NETS || p->AppCount > ODDLY_MAX_APPS)
        return STATUS_INVALID_PARAMETER;
    if (Length != sizeof(ODDLY_POLICY) + p->NetCount * sizeof(ODDLY_NET) + p->AppCount * sizeof(ODDLY_APP))
        return STATUS_INVALID_PARAMETER;
    if (p->Flags & ODDLY_FLAG_ENABLED) {
        if (p->EnginePid == 0 || p->Port == 0)
            return STATUS_INVALID_PARAMETER;
    }
    nets = (const ODDLY_NET *)(p + 1);
    for (i = 0; i < p->NetCount; i++) {
        if (nets[i].Family == 4 ? nets[i].Bits > 32 : nets[i].Family != 6 || nets[i].Bits > 128)
            return STATUS_INVALID_PARAMETER;
        if (nets[i].Kind > ODDLY_NET_FORCE)
            return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}

/* Replaces the active policy. New == NULL switches redirection off. */
static VOID
OddlySwapPolicy(_In_opt_ ODDLY_POLICY *New, _In_opt_ PFILE_OBJECT Owner)
{
    ODDLY_POLICY *old;
    KIRQL irql;

    irql = ExAcquireSpinLockExclusive(&g_PolicyLock);
    old = g_Policy;
    g_Policy = New;
    g_Owner = Owner;
    ExReleaseSpinLockExclusive(&g_PolicyLock, irql);
    if (old)
        ExFreePoolWithTag(old, ODDLY_TAG);
}

static NTSTATUS
OddlySetPolicy(_In_reads_bytes_(Length) const ODDLY_POLICY *In, _In_ ULONG Length, _In_ PFILE_OBJECT File)
{
    ODDLY_POLICY *copy;
    ODDLY_APP *apps;
    NTSTATUS status;
    ULONG i;

    status = OddlyCheckPolicy(In, Length);
    if (!NT_SUCCESS(status))
        return status;

    /* One engine at a time. */
    if (g_Owner != NULL && g_Owner != File)
        return STATUS_SHARING_VIOLATION;

    if (!(In->Flags & ODDLY_FLAG_ENABLED)) {
        OddlySwapPolicy(NULL, NULL);
        return STATUS_SUCCESS;
    }

    copy = (ODDLY_POLICY *)ExAllocatePoolWithTag(NonPagedPoolNx, Length, ODDLY_TAG);
    if (copy == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(copy, In, Length);
    apps = (ODDLY_APP *)((ODDLY_NET *)(copy + 1) + copy->NetCount);
    for (i = 0; i < copy->AppCount; i++)
        apps[i].Name[ODDLY_MAX_APP_CHARS - 1] = 0;
    OddlySwapPolicy(copy, File);
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------- dispatch */

static NTSTATUS
OddlyComplete(_Inout_ PIRP Irp, _In_ NTSTATUS Status, _In_ ULONG_PTR Info)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static NTSTATUS
OddlyDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID buf = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR info = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_ODDLY_GET_VERSION:
        if (buf == NULL || outLen < sizeof(ULONG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        *(ULONG *)buf = ODDLY_ABI_VERSION;
        info = sizeof(ULONG);
        break;

    case IOCTL_ODDLY_SET_POLICY:
        if (buf == NULL) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = OddlySetPolicy((const ODDLY_POLICY *)buf, inLen, stack->FileObject);
        break;

    case IOCTL_ODDLY_GET_STATS: {
        ODDLY_STATS *s = (ODDLY_STATS *)buf;
        if (buf == NULL || outLen < sizeof(ODDLY_STATS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        s->Classified = (ULONG64)g_Classified;
        s->Redirected = (ULONG64)g_Redirected;
        s->Bypassed = (ULONG64)g_Bypassed;
        s->QuicBlocked = (ULONG64)g_QuicBlocked;
        s->Errors = (ULONG64)g_Errors;
        info = sizeof(ODDLY_STATS);
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }
    return OddlyComplete(Irp, status, info);
}

static NTSTATUS
OddlyCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return OddlyComplete(Irp, STATUS_SUCCESS, 0);
}

/* The last handle of a file object is gone: the engine exited or crashed. */
static NTSTATUS
OddlyCleanup(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

    UNREFERENCED_PARAMETER(DeviceObject);
    if (g_Owner != NULL && stack->FileObject == g_Owner)
        OddlySwapPolicy(NULL, NULL);
    return OddlyComplete(Irp, STATUS_SUCCESS, 0);
}

/* ------------------------------------------------------------ load/unload */

static VOID
OddlyUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING dosName = RTL_CONSTANT_STRING(ODDLY_DEVICE_DOS);

    UNREFERENCED_PARAMETER(DriverObject);
    OddlySwapPolicy(NULL, NULL);
    OddlyWfpCleanup();
    if (g_SymLink) {
        IoDeleteSymbolicLink(&dosName);
        g_SymLink = FALSE;
    }
    if (g_Device) {
        IoDeleteDevice(g_Device);
        g_Device = NULL;
    }
}

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING devName = RTL_CONSTANT_STRING(ODDLY_DEVICE_NT);
    UNICODE_STRING dosName = RTL_CONSTANT_STRING(ODDLY_DEVICE_DOS);
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    /* SYSTEM and administrators only; FILE_DEVICE_SECURE_OPEN applies the
     * same check to every name below the device. */
    status = IoCreateDeviceSecure(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN,
                                  FILE_DEVICE_SECURE_OPEN, FALSE, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
                                  &ODDLY_DEVICE_CLASS_GUID, &g_Device);
    if (!NT_SUCCESS(status))
        return status;

    DriverObject->DriverUnload = OddlyUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = OddlyCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = OddlyCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = OddlyCleanup;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OddlyDeviceControl;

    status = IoCreateSymbolicLink(&dosName, &devName);
    if (NT_SUCCESS(status)) {
        g_SymLink = TRUE;
        status = OddlyWfpInit();
    }
    if (!NT_SUCCESS(status)) {
        OddlyUnload(DriverObject);
        return status;
    }
    return STATUS_SUCCESS;
}
